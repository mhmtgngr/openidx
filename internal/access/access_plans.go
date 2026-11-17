package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/accessdecision"
	"github.com/openidx/openidx/internal/accessplan"
)

// Access plans: "open application X to group Y". The rules (internal/accessplan)
// lay the plan out; an operator proposes it, an administrator approves it, and
// only then is the group assigned. After the grant the platform checks, with the
// same decision engine the proxy uses, what a member of the group can now do,
// and says so in plain words. An undo removes exactly the assignment the plan
// made.

const (
	proposalAccessOpen = "access_open"
	// accessPlanLife is how long a plan waits for a decision.
	accessPlanLife = 24 * time.Hour
)

type planResource struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type planGroup struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Members int    `json:"members"`
}

// planCheck is what a member of the group can do with the resource.
type planCheck struct {
	// Checked is false when the group has nobody to check with.
	Checked bool   `json:"checked"`
	Allowed bool   `json:"allowed"`
	Why     string `json:"why,omitempty"`
}

// accessPlanView is a plan as the console lists it.
type accessPlanView struct {
	ID        string          `json:"id,omitempty"`
	Status    string          `json:"status"` // pending | applied | rejected | expired | superseded | undone, or the rules' ready/noop/blocked for one never stored
	Resource  planResource    `json:"resource"`
	Group     planGroup       `json:"group"`
	Plan      accessplan.Plan `json:"plan"`
	Now       *planCheck      `json:"now,omitempty"`
	Outcome   json.RawMessage `json:"outcome,omitempty"`
	CreatedAt *time.Time      `json:"created_at,omitempty"`
	ExpiresAt *time.Time      `json:"expires_at,omitempty"`
}

var errAmbiguous = errors.New("the name matches more than one")

// planFacts gathers what the rules need about a resource and a group, each
// given by id or by name.
func (s *Service) planFacts(ctx context.Context, orgID, resource, group string) (accessplan.Facts, error) {
	var f accessplan.Facts
	var rid, gid *string
	if _, err := uuid.Parse(resource); err == nil {
		rid = &resource
	}
	if _, err := uuid.Parse(group); err == nil {
		gid = &group
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id::text, name, kind, enabled FROM applications
		 WHERE org_id = $1 AND (($2::text IS NOT NULL AND id::text = $2) OR ($2::text IS NULL AND LOWER(name) = LOWER($3)))
		 LIMIT 2`, orgID, rid, resource)
	if err != nil {
		return f, err
	}
	n := 0
	for rows.Next() {
		n++
		if err := rows.Scan(&f.ResourceID, &f.ResourceName, &f.ResourceKind, &f.ResourceEnabled); err != nil {
			rows.Close()
			return f, err
		}
	}
	rows.Close()
	if n > 1 {
		return f, errAmbiguous
	}
	f.ResourceFound = n == 1

	grows, err := s.db.Pool.Query(ctx, `
		SELECT id::text, name FROM groups
		 WHERE org_id = $1 AND (($2::text IS NOT NULL AND id::text = $2) OR ($2::text IS NULL AND LOWER(name) = LOWER($3)))
		 LIMIT 2`, orgID, gid, group)
	if err != nil {
		return f, err
	}
	n = 0
	for grows.Next() {
		n++
		if err := grows.Scan(&f.GroupID, &f.GroupName); err != nil {
			grows.Close()
			return f, err
		}
	}
	grows.Close()
	if n > 1 {
		return f, errAmbiguous
	}
	f.GroupFound = n == 1

	if err := s.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE org_id = $1 AND enabled`, orgID).Scan(&f.OrgUsers); err != nil {
		return f, err
	}
	if f.GroupFound {
		if err := s.db.Pool.QueryRow(ctx, `
			SELECT count(*) FROM group_memberships gm JOIN users u ON u.id = gm.user_id
			 WHERE gm.group_id = $1::uuid AND u.org_id = $2 AND u.enabled`, f.GroupID, orgID).Scan(&f.GroupMembers); err != nil {
			return f, err
		}
	}
	if f.GroupFound && f.ResourceFound {
		if err := s.db.Pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM group_application_assignments
			                WHERE group_id = $1::uuid AND application_id = $2::uuid AND org_id = $3)`,
			f.GroupID, f.ResourceID, orgID).Scan(&f.AlreadyGranted); err != nil {
			return f, err
		}
	}
	return f, nil
}

// planHash binds a plan to the facts it was drawn from.
func planHash(f accessplan.Facts) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%t|%t", f.ResourceID, f.GroupID, f.ResourceKind, f.ResourceEnabled, f.AlreadyGranted)))
	return hex.EncodeToString(sum[:])
}

// memberCheck asks the decision engine what one member of the group can do
// with the resource: the answer the proxy would give them.
func (s *Service) memberCheck(ctx context.Context, orgID string, f accessplan.Facts) *planCheck {
	if !f.GroupFound || !f.ResourceFound || f.GroupMembers == 0 {
		return &planCheck{}
	}
	var userID string
	if err := s.db.Pool.QueryRow(ctx, `
		SELECT gm.user_id::text FROM group_memberships gm JOIN users u ON u.id = gm.user_id
		 WHERE gm.group_id = $1::uuid AND u.org_id = $2 AND u.enabled ORDER BY gm.user_id LIMIT 1`,
		f.GroupID, orgID).Scan(&userID); err != nil {
		return &planCheck{}
	}
	roles, _ := s.userRoleNames(ctx, userID, orgID)
	d, err := accessdecision.Evaluate(ctx, s.db, s.config != nil && s.config.AccessAssignmentEnforce,
		accessdecision.Subject{UserID: userID, OrgID: orgID, Roles: roles}, f.ResourceID)
	if err != nil {
		return &planCheck{}
	}
	return &planCheck{Checked: true, Allowed: !d.WouldDeny, Why: accessdecision.Explain(d)}
}

func viewOf(f accessplan.Facts, p accessplan.Plan) accessPlanView {
	return accessPlanView{
		Status:   string(p.Status),
		Resource: planResource{ID: f.ResourceID, Name: f.ResourceName, Kind: f.ResourceKind},
		Group:    planGroup{ID: f.GroupID, Name: f.GroupName, Members: f.GroupMembers},
		Plan:     p,
	}
}

// handleCreateAccessPlan is POST /access/plans (operator): lay out a plan to
// open a resource to a group. Nothing changes. A plan that is ready is stored
// for an administrator to decide; one that is not needed or cannot be done is
// returned and not stored.
func (s *Service) handleCreateAccessPlan(c *gin.Context) {
	var body struct {
		Resource string `json:"resource"`
		Group    string `json:"group"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Resource == "" || body.Group == "" || len(body.Resource) > 255 || len(body.Group) > 255 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name the resource and the group, each by name or id"})
		return
	}
	ctx := c.Request.Context()
	orgID := orgIDFrom(ctx)
	f, err := s.planFacts(ctx, orgID, body.Resource, body.Group)
	switch {
	case errors.Is(err, errAmbiguous):
		c.JSON(http.StatusConflict, gin.H{"error": "that name matches more than one; use the id"})
		return
	case err != nil:
		s.logger.Error("access plan: facts failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read what the plan needs"})
		return
	}
	plan := accessplan.PlanOpenAccess(f)
	view := viewOf(f, plan)
	if plan.Status != accessplan.StatusReady {
		code := http.StatusOK
		if plan.Status == accessplan.StatusBlocked {
			code = http.StatusUnprocessableEntity
		}
		c.JSON(code, view)
		return
	}
	view.Now = s.memberCheck(ctx, orgID, f)
	params, _ := json.Marshal(map[string]string{
		"resource_id": f.ResourceID, "resource_name": f.ResourceName,
		"group_id": f.GroupID, "group_name": f.GroupName,
	})
	reasons, _ := json.Marshal(plan.Risks)
	target := f.ResourceID + ":" + f.GroupID
	var id string
	var created, expires time.Time
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO agentic_proposals (org_id, kind, target_type, target_id, params, reasons, base_hash, expires_at)
		VALUES ($1, 'access_open', 'resource', $2, $3::jsonb, $4::jsonb, $5, NOW() + make_interval(secs => $6))
		ON CONFLICT (org_id, kind, target_id) WHERE status = 'pending'
		DO UPDATE SET base_hash = EXCLUDED.base_hash, reasons = EXCLUDED.reasons, expires_at = EXCLUDED.expires_at
		RETURNING id::text, created_at, expires_at`,
		orgID, target, string(params), string(reasons), planHash(f), accessPlanLife.Seconds()).Scan(&id, &created, &expires)
	if err != nil {
		s.logger.Error("access plan: could not store", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store the plan"})
		return
	}
	view.ID, view.Status, view.CreatedAt, view.ExpiresAt = id, "pending", &created, &expires
	s.logAuditEvent(c, "access.plan.proposed", f.ResourceID, "application", map[string]interface{}{
		"group_id": f.GroupID, "plan": id, "risks": plan.Risks,
	})
	c.JSON(http.StatusCreated, view)
}

// handleListAccessPlans is GET /access/plans (operator): the plans waiting for
// a decision and the ones decided in the last week.
func (s *Service) handleListAccessPlans(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id::text, status, params, reasons, outcome, created_at, expires_at
		  FROM agentic_proposals
		 WHERE org_id = $1 AND kind = 'access_open'
		   AND ((status = 'pending' AND expires_at > NOW())
		        OR (status IN ('applied', 'rejected', 'undone') AND COALESCE(decided_at, created_at) > NOW() - INTERVAL '7 days'))
		 ORDER BY created_at DESC LIMIT 100`, orgIDFrom(ctx))
	if err != nil {
		s.logger.Error("access plans: list failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list the plans"})
		return
	}
	defer rows.Close()
	out := []accessPlanView{}
	for rows.Next() {
		var v accessPlanView
		var params, reasons []byte
		var created, expires time.Time
		if err := rows.Scan(&v.ID, &v.Status, &params, &reasons, &v.Outcome, &created, &expires); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list the plans"})
			return
		}
		var p map[string]string
		_ = json.Unmarshal(params, &p)
		v.Resource = planResource{ID: p["resource_id"], Name: p["resource_name"]}
		v.Group = planGroup{ID: p["group_id"], Name: p["group_name"]}
		v.Plan = accessplan.Plan{Status: accessplan.StatusReady, Blockers: []string{}, Notes: []string{},
			Steps: []accessplan.Step{{Action: accessplan.ActionGrantGroup, ResourceID: p["resource_id"], GroupID: p["group_id"]}}}
		_ = json.Unmarshal(reasons, &v.Plan.Risks)
		if v.Plan.Risks == nil {
			v.Plan.Risks = []string{}
		}
		v.CreatedAt, v.ExpiresAt = &created, &expires
		out = append(out, v)
	}
	c.JSON(http.StatusOK, gin.H{"plans": out})
}

// loadPendingPlan reads the plan an administrator is deciding on.
func (s *Service) loadPendingPlan(ctx context.Context, orgID, id string) (resourceID, groupID, baseHash string, err error) {
	var params []byte
	err = s.db.Pool.QueryRow(ctx, `
		SELECT params, base_hash FROM agentic_proposals
		 WHERE id = $1::uuid AND org_id = $2 AND kind = 'access_open' AND status = 'pending' AND expires_at > NOW()`,
		id, orgID).Scan(&params, &baseHash)
	if err != nil {
		return
	}
	var p map[string]string
	if json.Unmarshal(params, &p) != nil {
		err = errors.New("unreadable plan")
		return
	}
	return p["resource_id"], p["group_id"], baseHash, nil
}

func (s *Service) planDecider(c *gin.Context) interface{} {
	if u := c.GetString("user_id"); u != "" {
		if _, err := uuid.Parse(u); err == nil {
			return u
		}
	}
	return nil
}

// handleApproveAccessPlan is POST /access/plans/:id/approve (admin): carry the
// plan out if nothing has moved since it was laid out, then check what a member
// of the group can now do.
func (s *Service) handleApproveAccessPlan(c *gin.Context) {
	ctx := c.Request.Context()
	orgID := orgIDFrom(ctx)
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such plan"})
		return
	}
	rid, gid, baseHash, err := s.loadPendingPlan(ctx, orgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such plan, or it is no longer pending"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read the plan"})
		return
	}
	stale := func(msg string) {
		//silentwrite:ok the plan stays pending and expires by itself; the caller is told it is stale either way
		_, _ = s.db.Pool.Exec(ctx, `UPDATE agentic_proposals SET status = 'superseded', decided_at = NOW() WHERE id = $1::uuid AND org_id = $2`, id, orgID)
		c.JSON(http.StatusConflict, gin.H{"error": msg})
	}
	f, err := s.planFacts(ctx, orgID, rid, gid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read what the plan needs"})
		return
	}
	plan := accessplan.PlanOpenAccess(f)
	if plan.Status != accessplan.StatusReady || planHash(f) != baseHash {
		stale("the resource or the group changed since this plan was made")
		return
	}
	tag, err := s.db.Pool.Exec(ctx, `
		INSERT INTO group_application_assignments (group_id, application_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3) ON CONFLICT (group_id, application_id) DO NOTHING`, gid, rid, orgID)
	if err != nil {
		s.logger.Error("access plan: grant failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to carry out the plan"})
		return
	}
	after := s.memberCheck(ctx, orgID, f)
	outcome, _ := json.Marshal(map[string]interface{}{
		"granted": tag.RowsAffected() == 1, "applied_at": time.Now().UTC().Format(time.RFC3339), "after": after,
	})
	if _, err := s.db.Pool.Exec(ctx, `
		UPDATE agentic_proposals SET status = 'applied', decided_by = $3::uuid, decided_at = NOW(), outcome = $4::jsonb
		 WHERE id = $1::uuid AND org_id = $2`, id, orgID, s.planDecider(c), string(outcome)); err != nil {
		s.logger.Warn("access plan: could not close an applied plan", zap.Error(err))
	}
	s.logAuditEvent(c, "access.plan.applied", rid, "application", map[string]interface{}{
		"group_id": gid, "plan": id, "granted": tag.RowsAffected() == 1,
	})
	c.JSON(http.StatusOK, gin.H{"granted": tag.RowsAffected() == 1, "after": after})
}

// handleRejectAccessPlan is POST /access/plans/:id/reject (admin).
func (s *Service) handleRejectAccessPlan(c *gin.Context) {
	ctx := c.Request.Context()
	orgID := orgIDFrom(ctx)
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such plan"})
		return
	}
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE agentic_proposals SET status = 'rejected', decided_by = $3::uuid, decided_at = NOW()
		 WHERE id = $1::uuid AND org_id = $2 AND kind = 'access_open' AND status = 'pending'`, id, orgID, s.planDecider(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reject the plan"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such plan, or it is no longer pending"})
		return
	}
	s.logAuditEvent(c, "access.plan.rejected", id, "access_plan", map[string]interface{}{"plan": id})
	c.JSON(http.StatusOK, gin.H{"rejected": id})
}

// handleUndoAccessPlan is POST /access/plans/:id/undo (admin): take back
// exactly what an applied plan granted. A plan that found the grant already in
// place granted nothing and has nothing to undo.
func (s *Service) handleUndoAccessPlan(c *gin.Context) {
	ctx := c.Request.Context()
	orgID := orgIDFrom(ctx)
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such plan"})
		return
	}
	var params, outcome []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT params, outcome FROM agentic_proposals
		 WHERE id = $1::uuid AND org_id = $2 AND kind = 'access_open' AND status = 'applied'`, id, orgID).Scan(&params, &outcome)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such plan, or it was not applied"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read the plan"})
		return
	}
	var p map[string]string
	var o struct {
		Granted bool `json:"granted"`
	}
	_ = json.Unmarshal(params, &p)
	_ = json.Unmarshal(outcome, &o)
	if !o.Granted {
		c.JSON(http.StatusConflict, gin.H{"error": "this plan granted nothing: the access was already there, so there is nothing to undo"})
		return
	}
	if _, err := s.db.Pool.Exec(ctx, `
		DELETE FROM group_application_assignments WHERE group_id = $1::uuid AND application_id = $2::uuid AND org_id = $3`,
		p["group_id"], p["resource_id"], orgID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to take the access back"})
		return
	}
	if _, err := s.db.Pool.Exec(ctx, `
		UPDATE agentic_proposals SET status = 'undone', decided_by = $3::uuid, decided_at = NOW()
		 WHERE id = $1::uuid AND org_id = $2`, id, orgID, s.planDecider(c)); err != nil {
		s.logger.Warn("access plan: could not close an undone plan", zap.Error(err))
	}
	s.logAuditEvent(c, "access.plan.undone", p["resource_id"], "application", map[string]interface{}{
		"group_id": p["group_id"], "plan": id,
	})
	c.JSON(http.StatusOK, gin.H{"undone": id})
}
