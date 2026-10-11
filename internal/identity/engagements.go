package identity

// Vendor engagements (migration v234): the unit of a vendor's work. An
// engagement names a vendor organization, an internal sponsor, a window, the
// vendor's people on it (none named meaning every live external user of the
// vendor) and its targets: applications (network resources included), PAM
// entries and enrolled devices.
//
// While an engagement runs, syncEngagementGrants writes the grants it implies
// and keeps them to its window: a connect grant on each PAM entry for each
// member (pam_entry_grants.engagement_id) and an assignment to each
// application (user_application_assignments, its window recorded in
// vendor_engagement_app_grants). Every enforcement point already reads those
// grants and their windows (appaccess, the proxy, /oauth/authorize, the
// overlay reconciler, the PAM launch and the PAM lifecycle sweep), so an
// engagement needs no enforcement of its own to start or end access. When an
// engagement ends or is closed, the same function cuts what it wrote.
//
// A vendor with require_engagement on has a stricter rule on top
// (internal/externalid.CheckEngagement, I13): its external users reach,
// launch and ask for a target only inside a running engagement that covers
// it, whatever other grant they hold.
//
// Administrator routes, like the rest of the vendor API, every change
// audited. The closing report gathers what happened in the window: the
// members' PAM sessions with their recordings, their access requests, the
// remote-support sessions on the engagement's devices and their audited
// actions.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/externalid"
)

// Engagement is the API view of a vendor_engagements row.
type Engagement struct {
	ID            string             `json:"id"`
	VendorOrgID   string             `json:"vendor_org_id"`
	VendorName    string             `json:"vendor_name"`
	SponsorUserID string             `json:"sponsor_user_id"`
	SponsorName   string             `json:"sponsor_name"`
	Title         string             `json:"title"`
	Purpose       string             `json:"purpose"`
	TicketRef     string             `json:"ticket_ref"`
	StartsAt      time.Time          `json:"starts_at"`
	EndsAt        time.Time          `json:"ends_at"`
	MemberUserIDs []string           `json:"member_user_ids"`
	Status        string             `json:"status"`
	State         string             `json:"state"`
	ClosedAt      *time.Time         `json:"closed_at,omitempty"`
	CloseReason   string             `json:"close_reason,omitempty"`
	Targets       []EngagementTarget `json:"targets"`
	CreatedAt     time.Time          `json:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at"`
}

// EngagementTarget is one thing an engagement covers.
type EngagementTarget struct {
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	TargetName string `json:"target_name"`
}

// Engagement states, derived from the status and the clock.
const (
	engagementScheduled = "scheduled"
	engagementRunning   = "running"
	engagementEnded     = "ended"
	engagementClosed    = "closed"
)

// engagementReq is the create and update body. starts_at defaults to now on a
// create; on an update every field left out keeps its value.
type engagementReq struct {
	Title         string     `json:"title"`
	Purpose       *string    `json:"purpose"`
	TicketRef     *string    `json:"ticket_ref"`
	SponsorUserID string     `json:"sponsor_user_id"`
	StartsAt      *time.Time `json:"starts_at"`
	EndsAt        *time.Time `json:"ends_at"`
	MemberUserIDs []string   `json:"member_user_ids"`
	Targets       []struct {
		TargetType string `json:"target_type"`
		TargetID   string `json:"target_id"`
	} `json:"targets"`
}

// engagementDB is what the engagement statements run on: the pool or a
// transaction.
type engagementDB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

const engagementSelect = `
	SELECT e.id::text, e.vendor_org_id::text, v.name, COALESCE(e.sponsor_user_id::text, ''),
	       COALESCE(NULLIF(TRIM(COALESCE(sp.first_name, '') || ' ' || COALESCE(sp.last_name, '')), ''), sp.username, ''),
	       e.title, e.purpose, e.ticket_ref, e.starts_at, e.ends_at,
	       COALESCE((SELECT array_agg(m::text) FROM unnest(e.member_user_ids) m), '{}'),
	       e.status,
	       CASE WHEN e.status = 'closed' THEN 'closed'
	            WHEN e.ends_at <= NOW() THEN 'ended'
	            WHEN e.starts_at > NOW() THEN 'scheduled'
	            ELSE 'running' END,
	       e.closed_at, COALESCE(e.close_reason, ''), e.created_at, e.updated_at
	  FROM vendor_engagements e
	  JOIN vendor_organizations v ON v.id = e.vendor_org_id AND v.org_id = e.org_id
	  LEFT JOIN users sp ON sp.id = e.sponsor_user_id`

func scanEngagement(row pgx.Row) (*Engagement, error) {
	var e Engagement
	if err := row.Scan(&e.ID, &e.VendorOrgID, &e.VendorName, &e.SponsorUserID, &e.SponsorName,
		&e.Title, &e.Purpose, &e.TicketRef, &e.StartsAt, &e.EndsAt, &e.MemberUserIDs,
		&e.Status, &e.State, &e.ClosedAt, &e.CloseReason, &e.CreatedAt, &e.UpdatedAt); err != nil {
		return nil, err
	}
	if e.MemberUserIDs == nil {
		e.MemberUserIDs = []string{}
	}
	e.Targets = []EngagementTarget{}
	return &e, nil
}

// engagementTargets reads the targets of the engagements named, by id.
func engagementTargets(ctx context.Context, q engagementDB, orgID string, ids []string) (map[string][]EngagementTarget, error) {
	out := map[string][]EngagementTarget{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `
		SELECT t.engagement_id::text, t.target_type, t.target_id,
		       COALESCE(a.name, pe.name, NULLIF(ag.metadata->>'hostname', ''), ag.agent_id, '')
		  FROM vendor_engagement_targets t
		  LEFT JOIN applications a ON t.target_type = 'application' AND a.id::text = t.target_id AND a.org_id = t.org_id
		  LEFT JOIN pam_entries pe ON t.target_type = 'pam_entry' AND pe.id::text = t.target_id AND pe.org_id = t.org_id
		  LEFT JOIN enrolled_agents ag ON t.target_type = 'device' AND ag.agent_id = t.target_id AND ag.org_id = t.org_id
		 WHERE t.org_id = $1 AND t.engagement_id::text = ANY ($2::text[])
		 ORDER BY t.target_type, 4`, orgID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var t EngagementTarget
		if err := rows.Scan(&id, &t.TargetType, &t.TargetID, &t.TargetName); err != nil {
			return nil, err
		}
		out[id] = append(out[id], t)
	}
	return out, rows.Err()
}

// listEngagements reads the engagements matching where (over e), newest first,
// with their targets.
func (s *Service) listEngagements(ctx context.Context, orgID, where string, args ...any) ([]*Engagement, error) {
	rows, err := s.db.Pool.Query(ctx, engagementSelect+` WHERE e.org_id = $1 `+where+` ORDER BY e.starts_at DESC LIMIT 500`,
		append([]any{orgID}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []*Engagement{}
	ids := []string{}
	for rows.Next() {
		e, err := scanEngagement(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, e)
		ids = append(ids, e.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	targets, err := engagementTargets(ctx, s.db.Pool, orgID, ids)
	if err != nil {
		return nil, err
	}
	for _, e := range list {
		if t := targets[e.ID]; t != nil {
			e.Targets = t
		}
	}
	return list, nil
}

// getEngagement reads one engagement of the org with its targets.
func (s *Service) getEngagement(ctx context.Context, q engagementDB, orgID, id string) (*Engagement, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, externalid.ErrEngagementNotFound
	}
	e, err := scanEngagement(q.QueryRow(ctx, engagementSelect+` WHERE e.id = $1::uuid AND e.org_id = $2`, id, orgID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, externalid.ErrEngagementNotFound
	}
	if err != nil {
		return nil, err
	}
	targets, err := engagementTargets(ctx, q, orgID, []string{id})
	if err != nil {
		return nil, err
	}
	if t := targets[id]; t != nil {
		e.Targets = t
	}
	return e, nil
}

// validEngagement is a checked engagementReq.
type validEngagement struct {
	title, purpose, ticket, sponsor string
	starts, ends                    time.Time
	// startNow is a create with no start: the row takes the database's
	// clock, which is the clock every running check reads (a Go timestamp
	// taken inside the transaction is later than its NOW()).
	startNow bool
	members  []string
	targets  [][2]string
}

// checkEngagement validates req for the vendor; current is the engagement
// being updated (nil on a create). It answers externalid refusals for what the
// caller got wrong.
func (s *Service) checkEngagement(ctx context.Context, q engagementDB, orgID, vendorID string, req engagementReq, current *Engagement) (*validEngagement, error) {
	v := &validEngagement{
		title:   strings.TrimSpace(req.Title),
		sponsor: strings.TrimSpace(req.SponsorUserID),
	}
	if current != nil {
		if v.title == "" {
			v.title = current.Title
		}
		v.purpose, v.ticket = current.Purpose, current.TicketRef
	}
	if req.Purpose != nil {
		v.purpose = strings.TrimSpace(*req.Purpose)
	}
	if req.TicketRef != nil {
		v.ticket = strings.TrimSpace(*req.TicketRef)
	}
	if v.title == "" || len(v.title) > 200 || len(v.ticket) > 200 {
		return nil, errEngagementTitle
	}
	now := time.Now()
	switch {
	case req.StartsAt != nil:
		v.starts = *req.StartsAt
	case current != nil:
		v.starts = current.StartsAt
	default:
		v.starts, v.startNow = now, true
	}
	// A running engagement's start is history: an update may not move it.
	if current != nil && !current.StartsAt.After(now) && !v.starts.Equal(current.StartsAt) {
		return nil, externalid.ErrEngagementWindow
	}
	switch {
	case req.EndsAt != nil:
		v.ends = *req.EndsAt
	case current != nil:
		v.ends = current.EndsAt
	default:
		return nil, externalid.ErrEngagementWindow
	}
	if !v.ends.After(v.starts) || !v.ends.After(now) {
		return nil, externalid.ErrEngagementWindow
	}
	if v.ends.Sub(v.starts) > externalid.MaxEngagementDays*24*time.Hour {
		return nil, externalid.ErrEngagementTooLong
	}

	var status string
	var closedList bool
	var contractEnd *time.Time
	var defaultSponsor string
	err := q.QueryRow(ctx, `
		SELECT status, closed_list, contract_end::timestamptz, COALESCE(default_sponsor_user_id::text, '')
		  FROM vendor_organizations WHERE id = $1::uuid AND org_id = $2`, vendorID, orgID).
		Scan(&status, &closedList, &contractEnd, &defaultSponsor)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errVendorOrgNotFound
	}
	if err != nil {
		return nil, err
	}
	if status != "active" {
		return nil, externalid.ErrVendorNotActive
	}
	// The contract's last day counts in full.
	if contractEnd != nil && v.ends.After(contractEnd.Add(24*time.Hour)) {
		return nil, externalid.ErrEngagementContract
	}

	if v.sponsor == "" {
		if current != nil && current.SponsorUserID != "" {
			v.sponsor = current.SponsorUserID
		} else {
			v.sponsor = defaultSponsor
		}
	}
	if v.sponsor == "" {
		return nil, externalid.ErrSponsorInvalid
	}
	if err := externalid.CheckSponsor(ctx, q, orgID, v.sponsor); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	for _, m := range req.MemberUserIDs {
		m = strings.TrimSpace(m)
		if _, err := uuid.Parse(m); err != nil {
			return nil, externalid.ErrEngagementMember
		}
		if !seen[m] {
			seen[m] = true
			v.members = append(v.members, m)
		}
	}
	if v.members == nil {
		v.members = []string{}
	}
	if len(v.members) > 0 {
		var n int
		if err := q.QueryRow(ctx, `
			SELECT count(*) FROM users
			 WHERE org_id = $1 AND vendor_org_id = $2::uuid AND user_type = 'external' AND id::text = ANY ($3::text[])`,
			orgID, vendorID, v.members).Scan(&n); err != nil {
			return nil, err
		}
		if n != len(v.members) {
			return nil, externalid.ErrEngagementMember
		}
	}

	if len(req.Targets) == 0 {
		return nil, externalid.ErrEngagementNoTargets
	}
	seenT := map[[2]string]bool{}
	for _, t := range req.Targets {
		key := [2]string{strings.TrimSpace(t.TargetType), strings.TrimSpace(t.TargetID)}
		if !externalid.EngagementTargetTypes[key[0]] || key[1] == "" {
			return nil, externalid.ErrEngagementBadTarget
		}
		if seenT[key] {
			continue
		}
		seenT[key] = true
		var exists, open bool
		var err error
		switch key[0] {
		case "application", "pam_entry":
			if _, perr := uuid.Parse(key[1]); perr != nil {
				return nil, externalid.ErrEngagementBadTarget
			}
			table := map[string]string{"application": "applications", "pam_entry": "pam_entries"}[key[0]]
			err = q.QueryRow(ctx, `
				SELECT EXISTS (SELECT 1 FROM `+table+` WHERE id = $1::uuid AND org_id = $2),
				       EXISTS (SELECT 1 FROM vendor_org_targets
				                WHERE vendor_org_id = $3::uuid AND org_id = $2 AND target_type = $4 AND target_id = $1::uuid)`,
				key[1], orgID, vendorID, key[0]).Scan(&exists, &open)
		case "device":
			open = true
			err = q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM enrolled_agents WHERE agent_id = $1 AND org_id = $2)`,
				key[1], orgID).Scan(&exists)
		}
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, externalid.ErrEngagementBadTarget
		}
		if closedList && !open {
			return nil, externalid.ErrEngagementTargetShut
		}
		v.targets = append(v.targets, key)
	}
	return v, nil
}

var errEngagementTitle = errors.New("an engagement needs a title of at most 200 characters (and a ticket reference of at most 200)")

// writeEngagementTargets replaces the engagement's targets with v's.
func writeEngagementTargets(ctx context.Context, q engagementDB, orgID, id string, v *validEngagement) error {
	if _, err := q.Exec(ctx, `DELETE FROM vendor_engagement_targets WHERE engagement_id = $1::uuid AND org_id = $2`, id, orgID); err != nil {
		return err
	}
	for _, t := range v.targets {
		if _, err := q.Exec(ctx, `
			INSERT INTO vendor_engagement_targets (engagement_id, org_id, target_type, target_id)
			VALUES ($1::uuid, $2, $3, $4)`, id, orgID, t[0], t[1]); err != nil {
			return err
		}
	}
	return nil
}

// engagementSync is what one syncEngagementGrants pass changed.
type engagementSync struct {
	PamGranted, PamCut, AppsGranted, AppsCut int64
}

// engagementMembersCTE is the running engagement $2 of org $1 (no row when it
// is not running) and its members: the external users of its vendor whose
// account is active, limited to those it names when it names any.
const engagementMembersCTE = `
	WITH e AS (
		SELECT id, vendor_org_id, member_user_ids, ends_at FROM vendor_engagements
		 WHERE id = $2::uuid AND org_id = $1 AND status = 'open' AND starts_at <= NOW() AND ends_at > NOW()),
	m AS (
		SELECT u.id FROM users u, e
		 WHERE u.org_id = $1 AND u.vendor_org_id = e.vendor_org_id AND u.user_type = 'external'
		   AND u.account_status = 'active'
		   AND (cardinality(e.member_user_ids) = 0 OR u.id = ANY (e.member_user_ids))),
	pt AS (
		SELECT pe.id AS entry_id FROM vendor_engagement_targets t
		  JOIN pam_entries pe ON pe.id::text = t.target_id AND pe.org_id = t.org_id
		 WHERE t.engagement_id = $2::uuid AND t.org_id = $1 AND t.target_type = 'pam_entry'),
	at AS (
		SELECT a.id AS app_id FROM vendor_engagement_targets t
		  JOIN applications a ON a.id::text = t.target_id AND a.org_id = t.org_id
		 WHERE t.engagement_id = $2::uuid AND t.org_id = $1 AND t.target_type = 'application')`

// engagementAssignmentWindow is the window an application assignment takes
// when engagement $2 writes EXCLUDED's: a standing row stays standing, a row
// still carrying the window this engagement wrote follows the engagement
// (longer or shorter), and any other row keeps the later of the two.
const engagementAssignmentWindow = `CASE
		    WHEN user_application_assignments.expires_at IS NULL THEN NULL
		    WHEN EXISTS (SELECT 1 FROM vendor_engagement_app_grants g
		                  WHERE g.engagement_id = $2::uuid AND g.user_id = user_application_assignments.user_id
		                    AND g.application_id = user_application_assignments.application_id
		                    AND g.written_until = user_application_assignments.expires_at) THEN EXCLUDED.expires_at
		    ELSE GREATEST(user_application_assignments.expires_at, EXCLUDED.expires_at) END`

// The four statements below continue engagementMembersCTE, so none is a
// statement on its own and tools/sqlprepare (which prepares single literals)
// does not see them; TestAnEngagementGrantsItsTargetsForItsWindowAndNothingElse
// runs each against the migrated schema.
//
// syncEngagementGrants makes the grants of engagement id match it: while it
// runs, a connect grant on each PAM entry and an assignment to each
// application for each member, ending with the engagement (the v215/v222
// triggers end them no later than each account); otherwise, and for a member
// or target no longer on it, nothing. It writes only what changed, so the
// sweep can call it every minute.
//
// An application assignment is shared: a request or an administrator may
// hold the same row. A standing row stays standing, a later window stays
// later, and the engagement cuts only a row that still carries the window it
// wrote.
func syncEngagementGrants(ctx context.Context, q engagementDB, orgID, id string) (engagementSync, error) {
	var out engagementSync
	if err := q.QueryRow(ctx, engagementMembersCTE+`,
	cut AS (
		UPDATE pam_entry_grants g SET expires_at = NOW()
		 WHERE g.engagement_id = $2::uuid AND g.org_id = $1
		   AND (g.expires_at IS NULL OR g.expires_at > NOW())
		   AND NOT EXISTS (SELECT 1 FROM m, pt WHERE pt.entry_id = g.entry_id AND m.id::text = g.principal_id)
		RETURNING 1)
		SELECT count(*) FROM cut`, orgID, id).Scan(&out.PamCut); err != nil {
		return out, err
	}
	if err := q.QueryRow(ctx, engagementMembersCTE+`,
	granted AS (
		INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions, expires_at, engagement_id)
		SELECT $1, pt.entry_id, 'user', m.id::text, ARRAY['connect'], e.ends_at, e.id FROM e, m, pt
		ON CONFLICT (engagement_id, entry_id, principal_id) WHERE engagement_id IS NOT NULL
		DO UPDATE SET expires_at = EXCLUDED.expires_at
		 WHERE pam_entry_grants.expires_at IS DISTINCT FROM EXCLUDED.expires_at
		RETURNING 1)
		SELECT count(*) FROM granted`, orgID, id).Scan(&out.PamGranted); err != nil {
		return out, err
	}
	tag, err := q.Exec(ctx, engagementMembersCTE+`,
	gone AS (
		DELETE FROM vendor_engagement_app_grants g
		 WHERE g.engagement_id = $2::uuid AND g.org_id = $1
		   AND NOT EXISTS (SELECT 1 FROM m, at WHERE m.id = g.user_id AND at.app_id = g.application_id)
		RETURNING g.user_id, g.application_id, g.written_until)
		UPDATE user_application_assignments uaa SET expires_at = NOW()
		  FROM gone
		 WHERE uaa.user_id = gone.user_id AND uaa.application_id = gone.application_id AND uaa.org_id = $1
		   AND uaa.expires_at = gone.written_until AND gone.written_until > NOW()`, orgID, id)
	if err != nil {
		return out, err
	}
	out.AppsCut = tag.RowsAffected()
	tag, err = q.Exec(ctx, engagementMembersCTE+`,
	up AS (
		INSERT INTO user_application_assignments (user_id, application_id, org_id, expires_at)
		SELECT m.id, at.app_id, $1, e.ends_at FROM e, m, at
		ON CONFLICT (user_id, application_id) DO UPDATE SET expires_at = `+engagementAssignmentWindow+`
		 WHERE user_application_assignments.expires_at IS DISTINCT FROM `+engagementAssignmentWindow+`
		RETURNING user_id, application_id, expires_at)
		INSERT INTO vendor_engagement_app_grants (engagement_id, org_id, user_id, application_id, written_until)
		SELECT $2::uuid, $1, up.user_id, up.application_id, up.expires_at FROM up, e
		 WHERE up.expires_at IS NOT NULL AND up.expires_at <= e.ends_at
		ON CONFLICT (engagement_id, user_id, application_id) DO UPDATE SET written_until = EXCLUDED.written_until`, orgID, id)
	if err != nil {
		return out, err
	}
	out.AppsGranted = tag.RowsAffected()
	if _, err := q.Exec(ctx, `UPDATE vendor_engagements SET grants_synced_at = NOW() WHERE id = $1::uuid AND org_id = $2`, id, orgID); err != nil {
		return out, err
	}
	return out, nil
}

func (sy engagementSync) details() map[string]interface{} {
	return map[string]interface{}{"pam_granted": sy.PamGranted, "pam_cut": sy.PamCut, "apps_granted": sy.AppsGranted, "apps_cut": sy.AppsCut}
}

// writeEngagementError answers an engagement error: a refusal is a 4xx.
func (s *Service) writeEngagementError(c *gin.Context, err error, what string) {
	switch {
	case errors.Is(err, externalid.ErrEngagementNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, errVendorOrgNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, errEngagementTitle):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "engagement_title_invalid"})
	case errors.Is(err, externalid.ErrEngagementClosed):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error(), "code": externalid.Code(err)})
	case externalid.Refusal(err) != nil:
		r := externalid.Refusal(err)
		status := http.StatusBadRequest
		if errors.Is(r, externalid.ErrVendorNotActive) {
			status = http.StatusConflict
		}
		c.JSON(status, gin.H{"error": r.Error(), "code": externalid.Code(r)})
	default:
		s.logger.Error(what+" failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to " + what})
	}
}

// handleListEngagements — GET /engagements[?state=scheduled|running|ended|closed].
func (s *Service) handleListEngagements(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	where, args := "", []any{}
	switch c.Query("state") {
	case "":
	case engagementScheduled:
		where = `AND e.status = 'open' AND e.starts_at > NOW()`
	case engagementRunning:
		where = `AND e.status = 'open' AND e.starts_at <= NOW() AND e.ends_at > NOW()`
	case engagementEnded:
		where = `AND e.status = 'open' AND e.ends_at <= NOW()`
	case engagementClosed:
		where = `AND e.status = 'closed'`
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "state must be scheduled, running, ended or closed"})
		return
	}
	list, err := s.listEngagements(ctx, org.ID, where, args...)
	if err != nil {
		s.writeEngagementError(c, err, "list engagements")
		return
	}
	c.JSON(http.StatusOK, gin.H{"engagements": list})
}

// handleListVendorEngagements — GET /vendor-orgs/:id/engagements.
func (s *Service) handleListVendorEngagements(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	if !s.vendorForTargets(c, org.ID, false) {
		return
	}
	list, err := s.listEngagements(ctx, org.ID, `AND e.vendor_org_id::text = $2`, c.Param("id"))
	if err != nil {
		s.writeEngagementError(c, err, "list engagements")
		return
	}
	c.JSON(http.StatusOK, gin.H{"engagements": list})
}

// handleGetEngagement — GET /engagements/:id.
func (s *Service) handleGetEngagement(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	e, err := s.getEngagement(ctx, s.db.Pool, org.ID, c.Param("id"))
	if err != nil {
		s.writeEngagementError(c, err, "read the engagement")
		return
	}
	c.JSON(http.StatusOK, e)
}

// handleCreateEngagement — POST /vendor-orgs/:id/engagements. The vendor must
// be active; the window ends in the future, after it starts, within 365 days
// and the vendor's contract; the sponsor (default: the vendor's default
// sponsor) is an enabled internal user; the members are external users of the
// vendor; every target exists in the organization and, for a vendor on a
// closed list, is open to it. An engagement that starts now has its grants
// written before the response.
func (s *Service) handleCreateEngagement(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var req engagementReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	vendorID := c.Param("id")
	if _, err := uuid.Parse(vendorID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": errVendorOrgNotFound.Error()})
		return
	}
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		s.writeEngagementError(c, err, "create the engagement")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	v, err := s.checkEngagement(ctx, tx, org.ID, vendorID, req, nil)
	if err != nil {
		s.writeEngagementError(c, err, "create the engagement")
		return
	}
	actor := c.GetString("user_id")
	var id string
	if err := tx.QueryRow(ctx, `
		INSERT INTO vendor_engagements
		    (org_id, vendor_org_id, sponsor_user_id, title, purpose, ticket_ref, starts_at, ends_at, member_user_ids, created_by)
		VALUES ($1, $2::uuid, $3::uuid, $4, $5, $6, CASE WHEN $11 THEN NOW() ELSE $7 END, $8, $9::uuid[], NULLIF($10, '')::uuid)
		RETURNING id::text`,
		org.ID, vendorID, v.sponsor, v.title, v.purpose, v.ticket, v.starts, v.ends, v.members, actor, v.startNow).Scan(&id); err != nil {
		s.writeEngagementError(c, err, "create the engagement")
		return
	}
	if err := writeEngagementTargets(ctx, tx, org.ID, id, v); err != nil {
		s.writeEngagementError(c, err, "create the engagement")
		return
	}
	sy, err := syncEngagementGrants(ctx, tx, org.ID, id)
	if err != nil {
		s.writeEngagementError(c, err, "create the engagement")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.writeEngagementError(c, err, "create the engagement")
		return
	}
	details := sy.details()
	details["vendor_org_id"], details["title"], details["starts_at"], details["ends_at"] = vendorID, v.title, v.starts, v.ends
	details["members"], details["targets"] = len(v.members), len(v.targets)
	s.logAuditEvent(ctx, "identity", "external_access", "vendor_engagement.created", "success", actor, id, "vendor_engagement", details)
	e, err := s.getEngagement(ctx, s.db.Pool, org.ID, id)
	if err != nil {
		c.JSON(http.StatusCreated, gin.H{"id": id})
		return
	}
	c.JSON(http.StatusCreated, e)
}

// handleUpdateEngagement — PUT /engagements/:id. An open engagement's title,
// purpose, ticket, sponsor, members, targets and end may change (its start
// only before it starts); its grants follow before the response. A closed
// engagement cannot change.
func (s *Service) handleUpdateEngagement(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var req engagementReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	id := c.Param("id")
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		s.writeEngagementError(c, err, "update the engagement")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := uuid.Parse(id); err != nil {
		s.writeEngagementError(c, externalid.ErrEngagementNotFound, "update the engagement")
		return
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM vendor_engagements WHERE id = $1::uuid AND org_id = $2 FOR UPDATE`, id, org.ID); err != nil {
		s.writeEngagementError(c, err, "update the engagement")
		return
	}
	current, err := s.getEngagement(ctx, tx, org.ID, id)
	if err != nil {
		s.writeEngagementError(c, err, "update the engagement")
		return
	}
	if current.Status == "closed" {
		s.writeEngagementError(c, externalid.ErrEngagementClosed, "update the engagement")
		return
	}
	if req.Targets == nil {
		for _, t := range current.Targets {
			req.Targets = append(req.Targets, struct {
				TargetType string `json:"target_type"`
				TargetID   string `json:"target_id"`
			}{t.TargetType, t.TargetID})
		}
	}
	if req.MemberUserIDs == nil {
		req.MemberUserIDs = current.MemberUserIDs
	}
	v, err := s.checkEngagement(ctx, tx, org.ID, current.VendorOrgID, req, current)
	if err != nil {
		s.writeEngagementError(c, err, "update the engagement")
		return
	}
	if _, err := tx.Exec(ctx, `
		UPDATE vendor_engagements
		   SET sponsor_user_id = $3::uuid, title = $4, purpose = $5, ticket_ref = $6, starts_at = $7, ends_at = $8,
		       member_user_ids = $9::uuid[], updated_at = NOW()
		 WHERE id = $1::uuid AND org_id = $2 AND status = 'open'`,
		id, org.ID, v.sponsor, v.title, v.purpose, v.ticket, v.starts, v.ends, v.members); err != nil {
		s.writeEngagementError(c, err, "update the engagement")
		return
	}
	if err := writeEngagementTargets(ctx, tx, org.ID, id, v); err != nil {
		s.writeEngagementError(c, err, "update the engagement")
		return
	}
	sy, err := syncEngagementGrants(ctx, tx, org.ID, id)
	if err != nil {
		s.writeEngagementError(c, err, "update the engagement")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.writeEngagementError(c, err, "update the engagement")
		return
	}
	details := sy.details()
	details["ends_at"], details["previous_ends_at"] = v.ends, current.EndsAt
	details["members"], details["targets"] = len(v.members), len(v.targets)
	s.logAuditEvent(ctx, "identity", "external_access", "vendor_engagement.updated", "success", c.GetString("user_id"), id, "vendor_engagement", details)
	e, err := s.getEngagement(ctx, s.db.Pool, org.ID, id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"id": id})
		return
	}
	c.JSON(http.StatusOK, e)
}

// handleCloseEngagement — POST /engagements/:id/close {reason?}. Ends an open
// engagement now: cancelled when it had not started, closed otherwise. Its
// grants are cut before the response; a PAM session riding one ends at the
// access service's next lifecycle pass, as for any ended grant.
func (s *Service) handleCloseEngagement(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	_ = c.ShouldBindJSON(&body)
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		s.writeEngagementError(c, externalid.ErrEngagementNotFound, "close the engagement")
		return
	}
	actor := c.GetString("user_id")
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		s.writeEngagementError(c, err, "close the engagement")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var reason string
	err = tx.QueryRow(ctx, `
		UPDATE vendor_engagements
		   SET status = 'closed', closed_at = NOW(), closed_by = NULLIF($3, '')::uuid,
		       close_reason = CASE WHEN starts_at > NOW() THEN 'cancelled' ELSE 'closed' END, updated_at = NOW()
		 WHERE id = $1::uuid AND org_id = $2 AND status = 'open'
		RETURNING close_reason`, id, org.ID, actor).Scan(&reason)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, gerr := s.getEngagement(ctx, tx, org.ID, id); gerr != nil {
			s.writeEngagementError(c, gerr, "close the engagement")
			return
		}
		s.writeEngagementError(c, externalid.ErrEngagementClosed, "close the engagement")
		return
	}
	if err != nil {
		s.writeEngagementError(c, err, "close the engagement")
		return
	}
	sy, err := syncEngagementGrants(ctx, tx, org.ID, id)
	if err != nil {
		s.writeEngagementError(c, err, "close the engagement")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.writeEngagementError(c, err, "close the engagement")
		return
	}
	details := sy.details()
	details["reason"], details["note"] = reason, body.Note
	s.logAuditEvent(ctx, "identity", "external_access", "vendor_engagement."+reason, "success", actor, id, "vendor_engagement", details)
	e, err := s.getEngagement(ctx, s.db.Pool, org.ID, id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"id": id, "close_reason": reason})
		return
	}
	c.JSON(http.StatusOK, e)
}

// sweepEngagements is part of the external account sweep: each tick it
// closes the engagements whose window is over (or whose vendor is closed) and
// brings every started engagement's grants in line with it, so an engagement
// scheduled for later starts on time and a member who became active, or
// stopped being, is followed within a minute.
func (s *Service) sweepEngagements(ctx context.Context) {
	//orgscope:ignore background sweep of vendor engagements across all orgs; each row's org is returned and audited
	rows, err := s.db.Pool.Query(ctx, `
		UPDATE vendor_engagements e
		   SET status = 'closed', closed_at = NOW(), updated_at = NOW(),
		       close_reason = CASE WHEN v.status = 'closed' THEN 'vendor_closed' ELSE 'ended' END
		  FROM vendor_organizations v
		 WHERE v.id = e.vendor_org_id AND v.org_id = e.org_id
		   AND e.status = 'open' AND (e.ends_at <= NOW() OR v.status = 'closed')
		RETURNING e.id::text, e.org_id::text, e.close_reason`)
	if err != nil {
		s.logger.Error("engagement sweep: close failed", zap.Error(err))
		return
	}
	type closed struct{ id, org, reason string }
	var ended []closed
	for rows.Next() {
		var x closed
		if err := rows.Scan(&x.id, &x.org, &x.reason); err != nil {
			s.logger.Error("engagement sweep: scan failed", zap.Error(err))
			break
		}
		ended = append(ended, x)
	}
	rows.Close()
	for _, x := range ended {
		s.logAuditEvent(orgctx.With(ctx, orgctx.Org{ID: x.org}), "identity", "external_access", "vendor_engagement."+x.reason,
			"success", "system", x.id, "vendor_engagement", map[string]interface{}{"reason": x.reason})
	}

	//orgscope:ignore background sweep of vendor engagements across all orgs; each row's org is carried into the sync
	rows, err = s.db.Pool.Query(ctx, `
		SELECT id::text, org_id::text FROM vendor_engagements
		 WHERE (status = 'open' AND starts_at <= NOW())
		    OR (status = 'closed' AND (grants_synced_at IS NULL OR grants_synced_at < closed_at))
		 ORDER BY starts_at
		 LIMIT `+"200")
	if err != nil {
		s.logger.Error("engagement sweep: list failed", zap.Error(err))
		return
	}
	type due struct{ id, org string }
	var list []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.org); err != nil {
			s.logger.Error("engagement sweep: scan failed", zap.Error(err))
			break
		}
		list = append(list, d)
	}
	rows.Close()
	for _, d := range list {
		sy, err := syncEngagementGrants(ctx, s.db.Pool, d.org, d.id)
		if err != nil {
			s.logger.Error("engagement sweep: sync failed", logsafe.String("engagement_id", d.id), zap.Error(err))
			continue
		}
		if sy.PamGranted+sy.PamCut+sy.AppsGranted+sy.AppsCut > 0 {
			s.logAuditEvent(orgctx.With(ctx, orgctx.Org{ID: d.org}), "identity", "external_access", "vendor_engagement.grants_synced",
				"success", "system", d.id, "vendor_engagement", sy.details())
		}
	}
}

// EngagementReport is what happened during an engagement's window.
type EngagementReport struct {
	Engagement     *Engagement               `json:"engagement"`
	GeneratedAt    time.Time                 `json:"generated_at"`
	WindowStart    time.Time                 `json:"window_start"`
	WindowEnd      time.Time                 `json:"window_end"`
	Members        []engagementReportMember  `json:"members"`
	PamSessions    []engagementReportPam     `json:"pam_sessions"`
	AccessRequests []engagementReportRequest `json:"access_requests"`
	RemoteSupport  []engagementReportRemote  `json:"remote_support_sessions"`
	Actions        []engagementReportAction  `json:"audited_actions"`
	GrantsHeld     map[string]int            `json:"grants_held"`
}

type engagementReportMember struct {
	UserID        string `json:"user_id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	AccountStatus string `json:"account_status"`
}

type engagementReportPam struct {
	ID        string     `json:"id"`
	EntryID   string     `json:"entry_id"`
	EntryName string     `json:"entry_name"`
	UserID    string     `json:"user_id"`
	Username  string     `json:"username"`
	Protocol  string     `json:"protocol"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Status    string     `json:"status"`
	Recorded  bool       `json:"recorded"`
	InScope   bool       `json:"in_scope"`
}

type engagementReportRequest struct {
	ID           string     `json:"id"`
	RequesterID  string     `json:"requester_id"`
	ResourceType string     `json:"resource_type"`
	ResourceID   string     `json:"resource_id"`
	ResourceName string     `json:"resource_name"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

type engagementReportRemote struct {
	ID          string     `json:"id"`
	AgentID     string     `json:"agent_id"`
	AdminUserID string     `json:"admin_user_id"`
	Status      string     `json:"status"`
	StartedAt   time.Time  `json:"started_at"`
	EndedAt     *time.Time `json:"ended_at,omitempty"`
	Recorded    bool       `json:"recorded"`
	Consent     string     `json:"consent_status"`
}

type engagementReportAction struct {
	Action string `json:"action"`
	Count  int    `json:"count"`
}

// handleEngagementReport — GET /engagements/:id/report. The window is the
// engagement's start until it was closed, it ended, or now. The members are
// those it names, or every external user of its vendor when it names none.
// PAM sessions and access requests are the members' in the window (a session
// on one of the engagement's entries is in scope); remote-support sessions
// are those on the engagement's devices; audited actions are the members',
// counted by action.
func (s *Service) handleEngagementReport(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	e, err := s.getEngagement(ctx, s.db.Pool, org.ID, c.Param("id"))
	if err != nil {
		s.writeEngagementError(c, err, "read the engagement")
		return
	}
	now := time.Now()
	rep := &EngagementReport{Engagement: e, GeneratedAt: now, WindowStart: e.StartsAt, WindowEnd: e.EndsAt,
		Members: []engagementReportMember{}, PamSessions: []engagementReportPam{}, AccessRequests: []engagementReportRequest{},
		RemoteSupport: []engagementReportRemote{}, Actions: []engagementReportAction{}, GrantsHeld: map[string]int{}}
	if e.ClosedAt != nil && e.ClosedAt.Before(rep.WindowEnd) {
		rep.WindowEnd = *e.ClosedAt
	}
	if now.Before(rep.WindowEnd) {
		rep.WindowEnd = now
	}
	fail := func(err error) {
		s.logger.Error("engagement report failed", logsafe.String("engagement_id", e.ID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build the engagement report"})
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT u.id::text, u.username, COALESCE(u.email, ''), COALESCE(u.account_status, '')
		  FROM users u
		 WHERE u.org_id = $1 AND u.vendor_org_id = $2::uuid AND u.user_type = 'external'
		   AND (cardinality($3::uuid[]) = 0 OR u.id = ANY ($3::uuid[]))
		 ORDER BY u.username`, org.ID, e.VendorOrgID, e.MemberUserIDs)
	if err != nil {
		fail(err)
		return
	}
	members := []string{}
	for rows.Next() {
		var m engagementReportMember
		if err := rows.Scan(&m.UserID, &m.Username, &m.Email, &m.AccountStatus); err != nil {
			rows.Close()
			fail(err)
			return
		}
		rep.Members = append(rep.Members, m)
		members = append(members, m.UserID)
	}
	rows.Close()

	rows, err = s.db.Pool.Query(ctx, `
		SELECT ps.id::text, ps.entry_id::text, COALESCE(pe.name, ''), COALESCE(ps.user_id::text, ''), COALESCE(u.username, ''),
		       COALESCE(ps.protocol, ''), ps.started_at, ps.ended_at, ps.status,
		       COALESCE(ps.recording_path, '') <> '',
		       EXISTS (SELECT 1 FROM vendor_engagement_targets t
		                WHERE t.engagement_id = $2::uuid AND t.org_id = ps.org_id
		                  AND t.target_type = 'pam_entry' AND t.target_id = ps.entry_id::text)
		  FROM pam_entry_sessions ps
		  LEFT JOIN pam_entries pe ON pe.id = ps.entry_id
		  LEFT JOIN users u ON u.id = ps.user_id
		 WHERE ps.org_id = $1 AND ps.user_id::text = ANY ($3::text[])
		   AND ps.started_at >= $4 AND ps.started_at <= $5
		 ORDER BY ps.started_at`, org.ID, e.ID, members, rep.WindowStart, rep.WindowEnd)
	if err != nil {
		fail(err)
		return
	}
	for rows.Next() {
		var p engagementReportPam
		if err := rows.Scan(&p.ID, &p.EntryID, &p.EntryName, &p.UserID, &p.Username, &p.Protocol,
			&p.StartedAt, &p.EndedAt, &p.Status, &p.Recorded, &p.InScope); err != nil {
			rows.Close()
			fail(err)
			return
		}
		rep.PamSessions = append(rep.PamSessions, p)
	}
	rows.Close()

	rows, err = s.db.Pool.Query(ctx, `
		SELECT id::text, requester_id::text, resource_type, resource_id::text, COALESCE(resource_name, ''), status, created_at, expires_at
		  FROM access_requests
		 WHERE org_id = $1 AND requester_id::text = ANY ($2::text[]) AND created_at >= $3 AND created_at <= $4
		 ORDER BY created_at`, org.ID, members, rep.WindowStart, rep.WindowEnd)
	if err != nil {
		fail(err)
		return
	}
	for rows.Next() {
		var r engagementReportRequest
		if err := rows.Scan(&r.ID, &r.RequesterID, &r.ResourceType, &r.ResourceID, &r.ResourceName, &r.Status, &r.CreatedAt, &r.ExpiresAt); err != nil {
			rows.Close()
			fail(err)
			return
		}
		rep.AccessRequests = append(rep.AccessRequests, r)
	}
	rows.Close()

	rows, err = s.db.Pool.Query(ctx, `
		SELECT rs.id::text, rs.agent_id, COALESCE(rs.admin_user_id::text, ''), rs.status, rs.started_at, rs.ended_at,
		       rs.recording_enabled, rs.consent_status
		  FROM remote_support_sessions rs
		 WHERE rs.org_id = $1 AND rs.started_at >= $3 AND rs.started_at <= $4
		   AND rs.agent_id IN (SELECT t.target_id FROM vendor_engagement_targets t
		                        WHERE t.engagement_id = $2::uuid AND t.org_id = $1 AND t.target_type = 'device')
		 ORDER BY rs.started_at`, org.ID, e.ID, rep.WindowStart, rep.WindowEnd)
	if err != nil {
		fail(err)
		return
	}
	for rows.Next() {
		var r engagementReportRemote
		if err := rows.Scan(&r.ID, &r.AgentID, &r.AdminUserID, &r.Status, &r.StartedAt, &r.EndedAt, &r.Recorded, &r.Consent); err != nil {
			rows.Close()
			fail(err)
			return
		}
		rep.RemoteSupport = append(rep.RemoteSupport, r)
	}
	rows.Close()

	rows, err = s.db.Pool.Query(ctx, `
		SELECT action, count(*)::int FROM audit_events
		 WHERE org_id = $1 AND actor_id = ANY ($2::text[]) AND created_at >= $3 AND created_at <= $4
		 GROUP BY action ORDER BY 2 DESC, 1 LIMIT 100`, org.ID, members, rep.WindowStart, rep.WindowEnd)
	if err != nil {
		fail(err)
		return
	}
	for rows.Next() {
		var a engagementReportAction
		if err := rows.Scan(&a.Action, &a.Count); err != nil {
			rows.Close()
			fail(err)
			return
		}
		rep.Actions = append(rep.Actions, a)
	}
	rows.Close()

	var pam, apps int
	if err := s.db.Pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM pam_entry_grants WHERE engagement_id = $1::uuid AND org_id = $2
		          AND (expires_at IS NULL OR expires_at > NOW()))::int,
		       (SELECT count(*) FROM vendor_engagement_app_grants WHERE engagement_id = $1::uuid AND org_id = $2)::int`,
		e.ID, org.ID).Scan(&pam, &apps); err != nil {
		fail(err)
		return
	}
	rep.GrantsHeld["pam_entry"], rep.GrantsHeld["application"] = pam, apps
	c.JSON(http.StatusOK, rep)
}
