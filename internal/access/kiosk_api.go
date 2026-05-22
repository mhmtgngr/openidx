// Package access — kiosk policy CRUD, assignment, and the resolution helper
// that /agent/config calls to embed the effective policy in the agent's
// configuration response.
package access

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// KioskAPIHandler exposes the admin-side kiosk policy CRUD + assignment
// endpoints AND the package-internal resolveEffectiveKioskPolicy helper that
// the agent config delivery uses.
type KioskAPIHandler struct {
	logger *zap.Logger
	db     *database.PostgresDB
	// audit reuses the agent handler's audit functions so kiosk events land
	// in unified_audit_events alongside the rest of the device lifecycle.
	auditAgent *AgentAPIHandler
}

// NewKioskAPIHandler constructs a KioskAPIHandler. auditAgent may be nil in
// tests; when present, kiosk events ride the agent audit pipeline.
func NewKioskAPIHandler(logger *zap.Logger, db *database.PostgresDB, auditAgent *AgentAPIHandler) *KioskAPIHandler {
	return &KioskAPIHandler{logger: logger, db: db, auditAgent: auditAgent}
}

// RegisterKioskAdminRoutes mounts the admin endpoints under the given group.
// MUST be mounted behind middleware.Auth — kiosk policy edits are admin ops.
func (h *KioskAPIHandler) RegisterKioskAdminRoutes(r *gin.RouterGroup) {
	r.GET("/kiosk/policies", h.HandleListPolicies)
	r.POST("/kiosk/policies", h.HandleCreatePolicy)
	r.GET("/kiosk/policies/:id", h.HandleGetPolicy)
	r.PUT("/kiosk/policies/:id", h.HandleUpdatePolicy)
	r.DELETE("/kiosk/policies/:id", h.HandleDeletePolicy)

	r.GET("/kiosk/policies/:id/assignments", h.HandleListAssignments)
	r.POST("/kiosk/policies/:id/assignments", h.HandleAssignPolicy)
	r.DELETE("/kiosk/assignments/:assignment_id", h.HandleUnassignPolicy)
}

// kioskPolicyRow is the wire shape returned to admins and embedded in
// /agent/config. allowed_packages, lock_task_features and branding stay
// JSON-passthrough so the agent doesn't need to track schema drift on every
// field; the Android side defines its own ignoring-unknown-keys parser.
type kioskPolicyRow struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	Mode             string          `json:"mode"`
	AllowedPackages  json.RawMessage `json:"allowed_packages"`
	PrimaryActivity  string          `json:"primary_activity,omitempty"`
	LockTaskFeatures json.RawMessage `json:"lock_task_features"`
	Branding         json.RawMessage `json:"branding"`
	HasExitPIN       bool            `json:"has_exit_pin"`
	Enabled          bool            `json:"enabled"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

type kioskPolicyAssignmentRow struct {
	ID         string    `json:"id"`
	PolicyID   string    `json:"policy_id"`
	TargetKind string    `json:"target_kind"`
	TargetID   string    `json:"target_id"`
	Priority   int       `json:"priority"`
	CreatedAt  time.Time `json:"created_at"`
}

// kioskPolicyCreate is the body accepted by HandleCreatePolicy /
// HandleUpdatePolicy. allowed_packages / lock_task_features / branding accept
// arrays / objects directly so admins don't need to pre-stringify them.
type kioskPolicyCreate struct {
	Name             string          `json:"name" binding:"required"`
	Description      string          `json:"description"`
	Mode             string          `json:"mode"`
	AllowedPackages  json.RawMessage `json:"allowed_packages"`
	PrimaryActivity  string          `json:"primary_activity"`
	LockTaskFeatures json.RawMessage `json:"lock_task_features"`
	Branding         json.RawMessage `json:"branding"`
	ExitPIN          string          `json:"exit_pin"`
	Enabled          *bool           `json:"enabled"`
}

// HandleCreatePolicy persists a new kiosk policy. mode is validated against
// the small enum the agent recognises; everything else passes through.
func (h *KioskAPIHandler) HandleCreatePolicy(c *gin.Context) {
	var req kioskPolicyCreate
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateKioskMode(req.Mode); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	pinHash := ""
	if req.ExitPIN != "" {
		pinHash = sha256Hex(req.ExitPIN)
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	id := uuid.New().String()
	createdBy := getUserID(c)

	_, err := h.db.Pool.Exec(c.Request.Context(), `
        INSERT INTO kiosk_policies
            (id, name, description, mode, allowed_packages, primary_activity,
             lock_task_features, branding, exit_pin_hash, enabled, created_by)
        VALUES ($1,$2,$3,$4, COALESCE($5,'[]'::jsonb), NULLIF($6,''),
                COALESCE($7,'[]'::jsonb), COALESCE($8,'{}'::jsonb),
                NULLIF($9,''), $10, NULLIF($11,'')::uuid)
    `, id, req.Name, req.Description, normalizeKioskMode(req.Mode),
		string(req.AllowedPackages), req.PrimaryActivity,
		string(req.LockTaskFeatures), string(req.Branding),
		pinHash, enabled, createdBy)
	if err != nil {
		h.logger.Error("HandleCreatePolicy: insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create policy"})
		return
	}

	h.auditKiosk(c.Request.Context(), "kiosk.policy_created", id, "success", "name="+req.Name)
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// HandleListPolicies returns every kiosk policy (admin view, no filtering).
func (h *KioskAPIHandler) HandleListPolicies(c *gin.Context) {
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusOK, []kioskPolicyRow{})
		return
	}
	rows, err := h.db.Pool.Query(c.Request.Context(), kioskPolicySelect+` ORDER BY created_at DESC`)
	if err != nil {
		h.logger.Error("HandleListPolicies: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list policies"})
		return
	}
	defer rows.Close()

	out := []kioskPolicyRow{}
	for rows.Next() {
		rec, scanErr := scanKioskPolicyRow(rows)
		if scanErr != nil {
			h.logger.Warn("HandleListPolicies: scan failed", zap.Error(scanErr))
			continue
		}
		out = append(out, rec)
	}
	c.JSON(http.StatusOK, out)
}

// HandleGetPolicy returns a single policy by ID.
func (h *KioskAPIHandler) HandleGetPolicy(c *gin.Context) {
	id := c.Param("id")
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	row := h.db.Pool.QueryRow(c.Request.Context(), kioskPolicySelect+` WHERE id = $1`, id)
	rec, err := scanKioskPolicyRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rec)
}

// HandleUpdatePolicy replaces an existing policy in-place. exit_pin is rotated
// when supplied; an empty exit_pin keeps the previous hash so admins can edit
// other fields without re-entering the PIN.
func (h *KioskAPIHandler) HandleUpdatePolicy(c *gin.Context) {
	id := c.Param("id")
	var req kioskPolicyCreate
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Mode != "" {
		if err := validateKioskMode(req.Mode); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	pinHash := ""
	if req.ExitPIN != "" {
		pinHash = sha256Hex(req.ExitPIN)
	}

	tag, err := h.db.Pool.Exec(c.Request.Context(), `
        UPDATE kiosk_policies SET
            name = COALESCE(NULLIF($2,''), name),
            description = COALESCE($3, description),
            mode = COALESCE(NULLIF($4,''), mode),
            allowed_packages = COALESCE($5::jsonb, allowed_packages),
            primary_activity = COALESCE(NULLIF($6,''), primary_activity),
            lock_task_features = COALESCE($7::jsonb, lock_task_features),
            branding = COALESCE($8::jsonb, branding),
            exit_pin_hash = COALESCE(NULLIF($9,''), exit_pin_hash),
            enabled = COALESCE($10, enabled),
            updated_at = NOW()
        WHERE id = $1
    `, id, req.Name, req.Description, normalizeKioskMode(req.Mode),
		nilIfEmpty(req.AllowedPackages), req.PrimaryActivity,
		nilIfEmpty(req.LockTaskFeatures), nilIfEmpty(req.Branding),
		pinHash, req.Enabled)
	if err != nil {
		h.logger.Error("HandleUpdatePolicy: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update policy"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}

	h.auditKiosk(c.Request.Context(), "kiosk.policy_changed", id, "success", "")
	c.JSON(http.StatusOK, gin.H{"status": "updated", "id": id})
}

// HandleDeletePolicy removes a policy. ON DELETE CASCADE in the migration
// drops any assignments pointing at it.
func (h *KioskAPIHandler) HandleDeletePolicy(c *gin.Context) {
	id := c.Param("id")
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	_, err := h.db.Pool.Exec(c.Request.Context(), `DELETE FROM kiosk_policies WHERE id = $1`, id)
	if err != nil {
		h.logger.Error("HandleDeletePolicy: delete failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete policy"})
		return
	}
	h.auditKiosk(c.Request.Context(), "kiosk.policy_deleted", id, "success", "")
	c.JSON(http.StatusOK, gin.H{"status": "deleted", "id": id})
}

// kioskAssignmentCreate is the body accepted by HandleAssignPolicy.
type kioskAssignmentCreate struct {
	TargetKind string `json:"target_kind" binding:"required"`
	TargetID   string `json:"target_id"   binding:"required"`
	Priority   *int   `json:"priority"`
}

// HandleAssignPolicy creates an assignment from policy → target.
func (h *KioskAPIHandler) HandleAssignPolicy(c *gin.Context) {
	policyID := c.Param("id")
	var req kioskAssignmentCreate
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !validKioskTargetKind(req.TargetKind) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target_kind must be agent|group|tag"})
		return
	}
	priority := defaultKioskPriority(req.TargetKind)
	if req.Priority != nil {
		priority = *req.Priority
	}
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	id := uuid.New().String()
	createdBy := getUserID(c)
	_, err := h.db.Pool.Exec(c.Request.Context(), `
        INSERT INTO kiosk_policy_assignments
            (id, policy_id, target_kind, target_id, priority, created_by)
        VALUES ($1,$2,$3,$4,$5, NULLIF($6,'')::uuid)
        ON CONFLICT (policy_id, target_kind, target_id) DO UPDATE
            SET priority = EXCLUDED.priority
    `, id, policyID, req.TargetKind, req.TargetID, priority, createdBy)
	if err != nil {
		h.logger.Error("HandleAssignPolicy: insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to assign policy"})
		return
	}
	h.auditKiosk(c.Request.Context(), "kiosk.policy_assigned", policyID, "success",
		req.TargetKind+":"+req.TargetID)
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// HandleListAssignments returns the assignments for one policy.
func (h *KioskAPIHandler) HandleListAssignments(c *gin.Context) {
	policyID := c.Param("id")
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusOK, []kioskPolicyAssignmentRow{})
		return
	}
	rows, err := h.db.Pool.Query(c.Request.Context(), `
        SELECT id, policy_id, target_kind, target_id, priority, created_at
          FROM kiosk_policy_assignments
         WHERE policy_id = $1
         ORDER BY priority DESC, created_at DESC
    `, policyID)
	if err != nil {
		h.logger.Error("HandleListAssignments: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list assignments"})
		return
	}
	defer rows.Close()
	out := []kioskPolicyAssignmentRow{}
	for rows.Next() {
		var rec kioskPolicyAssignmentRow
		if err := rows.Scan(&rec.ID, &rec.PolicyID, &rec.TargetKind, &rec.TargetID, &rec.Priority, &rec.CreatedAt); err != nil {
			h.logger.Warn("HandleListAssignments: scan failed", zap.Error(err))
			continue
		}
		out = append(out, rec)
	}
	c.JSON(http.StatusOK, out)
}

// HandleUnassignPolicy removes a single assignment by its row id.
func (h *KioskAPIHandler) HandleUnassignPolicy(c *gin.Context) {
	assignmentID := c.Param("assignment_id")
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	var policyID string
	_ = h.db.Pool.QueryRow(c.Request.Context(),
		`SELECT policy_id FROM kiosk_policy_assignments WHERE id = $1`,
		assignmentID).Scan(&policyID)
	_, err := h.db.Pool.Exec(c.Request.Context(),
		`DELETE FROM kiosk_policy_assignments WHERE id = $1`, assignmentID)
	if err != nil {
		h.logger.Error("HandleUnassignPolicy: delete failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to unassign"})
		return
	}
	h.auditKiosk(c.Request.Context(), "kiosk.policy_unassigned", policyID, "success", assignmentID)
	c.JSON(http.StatusOK, gin.H{"status": "deleted", "id": assignmentID})
}

// resolveEffectiveKioskPolicy looks up the highest-priority assignment that
// targets the given agent (directly or indirectly via tag) and returns the
// matching policy. Returns nil, nil when no policy applies — callers should
// then omit the kiosk_policy block from /agent/config.
//
// Lookup order (priority DESC, then created_at DESC):
//  1. assignment.target_kind='agent'  AND target_id = agentID
//  2. assignment.target_kind='tag'    AND target_id IN (agent's metadata.tags)
//
// Group support is reserved for future identity-service integration; we
// query for it so the schema is exercised, but no rows ever match today.
func resolveEffectiveKioskPolicy(
	ctx context.Context,
	db *database.PostgresDB,
	agentID string,
) (*kioskPolicyRow, error) {
	if db == nil || db.Pool == nil || agentID == "" {
		return nil, nil
	}
	// Walk both direct + tag-based assignments in one query. The tag join
	// uses the agent's metadata->'tags' JSONB array (empty when absent so
	// we still return the agent-direct match cleanly).
	const query = `
SELECT kp.id, kp.name, COALESCE(kp.description, ''), kp.mode,
       kp.allowed_packages, COALESCE(kp.primary_activity, ''),
       kp.lock_task_features, kp.branding,
       (kp.exit_pin_hash IS NOT NULL),
       kp.enabled, kp.created_at, kp.updated_at
  FROM kiosk_policies kp
  JOIN kiosk_policy_assignments kpa ON kpa.policy_id = kp.id
  LEFT JOIN enrolled_agents ea ON ea.agent_id = $1
 WHERE kp.enabled = TRUE
   AND (
     (kpa.target_kind = 'agent' AND kpa.target_id = $1)
     OR (kpa.target_kind = 'tag'
         AND COALESCE(ea.metadata->'tags', '[]'::jsonb) ? kpa.target_id)
   )
 ORDER BY kpa.priority DESC, kpa.created_at DESC
 LIMIT 1`
	row := db.Pool.QueryRow(ctx, query, agentID)
	rec, err := scanKioskPolicyRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &rec, nil
}

func (h *KioskAPIHandler) auditKiosk(ctx context.Context, action, policyID, outcome, detail string) {
	if h.auditAgent != nil {
		h.auditAgent.logAuditEvent(action, policyID, outcome, detail)
		h.auditAgent.logAuditEventToDB(ctx, action, policyID, outcome, detail)
	}
}

// --- helpers ---

// kioskPolicySelect is the SELECT clause shared by single-row and list
// queries. Kept as a string so column order matches scanKioskPolicyRow.
const kioskPolicySelect = `
SELECT id, name, COALESCE(description, ''), mode,
       allowed_packages, COALESCE(primary_activity, ''),
       lock_task_features, branding,
       (exit_pin_hash IS NOT NULL),
       enabled, created_at, updated_at
  FROM kiosk_policies`

// rowScanner abstracts pgx.Row and pgx.Rows so scanKioskPolicyRow works for
// both single-row and list queries.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanKioskPolicyRow(r rowScanner) (kioskPolicyRow, error) {
	var rec kioskPolicyRow
	var allowed, features, branding []byte
	err := r.Scan(
		&rec.ID, &rec.Name, &rec.Description, &rec.Mode,
		&allowed, &rec.PrimaryActivity,
		&features, &branding,
		&rec.HasExitPIN,
		&rec.Enabled, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return rec, err
	}
	rec.AllowedPackages = allowed
	rec.LockTaskFeatures = features
	rec.Branding = branding
	return rec, nil
}

func validateKioskMode(mode string) error {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "single_app", "multi_app", "off":
		return nil
	default:
		return errors.New("mode must be one of: single_app, multi_app, off")
	}
}

func normalizeKioskMode(mode string) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "" {
		return ""
	}
	return m
}

func validKioskTargetKind(k string) bool {
	switch k {
	case "agent", "group", "tag":
		return true
	default:
		return false
	}
}

// defaultKioskPriority encodes the natural precedence: agent > group > tag.
// Admins can still override by passing an explicit priority on assignment.
func defaultKioskPriority(kind string) int {
	switch kind {
	case "agent":
		return 300
	case "group":
		return 200
	case "tag":
		return 100
	}
	return 100
}

func getUserID(c *gin.Context) string {
	if v, ok := c.Get("user_id"); ok {
		if s, _ := v.(string); s != "" {
			return s
		}
	}
	return ""
}

// nilIfEmpty returns nil when the JSON payload is empty so the SQL
// COALESCE($N::jsonb, existing) pattern preserves the existing column value
// on update-without-supply.
func nilIfEmpty(b json.RawMessage) interface{} {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	return string(b)
}
