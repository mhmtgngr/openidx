// Package access — legal-hold workflow for remote-support recordings.
//
// A legal hold exempts a session's recording from the retention
// sweeper. Use case: compliance / litigation requires us to preserve a
// specific recording past its normal retention window, regardless of
// org policy or per-session override.
//
// Holds are append-only history rows; "release" stamps released_at
// instead of deleting, so the audit trail survives the eventual purge
// of the recording itself.
package access

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// legalHoldRow is the wire shape returned by the list endpoint. Includes
// both active and historical holds so admins can audit who placed what.
type legalHoldRow struct {
	ID             string     `json:"id"`
	SessionID      string     `json:"session_id"`
	Reason         string     `json:"reason"`
	PlacedAt       time.Time  `json:"placed_at"`
	PlacedBy       string     `json:"placed_by,omitempty"`
	ReleasedAt     *time.Time `json:"released_at,omitempty"`
	ReleasedBy     string     `json:"released_by,omitempty"`
	ReleasedReason string     `json:"released_reason,omitempty"`
}

// RegisterLegalHoldAdminRoutes mounts the legal-hold surface. MUST go
// behind middleware.Auth — these endpoints capture the caller's
// user_id for the audit trail.
func (h *RemoteSupportHandler) RegisterLegalHoldAdminRoutes(r *gin.RouterGroup) {
	r.POST("/remote-support/sessions/:id/legal-hold", h.HandlePlaceLegalHold)
	r.DELETE("/remote-support/sessions/:id/legal-hold", h.HandleReleaseLegalHold)
	r.GET("/remote-support/sessions/:id/legal-holds", h.HandleListLegalHolds)
}

type placeLegalHoldRequest struct {
	Reason string `json:"reason" binding:"required"`
}

// HandlePlaceLegalHold creates a new hold for the session. Returns 409
// if an active hold already exists — admins must release before
// placing a new one with a different reason.
func (h *RemoteSupportHandler) HandlePlaceLegalHold(c *gin.Context) {
	sessionID := c.Param("id")
	var req placeLegalHoldRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	// TENANCY (v149). Every handler in this file took a bare session id. The
	// Guacamole twin, doing the identical job, gates on session visibility
	// first; this one did not gate at all.
	orgID, ok := h.legalHoldSessionOrg(c, sessionID)
	if !ok {
		return
	}

	placedBy := getUserID(c)
	var placedByArg interface{}
	if placedBy != "" {
		placedByArg = placedBy
	}

	var id string
	err := h.db.Pool.QueryRow(c.Request.Context(), `
        INSERT INTO recording_legal_holds (session_id, reason, placed_by, org_id)
        VALUES ($1::uuid, $2, NULLIF($3,'')::uuid, $4)
        RETURNING id::text
    `, sessionID, req.Reason, placedByArg, orgID).Scan(&id)
	if err != nil {
		// Unique partial index → 23505 when an active hold already exists.
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "an active legal hold already exists for this session"})
			return
		}
		h.logger.Error("HandlePlaceLegalHold: insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to place hold"})
		return
	}

	h.audit(c.Request.Context(), "remote_support.legal_hold_placed", sessionID, "success", req.Reason)
	c.JSON(http.StatusCreated, gin.H{
		"id":         id,
		"session_id": sessionID,
		"reason":     req.Reason,
		"placed_at":  time.Now().UTC().Format(time.RFC3339),
		"placed_by":  placedBy,
	})
}

type releaseLegalHoldRequest struct {
	Reason string `json:"reason"`
}

// HandleReleaseLegalHold stamps released_at + released_by on the
// currently-active hold for the session. Returns 404 when no active
// hold exists.
func (h *RemoteSupportHandler) HandleReleaseLegalHold(c *gin.Context) {
	sessionID := c.Param("id")
	var req releaseLegalHoldRequest
	_ = c.ShouldBindJSON(&req)
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	// TENANCY (v149), and this is the one that destroys. Releasing a hold is
	// what lets sweepExpiredRecordings purge the recording it was protecting.
	// With a bare session id, an administrator of one tenant released another
	// tenant's litigation hold and the recording was gone at the next sweep.
	orgID, ok := h.legalHoldSessionOrg(c, sessionID)
	if !ok {
		return
	}

	releasedBy := getUserID(c)
	var releasedByArg interface{}
	if releasedBy != "" {
		releasedByArg = releasedBy
	}
	tag, err := h.db.Pool.Exec(c.Request.Context(), `
        UPDATE recording_legal_holds
           SET released_at     = NOW(),
               released_by     = NULLIF($2,'')::uuid,
               released_reason = NULLIF($3,'')
         WHERE session_id  = $1::uuid
           AND released_at IS NULL
           AND org_id      = $4
    `, sessionID, releasedByArg, req.Reason, orgID)
	if err != nil {
		h.logger.Error("HandleReleaseLegalHold: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to release hold"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no active legal hold for this session"})
		return
	}
	h.audit(c.Request.Context(), "remote_support.legal_hold_released", sessionID, "success", req.Reason)
	c.JSON(http.StatusOK, gin.H{"status": "released", "session_id": sessionID})
}

// HandleListLegalHolds returns every hold (active + historical) for a
// session, newest first.
func (h *RemoteSupportHandler) HandleListLegalHolds(c *gin.Context) {
	sessionID := c.Param("id")
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusOK, []legalHoldRow{})
		return
	}
	// TENANCY (v149): the reason is free text describing an investigation.
	orgID, ok := h.legalHoldSessionOrg(c, sessionID)
	if !ok {
		return
	}

	rows, err := h.db.Pool.Query(c.Request.Context(), `
        SELECT id::text, session_id::text, reason, placed_at,
               COALESCE(placed_by::text, ''), released_at,
               COALESCE(released_by::text, ''), COALESCE(released_reason, '')
          FROM recording_legal_holds
         WHERE session_id = $1::uuid
           AND org_id     = $2
         ORDER BY placed_at DESC
    `, sessionID, orgID)
	if err != nil {
		h.logger.Warn("HandleListLegalHolds: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()
	out := []legalHoldRow{}
	for rows.Next() {
		var r legalHoldRow
		if err := rows.Scan(
			&r.ID, &r.SessionID, &r.Reason, &r.PlacedAt,
			&r.PlacedBy, &r.ReleasedAt, &r.ReleasedBy, &r.ReleasedReason,
		); err != nil {
			h.logger.Warn("HandleListLegalHolds: scan failed", zap.Error(err))
			continue
		}
		out = append(out, r)
	}
	c.JSON(http.StatusOK, out)
}

// isUniqueViolation peeks at pgx errors for the unique-violation
// SQLSTATE so callers can return a friendlier 409 than the generic
// 500.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// legalHoldSessionOrg resolves the organization of the remote-support session a
// legal-hold request names, answering 404 and reporting false if the session is
// not in the caller's organization.
//
// Before v149 this file had no equivalent: place, release and list all took a
// bare session id. The Guacamole twin's guacSessionVisible is the same idea,
// and v149 gave that one an explicit tenant term too — a check that sources its
// scope from RLS alone stops being a check the moment the app connects with
// BYPASSRLS.
func (h *RemoteSupportHandler) legalHoldSessionOrg(c *gin.Context, sessionID string) (string, bool) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
		return "", false
	}
	var found string
	if err := h.db.Pool.QueryRow(c.Request.Context(),
		`SELECT org_id::text FROM remote_support_sessions WHERE id = $1::uuid AND org_id = $2`,
		sessionID, org.ID).Scan(&found); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return "", false
	}
	return found, true
}

// hasActiveLegalHold reports whether a session is currently under legal hold.
//
// THE DIRECTION MATTERS HERE and points at destruction: a false answer means
// "no hold", which means the recording may be purged. Under the v149 belt, a
// read on a connection with no app.org_id returns zero rows — indistinguishable
// from "not held" — so this runs BYPASSED, and over-reporting a hold (refusing
// to purge) is the only failure this function is allowed to have. It has no
// production caller today; the sweeps inline their own NOT EXISTS. It is left
// safe rather than deleted so that wiring it up later cannot quietly turn a
// retention sweep into an evidence shredder.
func (h *RemoteSupportHandler) hasActiveLegalHold(ctx context.Context, sessionID string) (bool, error) {
	if h.db == nil || h.db.Pool == nil {
		return false, nil
	}
	var count int
	//orgscope:ignore purge gate — must never read empty because of RLS; a false answer here permits deletion
	err := h.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx), `
        SELECT COUNT(*)
          FROM recording_legal_holds
         WHERE session_id = $1::uuid
           AND released_at IS NULL
    `, sessionID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
