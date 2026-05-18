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

	placedBy := getUserID(c)
	var placedByArg interface{}
	if placedBy != "" {
		placedByArg = placedBy
	}

	var id string
	err := h.db.Pool.QueryRow(c.Request.Context(), `
        INSERT INTO recording_legal_holds (session_id, reason, placed_by)
        VALUES ($1::uuid, $2, NULLIF($3,'')::uuid)
        RETURNING id::text
    `, sessionID, req.Reason, placedByArg).Scan(&id)
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
    `, sessionID, releasedByArg, req.Reason)
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
	rows, err := h.db.Pool.Query(c.Request.Context(), `
        SELECT id::text, session_id::text, reason, placed_at,
               COALESCE(placed_by::text, ''), released_at,
               COALESCE(released_by::text, ''), COALESCE(released_reason, '')
          FROM recording_legal_holds
         WHERE session_id = $1::uuid
         ORDER BY placed_at DESC
    `, sessionID)
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

// holdLookup runs from the sweeper to decide whether a session is
// currently under legal hold. Pulled out so the sweeper's main query
// can stay readable. Returns true when at least one unreleased hold
// exists for the session.
func (h *RemoteSupportHandler) hasActiveLegalHold(ctx context.Context, sessionID string) (bool, error) {
	if h.db == nil || h.db.Pool == nil {
		return false, nil
	}
	var count int
	err := h.db.Pool.QueryRow(ctx, `
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
