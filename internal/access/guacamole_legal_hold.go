package access

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// guacSessionOrg resolves the organization of the guacamole_sessions row a
// legal-hold request names, or reports not-visible.
//
// Until v149 this was guacSessionVisible, and it carried no tenant term at all:
// `SELECT EXISTS(SELECT 1 FROM guacamole_sessions WHERE id=$1)`, under a comment
// sourcing the scope from "RLS on guacamole_sessions". That is true on a
// correctly configured connection and false on any connection with BYPASSRLS —
// which is what every test pool in this repo is, and what an operator gets by
// pointing the app at a superuser DSN. A control whose only defence is a
// database setting has no defence in the code, so the organization is in the
// query now and the belt is the second layer rather than the only one.
func (s *Service) guacSessionOrg(ctx context.Context, sessionID string) (string, bool, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return "", false, err
	}
	var found string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT org_id::text FROM guacamole_sessions WHERE id=$1::uuid AND org_id=$2`,
		sessionID, org.ID).Scan(&found)
	if err != nil {
		return "", false, nil
	}
	return found, true, nil
}

// POST /api/v1/access/guacamole/sessions/:id/legal-hold — place a hold (409 if one is active).
func (s *Service) handlePlaceGuacLegalHold(c *gin.Context) {
	sessionID := c.Param("id")
	var req struct {
		Reason string `json:"reason" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if s.db == nil || s.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	ctx := c.Request.Context()
	orgID, vis, err := s.guacSessionOrg(ctx, sessionID)
	if err != nil {
		s.logger.Error("place guac legal hold: session lookup", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
		return
	}
	if !vis {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	placedBy := getUserID(c)
	var placedByArg interface{}
	if placedBy != "" {
		placedByArg = placedBy
	}
	var id string
	err = s.db.Pool.QueryRow(ctx, `
        INSERT INTO guacamole_recording_legal_holds (session_id, reason, placed_by, org_id)
        VALUES ($1::uuid, $2, NULLIF($3,'')::uuid, $4)
        RETURNING id::text
    `, sessionID, req.Reason, placedByArg, orgID).Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "an active legal hold already exists for this session"})
			return
		}
		s.logger.Error("place guac legal hold: insert", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to place hold"})
		return
	}
	s.auditLog(c, "guacamole.legal_hold_placed", map[string]interface{}{"session_id": sessionID, "reason": req.Reason})
	c.JSON(http.StatusCreated, gin.H{"id": id, "session_id": sessionID, "reason": req.Reason})
}

// DELETE /api/v1/access/guacamole/sessions/:id/legal-hold — release the active hold.
func (s *Service) handleReleaseGuacLegalHold(c *gin.Context) {
	sessionID := c.Param("id")
	var req struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&req)
	if s.db == nil || s.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	ctx := c.Request.Context()
	orgID, vis, err := s.guacSessionOrg(ctx, sessionID)
	if err != nil || !vis {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	releasedBy := getUserID(c)
	var releasedByArg interface{}
	if releasedBy != "" {
		releasedByArg = releasedBy
	}
	// Releasing a hold is what lets sweepExpiredGuacRecordings purge the
	// recording, so the tenant belongs in this predicate, not only in the
	// visibility check above.
	tag, err := s.db.Pool.Exec(ctx, `
        UPDATE guacamole_recording_legal_holds
           SET released_at=NOW(), released_by=NULLIF($2,'')::uuid, released_reason=NULLIF($3,'')
         WHERE session_id=$1::uuid AND released_at IS NULL AND org_id=$4
    `, sessionID, releasedByArg, req.Reason, orgID)
	if err != nil {
		s.logger.Error("release guac legal hold: update", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to release hold"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no active legal hold for this session"})
		return
	}
	s.auditLog(c, "guacamole.legal_hold_released", map[string]interface{}{"session_id": sessionID, "reason": req.Reason})
	c.JSON(http.StatusOK, gin.H{"status": "released", "session_id": sessionID})
}

// GET /api/v1/access/guacamole/sessions/:id/legal-holds — list active + historical holds.
func (s *Service) handleListGuacLegalHolds(c *gin.Context) {
	sessionID := c.Param("id")
	if s.db == nil || s.db.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"legal_holds": []any{}})
		return
	}
	ctx := c.Request.Context()
	orgID, vis, err := s.guacSessionOrg(ctx, sessionID)
	if err != nil || !vis {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	rows, err := s.db.Pool.Query(ctx, `
        SELECT id::text, reason, placed_at, COALESCE(placed_by::text,''),
               released_at, COALESCE(released_by::text,''), COALESCE(released_reason,'')
          FROM guacamole_recording_legal_holds
         WHERE session_id=$1::uuid AND org_id=$2 ORDER BY placed_at DESC
    `, sessionID, orgID)
	if err != nil {
		s.logger.Error("list guac legal holds", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id, reason, placedBy, releasedBy, releasedReason string
		var placedAt time.Time
		var releasedAt *time.Time
		if err := rows.Scan(&id, &reason, &placedAt, &placedBy, &releasedAt, &releasedBy, &releasedReason); err != nil {
			continue
		}
		out = append(out, gin.H{"id": id, "reason": reason, "placed_at": placedAt, "placed_by": placedBy,
			"released_at": releasedAt, "released_by": releasedBy, "released_reason": releasedReason})
	}
	c.JSON(http.StatusOK, gin.H{"legal_holds": out})
}
