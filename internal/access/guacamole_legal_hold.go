package access

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// guacSessionVisible reports whether the guacamole_sessions row is visible under the
// caller's org context (RLS on guacamole_sessions enforces the scope).
func (s *Service) guacSessionVisible(ctx context.Context, sessionID string) (bool, error) {
	var ok bool
	err := s.db.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM guacamole_sessions WHERE id=$1::uuid)`, sessionID).Scan(&ok)
	return ok, err
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
	vis, err := s.guacSessionVisible(ctx, sessionID)
	if err != nil {
		s.logger.Error("place guac legal hold: session lookup", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
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
        INSERT INTO guacamole_recording_legal_holds (session_id, reason, placed_by)
        VALUES ($1::uuid, $2, NULLIF($3,'')::uuid)
        RETURNING id::text
    `, sessionID, req.Reason, placedByArg).Scan(&id)
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
	if vis, err := s.guacSessionVisible(ctx, sessionID); err != nil || !vis {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	releasedBy := getUserID(c)
	var releasedByArg interface{}
	if releasedBy != "" {
		releasedByArg = releasedBy
	}
	tag, err := s.db.Pool.Exec(ctx, `
        UPDATE guacamole_recording_legal_holds
           SET released_at=NOW(), released_by=NULLIF($2,'')::uuid, released_reason=NULLIF($3,'')
         WHERE session_id=$1::uuid AND released_at IS NULL
    `, sessionID, releasedByArg, req.Reason)
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
	if vis, err := s.guacSessionVisible(ctx, sessionID); err != nil || !vis {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	rows, err := s.db.Pool.Query(ctx, `
        SELECT id::text, reason, placed_at, COALESCE(placed_by::text,''),
               released_at, COALESCE(released_by::text,''), COALESCE(released_reason,'')
          FROM guacamole_recording_legal_holds
         WHERE session_id=$1::uuid ORDER BY placed_at DESC
    `, sessionID)
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
