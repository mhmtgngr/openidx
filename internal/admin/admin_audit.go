package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AdminAuditEntry represents a single admin action audit log entry
type AdminAuditEntry struct {
	ID          string                 `json:"id"`
	ActorID     string                 `json:"actor_id"`
	ActorEmail  string                 `json:"actor_email"`
	Action      string                 `json:"action"`
	TargetType  string                 `json:"target_type"`
	TargetID    string                 `json:"target_id,omitempty"`
	TargetName  string                 `json:"target_name,omitempty"`
	BeforeState map[string]interface{} `json:"before_state,omitempty"`
	AfterState  map[string]interface{} `json:"after_state,omitempty"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

// RecordAdminAction inserts an admin audit log entry into the admin_audit_log table
func (s *Service) RecordAdminAction(
	ctx context.Context,
	actorID, actorEmail, action, targetType, targetID, targetName,
	ipAddress, userAgent, requestID string,
	before, after interface{},
) error {
	id := uuid.New().String()

	var beforeJSON, afterJSON []byte
	var err error

	if before != nil {
		beforeJSON, err = json.Marshal(before)
		if err != nil {
			s.logger.Warn("Failed to marshal before_state for admin audit",
				zap.Error(err),
				zap.String("action", action),
			)
			beforeJSON = nil
		}
	}

	if after != nil {
		afterJSON, err = json.Marshal(after)
		if err != nil {
			s.logger.Warn("Failed to marshal after_state for admin audit",
				zap.Error(err),
				zap.String("action", action),
			)
			afterJSON = nil
		}
	}

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO admin_audit_log (
			id, actor_id, actor_email, action, target_type, target_id, target_name,
			before_state, after_state, ip_address, user_agent, request_id, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`, id, actorID, actorEmail, action, targetType, targetID, targetName,
		beforeJSON, afterJSON, ipAddress, userAgent, requestID, time.Now())

	if err != nil {
		s.logger.Error("Failed to record admin audit action",
			zap.String("action", action),
			zap.String("actor_id", actorID),
			zap.String("target_type", targetType),
			zap.String("target_id", targetID),
			zap.Error(err),
		)
		return fmt.Errorf("failed to record admin audit action: %w", err)
	}

	s.logger.Info("Admin action recorded",
		zap.String("id", id),
		zap.String("action", action),
		zap.String("actor_id", actorID),
		zap.String("target_type", targetType),
		zap.String("target_id", targetID),
	)

	return nil
}

// handleGetAdminAuditLog returns paginated admin audit log entries with optional filters
func (s *Service) handleGetAdminAuditLog(c *gin.Context) {
	if !requireAdmin(c) { return }
	ctx := c.Request.Context()

	// Parse pagination
	limit := 20
	offset := 0
	if l := c.Query("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	if o := c.Query("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}
	if offset < 0 {
		offset = 0
	}

	// Build dynamic query with filters
	query := `SELECT id, actor_id, actor_email, action, target_type,
		COALESCE(target_id, ''), COALESCE(target_name, ''),
		before_state, after_state,
		COALESCE(ip_address, ''), COALESCE(user_agent, ''), COALESCE(request_id, ''),
		created_at
		FROM admin_audit_log WHERE 1=1`
	countQuery := `SELECT COUNT(*) FROM admin_audit_log WHERE 1=1`

	args := make([]interface{}, 0)
	argIndex := 1

	if actorID := c.Query("actor_id"); actorID != "" {
		query += fmt.Sprintf(" AND actor_id = $%d", argIndex)
		countQuery += fmt.Sprintf(" AND actor_id = $%d", argIndex)
		args = append(args, actorID)
		argIndex++
	}

	if action := c.Query("action"); action != "" {
		query += fmt.Sprintf(" AND action = $%d", argIndex)
		countQuery += fmt.Sprintf(" AND action = $%d", argIndex)
		args = append(args, action)
		argIndex++
	}

	if targetType := c.Query("target_type"); targetType != "" {
		query += fmt.Sprintf(" AND target_type = $%d", argIndex)
		countQuery += fmt.Sprintf(" AND target_type = $%d", argIndex)
		args = append(args, targetType)
		argIndex++
	}

	if startDate := c.Query("start_date"); startDate != "" {
		query += fmt.Sprintf(" AND created_at >= $%d", argIndex)
		countQuery += fmt.Sprintf(" AND created_at >= $%d", argIndex)
		args = append(args, startDate)
		argIndex++
	}

	if endDate := c.Query("end_date"); endDate != "" {
		query += fmt.Sprintf(" AND created_at <= $%d", argIndex)
		countQuery += fmt.Sprintf(" AND created_at <= $%d", argIndex)
		args = append(args, endDate)
		argIndex++
	}

	// Get total count
	var total int
	err := s.db.Pool.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		s.logger.Error("Failed to count admin audit entries", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query admin audit log"})
		return
	}

	// Add ordering and pagination
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, limit, offset)

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		s.logger.Error("Failed to query admin audit log", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query admin audit log"})
		return
	}
	defer rows.Close()

	entries := make([]AdminAuditEntry, 0)
	for rows.Next() {
		var entry AdminAuditEntry
		var beforeJSON, afterJSON []byte

		err := rows.Scan(
			&entry.ID, &entry.ActorID, &entry.ActorEmail, &entry.Action, &entry.TargetType,
			&entry.TargetID, &entry.TargetName,
			&beforeJSON, &afterJSON,
			&entry.IPAddress, &entry.UserAgent, &entry.RequestID,
			&entry.CreatedAt,
		)
		if err != nil {
			s.logger.Error("Failed to scan admin audit entry", zap.Error(err))
			continue
		}

		if beforeJSON != nil {
			json.Unmarshal(beforeJSON, &entry.BeforeState)
		}
		if afterJSON != nil {
			json.Unmarshal(afterJSON, &entry.AfterState)
		}

		entries = append(entries, entry)
	}

	c.JSON(http.StatusOK, gin.H{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// handleGetAdminAuditEntry returns a single admin audit log entry by ID
func (s *Service) handleGetAdminAuditEntry(c *gin.Context) {
	if !requireAdmin(c) { return }
	id := c.Param("id")
	ctx := c.Request.Context()

	var entry AdminAuditEntry
	var beforeJSON, afterJSON []byte

	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, actor_id, actor_email, action, target_type,
			COALESCE(target_id, ''), COALESCE(target_name, ''),
			before_state, after_state,
			COALESCE(ip_address, ''), COALESCE(user_agent, ''), COALESCE(request_id, ''),
			created_at
		FROM admin_audit_log WHERE id = $1
	`, id).Scan(
		&entry.ID, &entry.ActorID, &entry.ActorEmail, &entry.Action, &entry.TargetType,
		&entry.TargetID, &entry.TargetName,
		&beforeJSON, &afterJSON,
		&entry.IPAddress, &entry.UserAgent, &entry.RequestID,
		&entry.CreatedAt,
	)

	if err != nil {
		s.logger.Debug("Admin audit entry not found", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "audit entry not found"})
		return
	}

	if beforeJSON != nil {
		json.Unmarshal(beforeJSON, &entry.BeforeState)
	}
	if afterJSON != nil {
		json.Unmarshal(afterJSON, &entry.AfterState)
	}

	c.JSON(http.StatusOK, entry)
}

// handleGetSettingsHistory returns admin audit entries for settings changes
func (s *Service) handleGetSettingsHistory(c *gin.Context) {
	if !requireAdmin(c) { return }
	ctx := c.Request.Context()

	limit := 20
	offset := 0
	if l := c.Query("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	if o := c.Query("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}
	if offset < 0 {
		offset = 0
	}

	// Count total settings changes
	var total int
	err := s.db.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM admin_audit_log WHERE target_type = 'settings'").Scan(&total)
	if err != nil {
		s.logger.Error("Failed to count settings history", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query settings history"})
		return
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, actor_id, actor_email, action, target_type,
			COALESCE(target_id, ''), COALESCE(target_name, ''),
			before_state, after_state,
			COALESCE(ip_address, ''), COALESCE(user_agent, ''), COALESCE(request_id, ''),
			created_at
		FROM admin_audit_log
		WHERE target_type = 'settings'
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		s.logger.Error("Failed to query settings history", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query settings history"})
		return
	}
	defer rows.Close()

	entries := make([]AdminAuditEntry, 0)
	for rows.Next() {
		var entry AdminAuditEntry
		var beforeJSON, afterJSON []byte

		err := rows.Scan(
			&entry.ID, &entry.ActorID, &entry.ActorEmail, &entry.Action, &entry.TargetType,
			&entry.TargetID, &entry.TargetName,
			&beforeJSON, &afterJSON,
			&entry.IPAddress, &entry.UserAgent, &entry.RequestID,
			&entry.CreatedAt,
		)
		if err != nil {
			s.logger.Error("Failed to scan settings history entry", zap.Error(err))
			continue
		}

		if beforeJSON != nil {
			json.Unmarshal(beforeJSON, &entry.BeforeState)
		}
		if afterJSON != nil {
			json.Unmarshal(afterJSON, &entry.AfterState)
		}

		entries = append(entries, entry)
	}

	c.JSON(http.StatusOK, gin.H{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}
