package admin

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// revokedSessionMarkerTTL is how long a revoked-session marker lives in
// Redis. Same reasoning as the identity service's deprovision path: the
// marker must outlast the longest refresh-token lifetime so in-flight
// refresh tokens keep failing the oauth-service's revoked-session check
// until they expire on their own.
const revokedSessionMarkerTTL = 30 * 24 * time.Hour

// publishSessionRevocations writes the Redis markers that make a revocation
// take effect. The sessions table row is the durable record, but the
// oauth-service enforces against "revoked_session:<id>" in Redis — a
// revocation that skips the marker looks revoked in the console while the
// user's refresh token keeps minting access tokens. Returns one warning per
// marker that could not be published; callers surface them instead of
// reporting a clean revoke (nothing is reported severed unless the write
// succeeded).
func (s *Service) publishSessionRevocations(ctx context.Context, sessionIDs []string) []string {
	if len(sessionIDs) == 0 {
		return nil
	}
	if s.redis == nil || s.redis.Client == nil {
		s.logger.Warn("session revocation markers not published: redis unavailable",
			zap.Int("sessions", len(sessionIDs)))
		return []string{"revocation markers not published (redis unavailable): existing refresh tokens remain usable until they expire"}
	}
	var warnings []string
	for _, id := range sessionIDs {
		if err := s.redis.Client.Set(ctx, "revoked_session:"+id, "1", revokedSessionMarkerTTL).Err(); err != nil {
			s.logger.Warn("failed to publish revoked-session marker",
				zap.String("session_id", id), zap.Error(err))
			warnings = append(warnings, "revocation marker not published for session "+id+": its refresh tokens remain usable until they expire")
		}
	}
	return warnings
}

// AdminSession represents an active or historical session for admin viewing
type AdminSession struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	ClientID     string     `json:"client_id"`
	IPAddress    *string    `json:"ip_address,omitempty"`
	UserAgent    *string    `json:"user_agent,omitempty"`
	DeviceName   *string    `json:"device_name,omitempty"`
	Location     *string    `json:"location,omitempty"`
	DeviceType   *string    `json:"device_type,omitempty"`
	StartedAt    time.Time  `json:"started_at"`
	LastSeenAt   time.Time  `json:"last_seen_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	Revoked      bool       `json:"revoked"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokeReason *string    `json:"revoke_reason,omitempty"`
}

// handleListAllSessions lists all sessions with optional filtering
func (s *Service) handleListAllSessions(c *gin.Context) {
	userID := c.Query("user_id")
	activeOnly := c.DefaultQuery("active_only", "true") == "true"

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

	ctx := c.Request.Context()

	baseQuery := `SELECT s.id, s.user_id, u.username, u.email, s.client_id,
		s.ip_address, s.user_agent, s.device_name, s.location, s.device_type,
		s.started_at, s.last_seen_at, s.expires_at,
		COALESCE(s.revoked, false), s.revoked_at, s.revoke_reason
		FROM sessions s JOIN users u ON s.user_id = u.id`
	countQuery := `SELECT COUNT(*) FROM sessions s JOIN users u ON s.user_id = u.id`

	conditions := []string{}
	args := []interface{}{}
	argIdx := 1

	if activeOnly {
		conditions = append(conditions, "s.expires_at > NOW() AND (s.revoked IS NULL OR s.revoked = false)")
	}
	if userID != "" {
		conditions = append(conditions, fmt.Sprintf("s.user_id = $%d", argIdx))
		args = append(args, userID)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE "
		for i, cond := range conditions {
			if i > 0 {
				whereClause += " AND "
			}
			whereClause += cond
		}
	}

	var total int
	err := s.db.Pool.QueryRow(ctx, countQuery+whereClause, args...).Scan(&total)
	if err != nil {
		s.logger.Error("Failed to count sessions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count sessions"})
		return
	}

	finalQuery := baseQuery + whereClause + " ORDER BY s.last_seen_at DESC"
	paginatedArgs := append([]interface{}{}, args...)
	finalQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	paginatedArgs = append(paginatedArgs, limit, offset)

	rows, err := s.db.Pool.Query(ctx, finalQuery, paginatedArgs...)
	if err != nil {
		s.logger.Error("Failed to query sessions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query sessions"})
		return
	}
	defer rows.Close()

	sessions := []AdminSession{}
	for rows.Next() {
		var sess AdminSession
		if err := rows.Scan(
			&sess.ID, &sess.UserID, &sess.Username, &sess.Email, &sess.ClientID,
			&sess.IPAddress, &sess.UserAgent, &sess.DeviceName, &sess.Location, &sess.DeviceType,
			&sess.StartedAt, &sess.LastSeenAt, &sess.ExpiresAt,
			&sess.Revoked, &sess.RevokedAt, &sess.RevokeReason,
		); err != nil {
			s.logger.Error("Failed to scan session row", zap.Error(err))
			continue
		}
		sessions = append(sessions, sess)
	}

	c.Header("X-Total-Count", fmt.Sprintf("%d", total))
	c.JSON(http.StatusOK, gin.H{
		"sessions": sessions,
		"total":    total,
	})
}

// handleAdminRevokeSession revokes a single session by ID
func (s *Service) handleAdminRevokeSession(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	sessionID := c.Param("id")
	ctx := c.Request.Context()

	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)

	adminUserID, _ := c.Get("user_id")
	adminID, ok := adminUserID.(string)
	if !ok || adminID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	result, err := s.db.Pool.Exec(ctx, `
		UPDATE sessions SET revoked = true, revoked_at = NOW(), revoked_by = $1, revoke_reason = $2
		WHERE id = $3 AND org_id = $4
	`, adminID, body.Reason, sessionID, org.ID)
	if err != nil {
		s.logger.Error("Failed to revoke session", zap.Error(err), zap.String("session_id", sessionID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke session"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}

	warnings := s.publishSessionRevocations(ctx, []string{sessionID})

	s.logger.Info("Session revoked by admin", zap.String("session_id", sessionID), zap.String("admin_id", adminID))
	resp := gin.H{"message": "Session revoked successfully"}
	if len(warnings) > 0 {
		resp["warnings"] = warnings
	}
	c.JSON(http.StatusOK, resp)
}

// handleAdminRevokeAllUserSessions revokes all active sessions for a user
func (s *Service) handleAdminRevokeAllUserSessions(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	userID := c.Param("id")
	ctx := c.Request.Context()

	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)

	adminUserID, _ := c.Get("user_id")
	adminID, ok := adminUserID.(string)
	if !ok || adminID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(ctx, `
		UPDATE sessions SET revoked = true, revoked_at = NOW(), revoked_by = $1, revoke_reason = $2
		WHERE user_id = $3 AND (revoked IS NULL OR revoked = false) AND org_id = $4
		RETURNING id
	`, adminID, body.Reason, userID, org.ID)
	if err != nil {
		s.logger.Error("Failed to revoke user sessions", zap.Error(err), zap.String("user_id", userID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke user sessions"})
		return
	}
	var sessionIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			sessionIDs = append(sessionIDs, id)
		}
	}
	rowsErr := rows.Err()
	rows.Close()

	warnings := s.publishSessionRevocations(ctx, sessionIDs)
	if rowsErr != nil {
		// The UPDATE itself committed; what failed is reading back the ids, so
		// some markers may be missing. Say so rather than reporting clean.
		s.logger.Warn("revoked-session id read-back incomplete", zap.Error(rowsErr), zap.String("user_id", userID))
		warnings = append(warnings, "some revoked sessions could not be read back; their refresh tokens may remain usable until they expire")
	}

	count := int64(len(sessionIDs))
	s.logger.Info("All user sessions revoked by admin",
		zap.String("user_id", userID),
		zap.String("admin_id", adminID),
		zap.Int64("count", count),
	)
	resp := gin.H{
		"message": "User sessions revoked successfully",
		"count":   count,
	}
	if len(warnings) > 0 {
		resp["warnings"] = warnings
	}
	c.JSON(http.StatusOK, resp)
}

// handleListSecurityAlerts lists security alerts (delegates to SecurityService)
func (s *Service) handleListSecurityAlerts(c *gin.Context) {
	if s.securityService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Security service not available"})
		return
	}

	status := c.Query("status")
	severity := c.Query("severity")
	alertType := c.Query("alert_type")

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

	alerts, total, err := s.securityService.ListSecurityAlerts(c.Request.Context(), status, severity, alertType, limit, offset)
	if err != nil {
		s.logger.Error("Failed to list security alerts", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list security alerts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"total":  total,
	})
}

// handleGetSecurityAlert gets a single security alert
func (s *Service) handleGetSecurityAlert(c *gin.Context) {
	if s.securityService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Security service not available"})
		return
	}

	alert, err := s.securityService.GetSecurityAlert(c.Request.Context(), c.Param("id"))
	if err != nil {
		if err.Error() == "security alert not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		s.logger.Error("Failed to get security alert", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get security alert"})
		return
	}

	c.JSON(http.StatusOK, alert)
}

// handleUpdateAlertStatus updates the status of a security alert
func (s *Service) handleUpdateAlertStatus(c *gin.Context) {
	if s.securityService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Security service not available"})
		return
	}

	var body struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	adminUserID, _ := c.Get("user_id")
	adminID, ok := adminUserID.(string)
	if !ok || adminID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	if err := s.securityService.UpdateAlertStatus(c.Request.Context(), c.Param("id"), body.Status, adminID); err != nil {
		s.logger.Error("Failed to update alert status", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update alert status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Alert status updated"})
}

// handleListIPThreats lists IP threat entries
func (s *Service) handleListIPThreats(c *gin.Context) {
	if s.securityService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Security service not available"})
		return
	}

	limit := 50
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

	entries, total, err := s.securityService.ListIPThreats(c.Request.Context(), limit, offset)
	if err != nil {
		s.logger.Error("Failed to list IP threats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list IP threats"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"threats": entries,
		"total":   total,
	})
}

// handleAddIPThreat adds an IP address to the threat list
func (s *Service) handleAddIPThreat(c *gin.Context) {
	if s.securityService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Security service not available"})
		return
	}

	var body struct {
		IPAddress  string `json:"ip_address"`
		ThreatType string `json:"threat_type"`
		Reason     string `json:"reason"`
		Permanent  bool   `json:"permanent"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if body.IPAddress == "" || body.ThreatType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip_address and threat_type are required"})
		return
	}

	var blockedUntil *time.Time
	if !body.Permanent {
		t := time.Now().Add(24 * time.Hour)
		blockedUntil = &t
	}

	if err := s.securityService.AddToThreatList(c.Request.Context(), body.IPAddress, body.ThreatType, body.Reason, body.Permanent, blockedUntil); err != nil {
		s.logger.Error("Failed to add IP threat", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add IP threat"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "IP address added to threat list"})
}

// handleRemoveIPThreat removes an IP threat entry
func (s *Service) handleRemoveIPThreat(c *gin.Context) {
	if s.securityService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Security service not available"})
		return
	}

	if err := s.securityService.RemoveFromThreatList(c.Request.Context(), c.Param("id")); err != nil {
		s.logger.Error("Failed to remove IP threat", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove IP threat"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "IP threat removed"})
}

// handleRotateServiceAccountKey rotates a service account's API key
func (s *Service) handleRotateServiceAccountKey(c *gin.Context) {
	saID := c.Param("id")

	if s.apiKeyService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "API key service not available"})
		return
	}

	// Revoke all existing keys for this service account
	keys, err := s.apiKeyService.ListAPIKeys(c.Request.Context(), saID, "service_account")
	if err != nil {
		s.logger.Error("Failed to list service account keys", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list existing keys"})
		return
	}

	if keySlice, ok := keys.([]interface{}); ok {
		for _, k := range keySlice {
			if km, ok := k.(map[string]interface{}); ok {
				if id, ok := km["id"].(string); ok {
					if status, ok := km["status"].(string); ok && status == "active" {
						if err := s.apiKeyService.RevokeAPIKey(c.Request.Context(), id); err != nil {
							s.logger.Error("Failed to revoke old key during rotation", zap.String("key_id", id), zap.Error(err))
							c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke existing key"})
							return
						}
					}
				}
			}
		}
	}

	// Create a new key
	scopes := []string{"service_account"}
	plaintext, newKey, err := s.apiKeyService.CreateAPIKey(c.Request.Context(), "auto-rotated", nil, &saID, scopes, nil)
	if err != nil {
		s.logger.Error("Failed to create rotated key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create new key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Service account key rotated",
		"key":       newKey,
		"plaintext": plaintext,
	})
}
