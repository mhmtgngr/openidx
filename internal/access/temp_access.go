// Package access provides temporary access link functionality for support/vendor access
package access

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// TempAccessLink represents a temporary access link for support/vendor access
type TempAccessLink struct {
	ID              string    `json:"id"`
	Token           string    `json:"token"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	Protocol        string    `json:"protocol"` // ssh, rdp, vnc
	TargetHost      string    `json:"target_host"`
	TargetPort      int       `json:"target_port"`
	Username        string    `json:"username,omitempty"`
	CreatedBy       string    `json:"created_by"`
	CreatedByEmail  string    `json:"created_by_email"`
	ExpiresAt       time.Time `json:"expires_at"`
	MaxUses         int       `json:"max_uses"`          // 0 = unlimited
	CurrentUses     int       `json:"current_uses"`
	AllowedIPs      []string  `json:"allowed_ips,omitempty"` // IP whitelist
	RequireMFA      bool      `json:"require_mfa"`
	NotifyOnUse     bool      `json:"notify_on_use"`
	NotifyEmail     string    `json:"notify_email,omitempty"`
	RouteID         string    `json:"route_id,omitempty"`
	GuacConnectionID string   `json:"guacamole_connection_id,omitempty"`
	AccessURL       string    `json:"access_url"`
	Status          string    `json:"status"` // active, expired, revoked, used
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP      string    `json:"last_used_ip,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// TempAccessUsage tracks usage of temporary access links
type TempAccessUsage struct {
	ID           string    `json:"id"`
	LinkID       string    `json:"link_id"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	ConnectedAt  time.Time `json:"connected_at"`
	DisconnectedAt *time.Time `json:"disconnected_at,omitempty"`
	Duration     int       `json:"duration_seconds,omitempty"`
}

// CreateTempAccessRequest is the request to create a temp access link
type CreateTempAccessRequest struct {
	Name         string   `json:"name" binding:"required"`
	Description  string   `json:"description"`
	Protocol     string   `json:"protocol" binding:"required,oneof=ssh rdp vnc"`
	TargetHost   string   `json:"target_host" binding:"required"`
	TargetPort   int      `json:"target_port" binding:"required,min=1,max=65535"`
	Username     string   `json:"username"`
	DurationMins int      `json:"duration_mins" binding:"required,min=5,max=10080"` // 5 mins to 7 days
	MaxUses      int      `json:"max_uses"`           // 0 = unlimited
	AllowedIPs   []string `json:"allowed_ips"`
	RequireMFA   bool     `json:"require_mfa"`
	NotifyOnUse  bool     `json:"notify_on_use"`
	NotifyEmail  string   `json:"notify_email"`
}

// generateSecureToken generates a cryptographically secure token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// handleCreateTempAccess creates a new temporary access link
func (s *Service) handleCreateTempAccess(c *gin.Context) {
	var req CreateTempAccessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get current user from context
	userID, _ := c.Get("user_id")
	userEmail, _ := c.Get("email")

	// Generate secure token
	token, err := generateSecureToken(32)
	if err != nil {
		s.logger.Error("failed to generate token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate access token"})
		return
	}

	linkID := uuid.New().String()
	expiresAt := time.Now().Add(time.Duration(req.DurationMins) * time.Minute)

	// Default port based on protocol
	port := req.TargetPort
	if port == 0 {
		switch req.Protocol {
		case "ssh":
			port = 22
		case "rdp":
			port = 3389
		case "vnc":
			port = 5900
		}
	}

	link := TempAccessLink{
		ID:             linkID,
		Token:          token,
		Name:           req.Name,
		Description:    req.Description,
		Protocol:       req.Protocol,
		TargetHost:     req.TargetHost,
		TargetPort:     port,
		Username:       req.Username,
		CreatedBy:      fmt.Sprintf("%v", userID),
		CreatedByEmail: fmt.Sprintf("%v", userEmail),
		ExpiresAt:      expiresAt,
		MaxUses:        req.MaxUses,
		CurrentUses:    0,
		AllowedIPs:     req.AllowedIPs,
		RequireMFA:     req.RequireMFA,
		NotifyOnUse:    req.NotifyOnUse,
		NotifyEmail:    req.NotifyEmail,
		Status:         "active",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Create Guacamole connection for this temp access
	if s.guacamoleClient != nil {
		connID, err := s.guacamoleClient.CreateConnection(
			fmt.Sprintf("temp-%s-%s", req.Protocol, token[:8]),
			req.Protocol,
			req.TargetHost,
			port,
			map[string]string{},
		)
		if err != nil {
			s.logger.Warn("failed to create guacamole connection", zap.Error(err))
		} else {
			link.GuacConnectionID = connID
		}
	}

	// Build access URL
	baseURL := s.config.AccessProxyDomain
	if baseURL == "" {
		baseURL = "browzer.localtest.me"
	}
	link.AccessURL = fmt.Sprintf("https://%s/temp-access/%s", baseURL, token)

	// Store in database
	query := `
		INSERT INTO temp_access_links (
			id, token, name, description, protocol, target_host, target_port, username,
			created_by, created_by_email, expires_at, max_uses, current_uses,
			allowed_ips, require_mfa, notify_on_use, notify_email, route_id,
			guacamole_connection_id, access_url, status, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
		)`

	_, err = s.db.Pool.Exec(c.Request.Context(), query,
		link.ID, link.Token, link.Name, link.Description, link.Protocol,
		link.TargetHost, link.TargetPort, link.Username, link.CreatedBy,
		link.CreatedByEmail, link.ExpiresAt, link.MaxUses, link.CurrentUses,
		link.AllowedIPs, link.RequireMFA, link.NotifyOnUse, link.NotifyEmail,
		link.RouteID, link.GuacConnectionID, link.AccessURL, link.Status,
		link.CreatedAt, link.UpdatedAt,
	)
	if err != nil {
		s.logger.Error("failed to create temp access link", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create access link"})
		return
	}

	// Audit log
	s.auditLog(c, "temp_access.created", map[string]interface{}{
		"link_id":     link.ID,
		"target_host": link.TargetHost,
		"protocol":    link.Protocol,
		"expires_at":  link.ExpiresAt,
	})

	c.JSON(http.StatusCreated, link)
}

// handleListTempAccess lists all temporary access links
func (s *Service) handleListTempAccess(c *gin.Context) {
	status := c.DefaultQuery("status", "")

	query := `
		SELECT id, token, name, description, protocol, target_host, target_port, username,
			created_by, created_by_email, expires_at, max_uses, current_uses,
			allowed_ips, require_mfa, notify_on_use, notify_email, route_id,
			guacamole_connection_id, access_url, status, last_used_at, last_used_ip,
			created_at, updated_at
		FROM temp_access_links
		WHERE ($1 = '' OR status = $1)
		ORDER BY created_at DESC
		LIMIT 100`

	rows, err := s.db.Pool.Query(c.Request.Context(), query, status)
	if err != nil {
		s.logger.Error("failed to list temp access links", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list access links"})
		return
	}
	defer rows.Close()

	var links []TempAccessLink
	for rows.Next() {
		var link TempAccessLink
		err := rows.Scan(
			&link.ID, &link.Token, &link.Name, &link.Description, &link.Protocol,
			&link.TargetHost, &link.TargetPort, &link.Username, &link.CreatedBy,
			&link.CreatedByEmail, &link.ExpiresAt, &link.MaxUses, &link.CurrentUses,
			&link.AllowedIPs, &link.RequireMFA, &link.NotifyOnUse, &link.NotifyEmail,
			&link.RouteID, &link.GuacConnectionID, &link.AccessURL, &link.Status,
			&link.LastUsedAt, &link.LastUsedIP, &link.CreatedAt, &link.UpdatedAt,
		)
		if err != nil {
			continue
		}

		// Auto-expire if past expiration
		if time.Now().After(link.ExpiresAt) && link.Status == "active" {
			link.Status = "expired"
		}

		// Mask token for security (only show first 8 chars)
		if len(link.Token) > 8 {
			link.Token = link.Token[:8] + "..."
		}

		links = append(links, link)
	}

	c.JSON(http.StatusOK, gin.H{"links": links})
}

// handleGetTempAccess gets a specific temp access link
func (s *Service) handleGetTempAccess(c *gin.Context) {
	id := c.Param("id")

	query := `
		SELECT id, token, name, description, protocol, target_host, target_port, username,
			created_by, created_by_email, expires_at, max_uses, current_uses,
			allowed_ips, require_mfa, notify_on_use, notify_email, route_id,
			guacamole_connection_id, access_url, status, last_used_at, last_used_ip,
			created_at, updated_at
		FROM temp_access_links
		WHERE id = $1`

	var link TempAccessLink
	err := s.db.Pool.QueryRow(c.Request.Context(), query, id).Scan(
		&link.ID, &link.Token, &link.Name, &link.Description, &link.Protocol,
		&link.TargetHost, &link.TargetPort, &link.Username, &link.CreatedBy,
		&link.CreatedByEmail, &link.ExpiresAt, &link.MaxUses, &link.CurrentUses,
		&link.AllowedIPs, &link.RequireMFA, &link.NotifyOnUse, &link.NotifyEmail,
		&link.RouteID, &link.GuacConnectionID, &link.AccessURL, &link.Status,
		&link.LastUsedAt, &link.LastUsedIP, &link.CreatedAt, &link.UpdatedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "access link not found"})
		return
	}

	c.JSON(http.StatusOK, link)
}

// handleRevokeTempAccess revokes a temp access link
func (s *Service) handleRevokeTempAccess(c *gin.Context) {
	id := c.Param("id")

	query := `UPDATE temp_access_links SET status = 'revoked', updated_at = $1 WHERE id = $2`
	result, err := s.db.Pool.Exec(c.Request.Context(), query, time.Now(), id)
	if err != nil {
		s.logger.Error("failed to revoke temp access link", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke access link"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "access link not found"})
		return
	}

	// Audit log
	s.auditLog(c, "temp_access.revoked", map[string]interface{}{"link_id": id})

	c.JSON(http.StatusOK, gin.H{"message": "access link revoked"})
}

// handleUseTempAccess handles accessing a temp link (redirects to Guacamole)
func (s *Service) handleUseTempAccess(c *gin.Context) {
	token := c.Param("token")

	query := `
		SELECT id, token, name, protocol, target_host, target_port, username,
			expires_at, max_uses, current_uses, allowed_ips, require_mfa,
			notify_on_use, notify_email, guacamole_connection_id, status
		FROM temp_access_links
		WHERE token = $1`

	var link TempAccessLink
	err := s.db.Pool.QueryRow(c.Request.Context(), query, token).Scan(
		&link.ID, &link.Token, &link.Name, &link.Protocol, &link.TargetHost,
		&link.TargetPort, &link.Username, &link.ExpiresAt, &link.MaxUses,
		&link.CurrentUses, &link.AllowedIPs, &link.RequireMFA, &link.NotifyOnUse,
		&link.NotifyEmail, &link.GuacConnectionID, &link.Status,
	)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"title":   "Access Link Not Found",
			"message": "This access link is invalid or has been removed.",
		})
		return
	}

	// Check if expired
	if time.Now().After(link.ExpiresAt) {
		c.HTML(http.StatusGone, "error.html", gin.H{
			"title":   "Access Link Expired",
			"message": "This temporary access link has expired.",
		})
		return
	}

	// Check if revoked
	if link.Status == "revoked" {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"title":   "Access Link Revoked",
			"message": "This access link has been revoked by an administrator.",
		})
		return
	}

	// Check max uses
	if link.MaxUses > 0 && link.CurrentUses >= link.MaxUses {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"title":   "Access Link Exhausted",
			"message": "This access link has reached its maximum usage limit.",
		})
		return
	}

	// Check IP whitelist
	clientIP := c.ClientIP()
	if len(link.AllowedIPs) > 0 {
		allowed := false
		for _, ip := range link.AllowedIPs {
			if ip == clientIP {
				allowed = true
				break
			}
		}
		if !allowed {
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"title":   "Access Denied",
				"message": "Your IP address is not authorized to use this access link.",
			})
			return
		}
	}

	// Update usage stats
	updateQuery := `
		UPDATE temp_access_links
		SET current_uses = current_uses + 1, last_used_at = $1, last_used_ip = $2, updated_at = $1
		WHERE id = $3`
	s.db.Pool.Exec(c.Request.Context(), updateQuery, time.Now(), clientIP, link.ID)

	// Log usage
	usageID := uuid.New().String()
	usageQuery := `
		INSERT INTO temp_access_usage (id, link_id, ip_address, user_agent, connected_at)
		VALUES ($1, $2, $3, $4, $5)`
	s.db.Pool.Exec(c.Request.Context(), usageQuery, usageID, link.ID, clientIP, c.Request.UserAgent(), time.Now())

	// Audit log
	s.auditLog(c, "temp_access.used", map[string]interface{}{
		"link_id":     link.ID,
		"ip_address":  clientIP,
		"target_host": link.TargetHost,
	})

	// Redirect to Guacamole
	if link.GuacConnectionID != "" {
		guacURL := fmt.Sprintf("/guacamole/#/client/%s", link.GuacConnectionID)
		c.Redirect(http.StatusFound, guacURL)
		return
	}

	// Fallback: show connection info
	c.HTML(http.StatusOK, "temp_access.html", gin.H{
		"name":     link.Name,
		"protocol": link.Protocol,
		"host":     link.TargetHost,
		"port":     link.TargetPort,
		"username": link.Username,
	})
}

// handleGetTempAccessUsage gets usage history for a temp access link
func (s *Service) handleGetTempAccessUsage(c *gin.Context) {
	linkID := c.Param("id")

	query := `
		SELECT id, link_id, ip_address, user_agent, connected_at, disconnected_at
		FROM temp_access_usage
		WHERE link_id = $1
		ORDER BY connected_at DESC
		LIMIT 50`

	rows, err := s.db.Pool.Query(c.Request.Context(), query, linkID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get usage history"})
		return
	}
	defer rows.Close()

	var usage []TempAccessUsage
	for rows.Next() {
		var u TempAccessUsage
		err := rows.Scan(&u.ID, &u.LinkID, &u.IPAddress, &u.UserAgent, &u.ConnectedAt, &u.DisconnectedAt)
		if err != nil {
			continue
		}
		if u.DisconnectedAt != nil {
			u.Duration = int(u.DisconnectedAt.Sub(u.ConnectedAt).Seconds())
		}
		usage = append(usage, u)
	}

	c.JSON(http.StatusOK, gin.H{"usage": usage})
}

// auditLog helper for audit logging
func (s *Service) auditLog(c *gin.Context, eventType string, details map[string]interface{}) {
	// Implementation would send to audit service
	s.logger.Info("audit event",
		zap.String("event_type", eventType),
		zap.Any("details", details),
		zap.String("ip", c.ClientIP()),
	)
}
