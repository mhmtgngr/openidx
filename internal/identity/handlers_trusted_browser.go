// Package identity - HTTP handlers for trusted browser management
package identity

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// handleTrustBrowser creates a trusted browser entry
func (s *Service) handleTrustBrowser(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	var req struct {
		Name        string `json:"name"`
		BrowserHash string `json:"browser_hash"`
	}

	c.ShouldBindJSON(&req)

	// Generate browser hash if not provided
	browserHash := req.BrowserHash
	if browserHash == "" {
		browserHash = generateBrowserHash(c.GetHeader("User-Agent"), c.ClientIP())
	}

	// Generate name if not provided
	name := req.Name
	if name == "" {
		name = parseBrowserName(c.GetHeader("User-Agent"))
	}

	tb, err := s.TrustBrowser(c.Request.Context(), userID, browserHash, name, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         tb.ID,
		"name":       tb.Name,
		"trusted_at": tb.TrustedAt,
		"expires_at": tb.ExpiresAt,
		"message":    "Browser trusted successfully",
	})
}

// handleGetTrustedBrowsers returns all trusted browsers for the current user
func (s *Service) handleGetTrustedBrowsers(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	browsers, err := s.GetTrustedBrowsers(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get trusted browsers"})
		return
	}

	// Mask browser hashes for security
	response := make([]gin.H, len(browsers))
	for i, b := range browsers {
		response[i] = gin.H{
			"id":           b.ID,
			"name":         b.Name,
			"ip_address":   b.IPAddress,
			"trusted_at":   b.TrustedAt,
			"expires_at":   b.ExpiresAt,
			"last_used_at": b.LastUsedAt,
			"revoked":      b.Revoked,
			"active":       !b.Revoked && b.ExpiresAt.After(time.Now()),
		}
	}

	c.JSON(http.StatusOK, response)
}

// handleRevokeTrustedBrowser revokes a specific trusted browser
func (s *Service) handleRevokeTrustedBrowser(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	browserID := c.Param("browser_id")
	if browserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "browser_id is required"})
		return
	}

	if err := s.RevokeTrustedBrowser(c.Request.Context(), userID, browserID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Browser trust revoked successfully"})
}

// handleRevokeAllTrustedBrowsers revokes all trusted browsers for the current user
func (s *Service) handleRevokeAllTrustedBrowsers(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	if err := s.RevokeAllTrustedBrowsers(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "All trusted browsers revoked successfully"})
}

// handleCheckTrustedBrowser checks if the current browser is trusted
func (s *Service) handleCheckTrustedBrowser(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	browserHash := generateBrowserHash(c.GetHeader("User-Agent"), c.ClientIP())

	tb, err := s.IsTrustedBrowser(c.Request.Context(), userID, browserHash)
	if err != nil || tb == nil {
		c.JSON(http.StatusOK, gin.H{
			"trusted": false,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"trusted":    true,
		"browser_id": tb.ID,
		"name":       tb.Name,
		"expires_at": tb.ExpiresAt,
	})
}

// handleGetRiskAssessment returns a risk assessment for the current session
func (s *Service) handleGetRiskAssessment(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// Build login context from current request
	lc := &LoginContext{
		UserID:      userID,
		IPAddress:   c.ClientIP(),
		UserAgent:   c.GetHeader("User-Agent"),
		BrowserHash: generateBrowserHash(c.GetHeader("User-Agent"), c.ClientIP()),
	}

	// Check if device is known
	knownDevices, _ := s.getKnownDevices(c.Request.Context(), userID)
	for _, d := range knownDevices {
		if d.Fingerprint == lc.BrowserHash {
			lc.KnownDevice = true
			break
		}
	}

	// Get last login info
	lastLogin, _ := s.getLastSuccessfulLogin(c.Request.Context(), userID)
	if lastLogin != nil {
		lc.LastLoginIP = lastLogin.IPAddress
		lc.LastLoginLat = lastLogin.Latitude
		lc.LastLoginLon = lastLogin.Longitude
		lc.LastLoginTime = lastLogin.LoginTime
	}

	assessment, err := s.AssessLoginRisk(c.Request.Context(), lc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to assess risk"})
		return
	}

	c.JSON(http.StatusOK, assessment)
}

// --- Helper Functions ---

func parseBrowserName(userAgent string) string {
	// Simple browser detection
	if contains(userAgent, "Chrome") {
		if contains(userAgent, "Edg") {
			return "Microsoft Edge"
		}
		if contains(userAgent, "OPR") || contains(userAgent, "Opera") {
			return "Opera"
		}
		return "Google Chrome"
	}
	if contains(userAgent, "Firefox") {
		return "Mozilla Firefox"
	}
	if contains(userAgent, "Safari") && !contains(userAgent, "Chrome") {
		return "Apple Safari"
	}
	if contains(userAgent, "MSIE") || contains(userAgent, "Trident") {
		return "Internet Explorer"
	}
	return "Unknown Browser"
}

// KnownDevice represents a known device from login history
type KnownDevice struct {
	Fingerprint string
	IPAddress   string
	UserAgent   string
	LastSeen    *time.Time
}

// LoginRecord represents the last login record
type LoginRecord struct {
	IPAddress string
	Latitude  float64
	Longitude float64
	LoginTime *time.Time
}

func (s *Service) getKnownDevices(ctx context.Context, userID string) ([]KnownDevice, error) {
	query := `
		SELECT fingerprint, ip_address, user_agent, last_seen_at
		FROM known_devices
		WHERE user_id = $1 AND trusted = true
	`
	rows, err := s.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []KnownDevice
	for rows.Next() {
		var d KnownDevice
		if err := rows.Scan(&d.Fingerprint, &d.IPAddress, &d.UserAgent, &d.LastSeen); err != nil {
			continue
		}
		devices = append(devices, d)
	}
	return devices, nil
}

func (s *Service) getLastSuccessfulLogin(ctx context.Context, userID string) (*LoginRecord, error) {
	query := `
		SELECT ip_address, latitude, longitude, created_at
		FROM login_history
		WHERE user_id = $1 AND success = true
		ORDER BY created_at DESC
		LIMIT 1
	`
	var record LoginRecord
	err := s.db.Pool.QueryRow(ctx, query, userID).Scan(
		&record.IPAddress,
		&record.Latitude,
		&record.Longitude,
		&record.LoginTime,
	)
	if err != nil {
		return nil, err
	}
	return &record, nil
}
