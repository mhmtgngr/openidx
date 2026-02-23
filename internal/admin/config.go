// Package admin provides system configuration management for the admin console
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// SystemConfig represents the complete system configuration
type SystemConfig struct {
	PasswordPolicy PasswordPolicyConfig `json:"password_policy"`
	SessionPolicy  SessionPolicyConfig  `json:"session_policy"`
	MFAPolicy      MFAPolicyConfig      `json:"mfa_policy"`
	RateLimit      RateLimitPolicyConfig `json:"rate_limit"`
	UpdatedAt      *time.Time           `json:"updated_at"`
}

// PasswordPolicyConfig defines password requirements
type PasswordPolicyConfig struct {
	MinLength      int      `json:"min_length" binding:"required,min=8,max=128"`
	RequireUpper   bool     `json:"require_upper"`
	RequireLower   bool     `json:"require_lower"`
	RequireDigit   bool     `json:"require_digit"`
	RequireSpecial bool     `json:"require_special"`
	HistoryCount   int      `json:"history_count" binding:"min=0,max=24"`
	SpecialChars   string   `json:"special_chars"`
	ForbiddenWords []string `json:"forbidden_words"`
}

// SessionPolicyConfig defines session management rules
type SessionPolicyConfig struct {
	TimeoutMinutes int `json:"timeout_minutes" binding:"required,min=5,max=1440"`
	MaxConcurrent  int `json:"max_concurrent" binding:"required,min=1,max=100"`
	IdleTimeout    int `json:"idle_timeout_minutes" binding:"min=0,max=1440"`
}

// MFAPolicyConfig defines MFA requirements
type MFAPolicyConfig struct {
	RequiredForRoles []string `json:"required_for_roles"`
	AllowedMethods   []string `json:"allowed_methods"` // totp, sms, email, push, webhook
	TrustDuration    int      `json:"trust_device_days" binding:"min=0,max=365"`
}

// RateLimitPolicyConfig defines rate limiting rules
type RateLimitPolicyConfig struct {
	PerIP      int `json:"per_ip" binding:"min=0,max=10000"`
	PerUser    int `json:"per_user" binding:"min=0,max=5000"`
	WindowSecs int `json:"window_seconds" binding:"min=1,max=3600"`
}

// GetSystemConfig retrieves the current system configuration
func (s *Service) GetSystemConfig(ctx context.Context) (*SystemConfig, error) {
	var configJSON []byte
	var updatedAt *time.Time

	err := s.db.Pool.QueryRow(ctx, `
		SELECT config, updated_at FROM system_config WHERE id = 'default'
	`).Scan(&configJSON, &updatedAt)

	if err != nil {
		// Return default config if not exists
		return s.GetDefaultSystemConfig(), nil
	}

	var config SystemConfig
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &config); err != nil {
			s.logger.Warn("Failed to unmarshal system config", zap.Error(err))
			return s.GetDefaultSystemConfig(), nil
		}
	} else {
		config = *s.GetDefaultSystemConfig()
	}

	config.UpdatedAt = updatedAt
	return &config, nil
}

// UpdateSystemConfig updates the system configuration
func (s *Service) UpdateSystemConfig(ctx context.Context, config *SystemConfig) error {
	// Validate configuration
	if err := s.ValidateSystemConfig(config); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	now := time.Now()

	// Check if config exists
	var exists bool
	err = s.db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM system_config WHERE id = 'default')").Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check config existence: %w", err)
	}

	if exists {
		_, err = s.db.Pool.Exec(ctx, `
			UPDATE system_config
			SET config = $1, updated_at = $2
			WHERE id = 'default'
		`, configJSON, now)
	} else {
		_, err = s.db.Pool.Exec(ctx, `
			INSERT INTO system_config (id, config, updated_at)
			VALUES ('default', $1, $2)
		`, configJSON, now)
	}

	if err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	// Invalidate dashboard cache
	_ = s.InvalidateEnhancedDashboardCache(ctx)

	return nil
}

// ValidateSystemConfig validates the system configuration
func (s *Service) ValidateSystemConfig(config *SystemConfig) error {
	// Validate password policy
	if config.PasswordPolicy.MinLength < 8 {
		return fmt.Errorf("password min_length must be at least 8")
	}
	if config.PasswordPolicy.MinLength > 128 {
		return fmt.Errorf("password min_length cannot exceed 128")
	}
	if config.PasswordPolicy.HistoryCount < 0 || config.PasswordPolicy.HistoryCount > 24 {
		return fmt.Errorf("password history_count must be between 0 and 24")
	}

	// Validate session policy
	if config.SessionPolicy.TimeoutMinutes < 5 {
		return fmt.Errorf("session timeout must be at least 5 minutes")
	}
	if config.SessionPolicy.MaxConcurrent < 1 {
		return fmt.Errorf("max concurrent sessions must be at least 1")
	}

	// Validate MFA policy
	validMFAMethods := map[string]bool{
		"totp": true, "sms": true, "email": true, "push": true, "webhook": true,
	}
	for _, method := range config.MFAPolicy.AllowedMethods {
		if !validMFAMethods[method] {
			return fmt.Errorf("invalid MFA method: %s", method)
		}
	}

	// Validate rate limit
	if config.RateLimit.PerIP < 0 || config.RateLimit.PerIP > 10000 {
		return fmt.Errorf("rate limit per_ip must be between 0 and 10000")
	}
	if config.RateLimit.PerUser < 0 || config.RateLimit.PerUser > 5000 {
		return fmt.Errorf("rate limit per_user must be between 0 and 5000")
	}

	return nil
}

// GetDefaultSystemConfig returns the default system configuration
func (s *Service) GetDefaultSystemConfig() *SystemConfig {
	return &SystemConfig{
		PasswordPolicy: PasswordPolicyConfig{
			MinLength:      12,
			RequireUpper:   true,
			RequireLower:   true,
			RequireDigit:   true,
			RequireSpecial: true,
			HistoryCount:   5,
			SpecialChars:   "!@#$%^&*()_+-=[]{}|;:,.<>?",
			ForbiddenWords: []string{"password", "123456", "qwerty"},
		},
		SessionPolicy: SessionPolicyConfig{
			TimeoutMinutes: 60,
			MaxConcurrent:  5,
			IdleTimeout:    30,
		},
		MFAPolicy: MFAPolicyConfig{
			RequiredForRoles: []string{"admin", "super_admin"},
			AllowedMethods:   []string{"totp", "sms", "push"},
			TrustDuration:    30,
		},
		RateLimit: RateLimitPolicyConfig{
			PerIP:      100,
			PerUser:    50,
			WindowSecs: 60,
		},
	}
}

// ValidatePassword validates a password against the configured policy
func (s *Service) ValidatePassword(ctx context.Context, password string) error {
	config, err := s.GetSystemConfig(ctx)
	if err != nil {
		s.logger.Warn("Failed to get system config for password validation", zap.Error(err))
		config = s.GetDefaultSystemConfig()
	}

	pp := config.PasswordPolicy

	// Check minimum length
	if len(password) < pp.MinLength {
		return fmt.Errorf("password must be at least %d characters", pp.MinLength)
	}

	// Check uppercase requirement
	if pp.RequireUpper {
		if matched, _ := regexp.MatchString("[A-Z]", password); !matched {
			return fmt.Errorf("password must contain at least one uppercase letter")
		}
	}

	// Check lowercase requirement
	if pp.RequireLower {
		if matched, _ := regexp.MatchString("[a-z]", password); !matched {
			return fmt.Errorf("password must contain at least one lowercase letter")
		}
	}

	// Check digit requirement
	if pp.RequireDigit {
		if matched, _ := regexp.MatchString("[0-9]", password); !matched {
			return fmt.Errorf("password must contain at least one digit")
		}
	}

	// Check special character requirement
	if pp.RequireSpecial {
		hasSpecial := false
		for _, char := range password {
			if pp.SpecialChars != "" {
				if containsChar(pp.SpecialChars, char) {
					hasSpecial = true
					break
				}
			} else {
				// Default special chars if not specified
				defaultSpecial := "!@#$%^&*()_+-=[]{}|;:,.<>?"
				if containsChar(defaultSpecial, char) {
					hasSpecial = true
					break
				}
			}
		}
		if !hasSpecial {
			return fmt.Errorf("password must contain at least one special character")
		}
	}

	// Check forbidden words
	lowerPassword := regexp.MustCompile(`[0-9]`).ReplaceAllString(password, "")
	lowerPassword = regexp.MustCompile(`[^a-zA-Z]`).ReplaceAllString(lowerPassword, "")
	for _, word := range pp.ForbiddenWords {
		if containsIgnoreCase(lowerPassword, word) {
			return fmt.Errorf("password cannot contain common words like '%s'", word)
		}
	}

	return nil
}

// ValidateSession validates session settings against policy
func (s *Service) ValidateSession(ctx context.Context, timeoutMinutes, maxConcurrent int) error {
	config, err := s.GetSystemConfig(ctx)
	if err != nil {
		s.logger.Warn("Failed to get system config for session validation", zap.Error(err))
		return nil // Allow if config not available
	}

	sp := config.SessionPolicy

	if timeoutMinutes > sp.TimeoutMinutes {
		return fmt.Errorf("session timeout cannot exceed %d minutes", sp.TimeoutMinutes)
	}

	if maxConcurrent > sp.MaxConcurrent {
		return fmt.Errorf("max concurrent sessions cannot exceed %d", sp.MaxConcurrent)
	}

	return nil
}

// IsMFARequiredForRole checks if MFA is required for a given role
func (s *Service) IsMFARequiredForRole(ctx context.Context, role string) (bool, error) {
	config, err := s.GetSystemConfig(ctx)
	if err != nil {
		s.logger.Warn("Failed to get system config for MFA check", zap.Error(err))
		return false, nil
	}

	for _, requiredRole := range config.MFAPolicy.RequiredForRoles {
		if requiredRole == role {
			return true, nil
		}
	}

	return false, nil
}

// IsMFAMethodAllowed checks if an MFA method is allowed
func (s *Service) IsMFAMethodAllowed(ctx context.Context, method string) (bool, error) {
	config, err := s.GetSystemConfig(ctx)
	if err != nil {
		s.logger.Warn("Failed to get system config for MFA method check", zap.Error(err))
		return true, nil // Allow if config not available
	}

	for _, allowedMethod := range config.MFAPolicy.AllowedMethods {
		if allowedMethod == method {
			return true, nil
		}
	}

	return false, nil
}

// GetRateLimitConfig returns the current rate limit configuration
func (s *Service) GetRateLimitConfig(ctx context.Context) (*RateLimitPolicyConfig, error) {
	config, err := s.GetSystemConfig(ctx)
	if err != nil {
		s.logger.Warn("Failed to get system config for rate limit", zap.Error(err))
		defaultConfig := s.GetDefaultSystemConfig()
		return &defaultConfig.RateLimit, nil
	}

	return &config.RateLimit, nil
}

func containsChar(s string, char rune) bool {
	for _, c := range s {
		if c == char {
			return true
		}
	}
	return false
}

func containsIgnoreCase(s, substr string) bool {
	return regexp.MustCompile("(?i)"+regexp.QuoteMeta(substr)).MatchString(s)
}

// --- Handlers ---

// handleGetSystemConfig handles GET /api/v1/admin/config
func (s *Service) handleGetSystemConfig(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	config, err := s.GetSystemConfig(c.Request.Context())
	if err != nil {
		s.logger.Error("Failed to get system config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve system configuration"})
		return
	}

	c.JSON(http.StatusOK, config)
}

// handleUpdateSystemConfig handles PUT /api/v1/admin/config
func (s *Service) handleUpdateSystemConfig(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var config SystemConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdateSystemConfig(c.Request.Context(), &config); err != nil {
		s.logger.Error("Failed to update system config", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Configuration updated successfully"})
}

// handleValidatePassword handles POST /api/v1/admin/config/validate-password
func (s *Service) handleValidatePassword(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := s.ValidatePassword(c.Request.Context(), req.Password)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid": true,
	})
}

// handleResetSystemConfig handles POST /api/v1/admin/config/reset
func (s *Service) handleResetSystemConfig(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	defaultConfig := s.GetDefaultSystemConfig()
	if err := s.UpdateSystemConfig(c.Request.Context(), defaultConfig); err != nil {
		s.logger.Error("Failed to reset system config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset configuration"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Configuration reset to defaults"})
}
