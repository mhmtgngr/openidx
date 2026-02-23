// Package admin provides login handlers for the admin console
package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// LoginHandler handles login operations for the admin console
type LoginHandler struct {
	authHandler *AuthHandler
	db          *pgxpool.Pool
	logger      *zap.Logger
}

// NewLoginHandler creates a new login handler
func NewLoginHandler(db *pgxpool.Pool, logger *zap.Logger, jwtSecret string) *LoginHandler {
	return &LoginHandler{
		authHandler: NewAuthHandler(db, logger, jwtSecret),
		db:          db,
		logger:      logger,
	}
}

// RegisterRoutes registers login routes
func (h *LoginHandler) RegisterRoutes(router *gin.RouterGroup) {
	router.POST("/login", h.Login)
	router.POST("/logout", h.Logout)
	router.POST("/refresh", h.RefreshToken)
	router.GET("/me", h.GetCurrentUser)
	router.POST("/mfa/verify", h.VerifyMFA)
}

// Login handles admin login requests
func (h *LoginHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Authenticate user
	user, err := h.authHandler.Authenticate(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		h.logger.Warn("Failed admin login attempt",
			zap.String("email", req.Email),
			zap.String("ip", c.ClientIP()),
			zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	// Check if user has MFA enabled
	mfaEnabled, err := h.checkMFAEnabled(c.Request.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to check MFA status",
			zap.String("user_id", user.ID),
			zap.Error(err))
	}

	if mfaEnabled {
		// Return temporary token for MFA verification
		tempToken, err := h.generateTempToken(user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to initiate authentication",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"mfa_required": true,
			"temp_token":   tempToken,
			"user": gin.H{
				"id":    user.ID,
				"email": user.Email,
				"name":  user.Name,
			},
		})
		return
	}

	// Generate JWT token
	token, expiresAt, err := h.authHandler.GenerateToken(user)
	if err != nil {
		h.logger.Error("Failed to generate token",
			zap.String("user_id", user.ID),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate authentication token",
		})
		return
	}

	// Create session
	session, err := h.authHandler.CreateSession(
		c.Request.Context(),
		user.ID,
		token,
		c.Request.UserAgent(),
		c.ClientIP(),
	)
	if err != nil {
		h.logger.Error("Failed to create session",
			zap.String("user_id", user.ID),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create session",
		})
		return
	}

	h.logger.Info("Admin user logged in",
		zap.String("user_id", user.ID),
		zap.String("email", user.Email),
		zap.String("ip", c.ClientIP()))

	c.JSON(http.StatusOK, LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User:      *user,
		SessionID: session.ID,
	})
}

// Logout handles logout requests
func (h *LoginHandler) Logout(c *gin.Context) {
	// Get session ID from context or token
	token := c.GetHeader("Authorization")
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	// Validate session to get session ID
	session, _, err := h.authHandler.ValidateSession(c.Request.Context(), token)
	if err == nil {
		// Invalidate session
		if err := h.authHandler.InvalidateSession(c.Request.Context(), session.ID); err != nil {
			h.logger.Error("Failed to invalidate session",
				zap.String("session_id", session.ID),
				zap.Error(err))
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully logged out",
	})
}

// RefreshToken refreshes an authentication token
func (h *LoginHandler) RefreshToken(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Missing authorization token",
		})
		return
	}

	newToken, expiresAt, err := h.authHandler.RefreshToken(c.Request.Context(), token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid or expired token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      newToken,
		"expires_at": expiresAt,
	})
}

// GetCurrentUser returns the currently authenticated user
func (h *LoginHandler) GetCurrentUser(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Missing authorization token",
		})
		return
	}

	session, user, err := h.authHandler.ValidateSession(c.Request.Context(), token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid or expired session",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user":       user,
		"session_id": session.ID,
	})
}

// VerifyMFA verifies MFA code during login
func (h *LoginHandler) VerifyMFA(c *gin.Context) {
	var req MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Get temp token from header
	tempToken := c.GetHeader("X-Temp-Token")
	if tempToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing temporary token",
		})
		return
	}

	// Verify temp token and get user ID
	userID, err := h.validateTempToken(tempToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid or expired temporary token",
		})
		return
	}

	// Verify MFA code
	valid, err := h.verifyMFACode(c.Request.Context(), userID, req.Code)
	if err != nil || !valid {
		h.logger.Warn("Failed MFA verification attempt",
			zap.String("user_id", userID),
			zap.String("ip", c.ClientIP()),
			zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid MFA code",
		})
		return
	}

	// Get user
	user, err := h.authHandler.GetAdminUserByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve user",
		})
		return
	}

	// Generate final JWT token
	token, expiresAt, err := h.authHandler.GenerateToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate authentication token",
		})
		return
	}

	// Create session
	session, err := h.authHandler.CreateSession(
		c.Request.Context(),
		user.ID,
		token,
		c.Request.UserAgent(),
		c.ClientIP(),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create session",
		})
		return
	}

	// Invalidate temp token
	h.invalidateTempToken(tempToken)

	h.logger.Info("Admin user logged in with MFA",
		zap.String("user_id", user.ID),
		zap.String("email", user.Email),
		zap.String("ip", c.ClientIP()))

	c.JSON(http.StatusOK, LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User:      *user,
		SessionID: session.ID,
	})
}

// checkMFAEnabled checks if MFA is enabled for a user
func (h *LoginHandler) checkMFAEnabled(ctx context.Context, userID string) (bool, error) {
	var enabled bool
	err := h.db.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM user_mfa WHERE user_id = $1 AND enabled = true)",
		userID).Scan(&enabled)
	return enabled, err
}

// verifyMFACode verifies an MFA code for a user
func (h *LoginHandler) verifyMFACode(ctx context.Context, userID, code string) (bool, error) {
	// Query MFA secrets for user
	var secret string
	var backupCodes []string

	err := h.db.QueryRow(ctx,
		`SELECT totp_secret, backup_codes FROM user_mfa
		 WHERE user_id = $1 AND enabled = true`,
		userID).Scan(&secret, &backupCodes)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}

	// Verify TOTP code (implementation would use a TOTP library)
	// For now, this is a placeholder
	// In production, you would use github.com/pquerna/otp

	return true, nil
}

// generateTempToken generates a temporary token for MFA flow
func (h *LoginHandler) generateTempToken(userID string) (string, error) {
	// This is a simplified implementation
	// In production, use proper JWT or random token with expiration
	return "temp_" + userID, nil
}

// validateTempToken validates a temporary token
func (h *LoginHandler) validateTempToken(token string) (string, error) {
	// This is a simplified implementation
	if strings.HasPrefix(token, "temp_") {
		return strings.TrimPrefix(token, "temp_"), nil
	}
	return "", errors.New("invalid temp token")
}

// invalidateTempToken invalidates a temporary token
func (h *LoginHandler) invalidateTempToken(token string) {
	// This is a simplified implementation
	// In production, maintain a token blacklist or use short-lived JWTs
}

// Middleware that verifies admin authentication
func (h *LoginHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		}

		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Missing authorization token",
			})
			return
		}

		session, user, err := h.authHandler.ValidateSession(c.Request.Context(), token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired session",
			})
			return
		}

		// Set user in context
		c.Set("user_id", user.ID)
		c.Set("user_email", user.Email)
		c.Set("user_name", user.Name)
		c.Set("session_id", session.ID)
		c.Set("is_super_admin", user.IsSuperAdmin)

		c.Next()
	}
}

// RequireSuperAdmin is a middleware that requires super admin privileges
func (h *LoginHandler) RequireSuperAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		isSuperAdmin, exists := c.Get("is_super_admin")
		if !exists || !isSuperAdmin.(bool) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Super admin privileges required",
			})
			return
		}
		c.Next()
	}
}
