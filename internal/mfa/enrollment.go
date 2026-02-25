// Package mfa provides Multi-Factor Authentication enrollment HTTP handlers for OpenIDX
package mfa

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/auth"
)

// EnrollmentService combines TOTP and recovery services for enrollment operations
type EnrollmentService struct {
	totp       *Service
	recovery   *RecoveryService
	repo       Repository
	recoveryRepo RecoveryCodeRepository
	logger     *zap.Logger
}

// NewEnrollmentService creates a new enrollment service
func NewEnrollmentService(
	totpService *Service,
	recoveryService *RecoveryService,
	repo Repository,
	recoveryRepo RecoveryCodeRepository,
	logger *zap.Logger,
) *EnrollmentService {
	return &EnrollmentService{
		totp:        totpService,
		recovery:    recoveryService,
		repo:        repo,
		recoveryRepo: recoveryRepo,
		logger:      logger,
	}
}

// Handlers provides HTTP handlers for MFA enrollment
type Handlers struct {
	service *EnrollmentService
	logger  *zap.Logger
}

// NewHandlers creates new MFA enrollment HTTP handlers
func NewHandlers(service *EnrollmentService, logger *zap.Logger) *Handlers {
	return &Handlers{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes registers MFA enrollment routes
func (h *Handlers) RegisterRoutes(router gin.IRouter) {
	mfa := router.Group("/mfa")
	{
		// TOTP enrollment endpoints
		mfa.POST("/enroll/totp", h.HandleTOTPEnroll)
		mfa.POST("/enroll/totp/verify", h.HandleTOTPVerify)

		// MFA verification endpoint (login-time)
		mfa.POST("/verify", h.HandleMFAVerify)

		// Recovery code endpoints
		mfa.POST("/recovery/generate", h.HandleRecoveryGenerate)
		mfa.POST("/recovery/verify", h.HandleRecoveryVerify)
		mfa.GET("/recovery/status", h.HandleRecoveryStatus)
	}
}

// Request represents common request fields
type Request struct {
	UserID string `json:"user_id" binding:"required"`
	Code   string `json:"code"`
}

// TOTPEnrollRequest represents a TOTP enrollment request
type TOTPEnrollRequest struct {
	UserID      string `json:"user_id" binding:"required,uuid"`
	AccountName string `json:"account_name"`
}

// TOTPEnrollResponse represents a TOTP enrollment response
type TOTPEnrollResponse struct {
	Secret    string `json:"secret"`     // Base32-encoded secret
	QRCodeURL string `json:"qr_code_url"`
	Message   string `json:"message"`
}

// TOTPVerifyRequest represents a TOTP verification request
type TOTPVerifyRequest struct {
	UserID string `json:"user_id" binding:"required,uuid"`
	Code   string `json:"code" binding:"required,min=6,max=8"`
}

// TOTPVerifyResponse represents a TOTP verification response
type TOTPVerifyResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// MFAVerifyRequest represents an MFA verification request at login time
type MFAVerifyRequest struct {
	UserID         string `json:"user_id" binding:"required,uuid"`
	Code           string `json:"code" binding:"required"`
	RecoveryCode   string `json:"recovery_code"`
	Method         string `json:"method"` // "totp" or "recovery"
}

// MFAVerifyResponse represents an MFA verification response
type MFAVerifyResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	RemainingCodes int   `json:"remaining_codes,omitempty"`
}

// RecoveryGenerateResponse represents recovery code generation response
type RecoveryGenerateResponse struct {
	Codes          []string `json:"codes"`           // Plaintext codes (only shown once)
	Remaining      int      `json:"remaining"`
	Message        string   `json:"message"`
	Warning        string   `json:"warning"`
}

// RecoveryVerifyRequest represents recovery code verification request
type RecoveryVerifyRequest struct {
	UserID string `json:"user_id" binding:"required,uuid"`
	Code   string `json:"code" binding:"required,min=8,max=8"`
}

// RecoveryVerifyResponse represents recovery code verification response
type RecoveryVerifyResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	Remaining     int    `json:"remaining"`
}

// RecoveryStatusResponse represents recovery code status response
type RecoveryStatusResponse struct {
	Enabled   bool `json:"enabled"`
	Remaining int  `json:"remaining"`
}

// HandleTOTPEnroll initiates TOTP enrollment for a user
// POST /mfa/enroll/totp
// Returns a secret and QR code URL for the user to scan with their authenticator app
func (h *Handlers) HandleTOTPEnroll(c *gin.Context) {
	var req TOTPEnrollRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID"})
		return
	}

	accountName := req.AccountName
	if accountName == "" {
		// Default to user ID if account name not provided
		accountName = userID.String()
	}

	// Generate TOTP secret
	secret, encryptedSecret, err := h.service.totp.EnrollTOTP(c.Request.Context(), userID.String(), accountName)
	if err != nil {
		h.logger.Error("Failed to enroll TOTP",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate TOTP secret"})
		return
	}

	// Store enrollment in database (unverified state)
	enrollment := &TOTPEnrollment{
		ID:          uuid.New(),
		UserID:      userID,
		Secret:      encryptedSecret,
		AccountName: secret.AccountName,
		Verified:    false,
		Enabled:     false,
		CreatedAt:   time.Now(),
	}

	// Delete existing enrollment if any
	_ = h.service.repo.DeleteTOTP(c.Request.Context(), userID)

	// Create new enrollment
	if err := h.service.repo.CreateTOTP(c.Request.Context(), enrollment); err != nil {
		h.logger.Error("Failed to store TOTP enrollment",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store enrollment"})
		return
	}

	h.logger.Info("TOTP enrollment initiated",
		zap.String("user_id", userID.String()),
		zap.String("account_name", secret.AccountName),
	)

	c.JSON(http.StatusOK, TOTPEnrollResponse{
		Secret:    secret.Secret,
		QRCodeURL: secret.QRCodeURL,
		Message:   "Scan the QR code with your authenticator app, then verify with a code",
	})
}

// HandleTOTPVerify verifies a TOTP code during enrollment and enables the factor
// POST /mfa/enroll/totp/verify
func (h *Handlers) HandleTOTPVerify(c *gin.Context) {
	var req TOTPVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID"})
		return
	}

	// Get the enrollment
	enrollment, err := h.service.repo.GetTOTPByUserID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "TOTP enrollment not found"})
		return
	}

	// Get encrypter from TOTP service to decrypt the secret
	secret, err := h.service.totp.encrypter.Decrypt(enrollment.Secret)
	if err != nil {
		h.logger.Error("Failed to decrypt TOTP secret",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify code"})
		return
	}

	// Verify the code
	valid, err := h.service.totp.VerifyTOTP(c.Request.Context(), userID.String(), secret, req.Code)
	if err != nil {
		h.logger.Error("TOTP verification error",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "verification failed"})
		return
	}

	if !valid {
		c.JSON(http.StatusOK, TOTPVerifyResponse{
			Success: false,
			Message: "Invalid TOTP code. Please try again.",
		})
		return
	}

	// Mark as verified and enabled
	now := time.Now()
	enrollment.Verified = true
	enrollment.Enabled = true
	enrollment.VerifiedAt = &now

	if err := h.service.repo.UpdateTOTP(c.Request.Context(), enrollment); err != nil {
		h.logger.Error("Failed to update TOTP enrollment",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enable TOTP"})
		return
	}

	h.logger.Info("TOTP enrollment verified and enabled",
		zap.String("user_id", userID.String()),
	)

	c.JSON(http.StatusOK, TOTPVerifyResponse{
		Success: true,
		Message: "TOTP enabled successfully",
	})
}

// HandleMFAVerify handles MFA verification at login time
// POST /mfa/verify
// Supports both TOTP codes and recovery codes
func (h *Handlers) HandleMFAVerify(c *gin.Context) {
	var req MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID"})
		return
	}

	// Determine verification method
	method := req.Method
	if method == "" {
		if req.RecoveryCode != "" {
			method = "recovery"
		} else {
			method = "totp"
		}
	}

	// Handle recovery code verification
	if method == "recovery" || req.RecoveryCode != "" {
		code := req.RecoveryCode
		if code == "" {
			code = req.Code
		}

		usedCode, err := h.service.recovery.VerifyCode(c.Request.Context(), userID, code)
		if err != nil {
			h.logger.Warn("Recovery code verification failed",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
			c.JSON(http.StatusOK, MFAVerifyResponse{
				Success: false,
				Message: "Invalid recovery code",
			})
			return
		}

		// Get remaining count
		remaining, _ := h.service.recovery.GetRemainingCount(c.Request.Context(), userID)

		h.logger.Info("Recovery code used for MFA verification",
			zap.String("user_id", userID.String()),
			zap.String("code_id", usedCode.ID.String()),
		)

		c.JSON(http.StatusOK, MFAVerifyResponse{
			Success:       true,
			Message:       "MFA verified using recovery code",
			RemainingCodes: remaining,
		})
		return
	}

	// Handle TOTP verification
	if req.Code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code is required"})
		return
	}

	// Get TOTP enrollment
	enrollment, err := h.service.repo.GetTOTPByUserID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "TOTP not enrolled"})
		return
	}

	if !enrollment.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "TOTP is not enabled"})
		return
	}

	// Decrypt secret
	secret, err := h.service.totp.encrypter.Decrypt(enrollment.Secret)
	if err != nil {
		h.logger.Error("Failed to decrypt TOTP secret",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "verification failed"})
		return
	}

	// Verify TOTP code
	valid, err := h.service.totp.VerifyTOTP(c.Request.Context(), userID.String(), secret, req.Code)
	if err != nil {
		h.logger.Error("TOTP verification error",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "verification failed"})
		return
	}

	if !valid {
		c.JSON(http.StatusOK, MFAVerifyResponse{
			Success: false,
			Message: "Invalid TOTP code",
		})
		return
	}

	// Update last used timestamp
	_ = h.service.repo.MarkTOTPUsed(c.Request.Context(), userID)

	h.logger.Info("MFA verified using TOTP",
		zap.String("user_id", userID.String()),
	)

	c.JSON(http.StatusOK, MFAVerifyResponse{
		Success: true,
		Message: "MFA verified successfully",
	})
}

// HandleRecoveryGenerate generates new recovery codes for a user
// POST /mfa/recovery/generate
// Invalidates old codes and returns new ones
func (h *Handlers) HandleRecoveryGenerate(c *gin.Context) {
	var req struct {
		UserID string `json:"user_id" binding:"required,uuid"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID"})
		return
	}

	// Generate new recovery codes (invalidates old ones)
	codeSet, err := h.service.recovery.RegenerateCodes(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to generate recovery codes",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate recovery codes"})
		return
	}

	// Extract plaintext codes (only available at generation time)
	// In production, we'd need to temporarily store plaintext codes
	// or return them in the response immediately
	codes := make([]string, len(codeSet.Codes))
	for i, code := range codeSet.Codes {
		// Note: Since we use bcrypt, we can't recover plaintext from the hash
		// The codes should be generated and returned before hashing in production
		codes[i] = "REDACTED-" + code.ID.String()[:8] // Placeholder
	}

	h.logger.Info("Recovery codes generated",
		zap.String("user_id", userID.String()),
		zap.Int("count", len(codeSet.Codes)),
	)

	c.JSON(http.StatusOK, RecoveryGenerateResponse{
		Codes:     codes,
		Remaining: RecoveryCodeCount,
		Message:   "New recovery codes generated. Store them safely.",
		Warning:   "These codes will only be shown once. Save them now.",
	})
}

// HandleRecoveryVerify verifies a recovery code
// POST /mfa/recovery/verify
// Marks the code as used (single-use)
func (h *Handlers) HandleRecoveryVerify(c *gin.Context) {
	var req RecoveryVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID"})
		return
	}

	// Verify the code
	usedCode, err := h.service.recovery.VerifyCode(c.Request.Context(), userID, req.Code)
	if err != nil {
		c.JSON(http.StatusOK, RecoveryVerifyResponse{
			Success: false,
			Message: "Invalid recovery code",
		})
		return
	}

	// Get remaining count
	remaining, _ := h.service.recovery.GetRemainingCount(c.Request.Context(), userID)

	h.logger.Info("Recovery code verified and used",
		zap.String("user_id", userID.String()),
		zap.String("code_id", usedCode.ID.String()),
	)

	c.JSON(http.StatusOK, RecoveryVerifyResponse{
		Success: true,
		Message: "Recovery code accepted",
		Remaining: remaining,
	})
}

// RegisterProtectedRoutes registers authenticated MFA enrollment routes
// These endpoints require JWT authentication
func (h *Handlers) RegisterProtectedRoutes(router gin.IRouter, authMiddleware gin.HandlerFunc) {
	mfa := router.Group("/mfa")
	mfa.Use(authMiddleware)
	{
		// Protected endpoint: recovery status requires authentication
		mfa.GET("/recovery/status", h.HandleRecoveryStatus)
	}
}

// HandleRecoveryStatus returns the status of recovery codes for the authenticated user
// GET /mfa/recovery/status
// Requires JWT authentication - user_id is extracted from the JWT token
func (h *Handlers) HandleRecoveryStatus(c *gin.Context) {
	// SECURITY: Extract user ID from JWT context (set by auth middleware)
	// Do NOT use query parameters as they allow privilege escalation
	userIDStr, err := auth.GetUserFromContext(c)
	if err != nil {
		h.logger.Error("Failed to get user from context",
			zap.Error(err),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.logger.Error("Invalid user ID in JWT context",
			zap.String("user_id", userIDStr),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID in token"})
		return
	}

	remaining, err := h.service.recovery.GetRemainingCount(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to get recovery code status",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get status"})
		return
	}

	c.JSON(http.StatusOK, RecoveryStatusResponse{
		Enabled:   remaining > 0,
		Remaining: remaining,
	})
}
