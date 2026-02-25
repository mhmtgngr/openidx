// Package mfa provides WebAuthn/FIDO2 HTTP handlers for OpenIDX
package mfa

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/auth"
)

// WebAuthnHandlers provides HTTP handlers for WebAuthn operations
type WebAuthnHandlers struct {
	service *WebAuthnService
	store   WebAuthnStore
	logger  *zap.Logger
}

// NewWebAuthnHandlers creates new WebAuthn HTTP handlers
func NewWebAuthnHandlers(
	service *WebAuthnService,
	store WebAuthnStore,
	logger *zap.Logger,
) *WebAuthnHandlers {
	return &WebAuthnHandlers{
		service: service,
		store:   store,
		logger:  logger,
	}
}

// RegisterRoutes registers public WebAuthn routes (no authentication required)
// These endpoints are used during registration and login flows
func (h *WebAuthnHandlers) RegisterRoutes(router gin.IRouter) {
	webauthn := router.Group("/mfa/webauthn")
	{
		// Registration endpoints (public - used during user registration)
		webauthn.POST("/register/begin", h.HandleRegisterBegin)
		webauthn.POST("/register/finish", h.HandleRegisterFinish)

		// Login/authentication endpoints (public - used during authentication)
		webauthn.POST("/login/begin", h.HandleLoginBegin)
		webauthn.POST("/login/finish", h.HandleLoginFinish)
	}
}

// RegisterProtectedRoutes registers authenticated WebAuthn credential management routes
// These endpoints require JWT authentication and are protected by RBAC middleware
func (h *WebAuthnHandlers) RegisterProtectedRoutes(router gin.IRouter, authMiddleware gin.HandlerFunc) {
	webauthn := router.Group("/mfa/webauthn")
	{
		// Apply authentication middleware to all credential management endpoints
		webauthn.Use(authMiddleware)

		// Credential management endpoints (authenticated)
		webauthn.GET("/credentials", h.HandleListCredentials)
		webauthn.DELETE("/credentials/:id", h.HandleDeleteCredential)
		webauthn.PUT("/credentials/:id/name", h.HandleRenameCredential)
	}
}

// RegisterBeginRequest is the request for beginning registration
type RegisterBeginRequest struct {
	UserID      uuid.UUID `json:"user_id" binding:"required"`
	Username    string    `json:"username" binding:"required"`
	DisplayName string    `json:"display_name"`
	FriendlyName string   `json:"friendly_name"` // Optional name for the credential
}

// RegisterFinishRequest is the request for finishing registration
type RegisterFinishRequest struct {
	UserID   uuid.UUID `json:"user_id" binding:"required"`
	Response string    `json:"response" binding:"required"` // JSON string of CredentialCreationResponse
}

// LoginBeginRequest is the request for beginning login
type LoginBeginRequest struct {
	UserID uuid.UUID `json:"user_id" binding:"required"`
}

// LoginFinishRequest is the request for finishing login
type LoginFinishRequest struct {
	UserID   uuid.UUID `json:"user_id" binding:"required"`
	Response string    `json:"response" binding:"required"` // JSON string of CredentialAssertionResponse
}

// RegisterBeginResponse is the response for beginning registration
type RegisterBeginResponse struct {
	Options *CredentialCreationOptionsRaw `json:"options"`
	Status  string                        `json:"status"`
	Message string                        `json:"message"`
}

// CredentialCreationOptionsRaw wraps the protocol options for JSON serialization
type CredentialCreationOptionsRaw struct {
	*protocol.CredentialCreation
}

// RegisterFinishResponse is the response for finishing registration
type RegisterFinishResponse struct {
	Success      bool   `json:"success"`
	CredentialID string `json:"credential_id,omitempty"`
	FriendlyName string `json:"friendly_name,omitempty"`
	Message      string `json:"message,omitempty"`
}

// LoginBeginResponse is the response for beginning login
type LoginBeginResponse struct {
	Options *CredentialAssertionOptionsRaw `json:"options"`
	Status  string                         `json:"status"`
	Message string                         `json:"message"`
}

// CredentialAssertionOptionsRaw wraps the protocol options for JSON serialization
type CredentialAssertionOptionsRaw struct {
	*protocol.CredentialAssertion
}

// LoginFinishResponse is the response for finishing login
type LoginFinishResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	FriendlyName string `json:"friendly_name,omitempty"`
}

// CredentialsResponse is the response for listing credentials
type CredentialsResponse struct {
	Credentials []*CredentialInfo `json:"credentials"`
	Count       int               `json:"count"`
}

// CredentialInfo represents information about a credential
type CredentialInfo struct {
	ID            uuid.UUID  `json:"id"`
	CredentialID  string     `json:"credential_id"`
	FriendlyName  string     `json:"friendly_name"`
	Authenticator string     `json:"authenticator"`
	IsPasskey     bool       `json:"is_passkey"`
	BackupEligible bool      `json:"backup_eligible"`
	BackupState   bool       `json:"backup_state"`
	CreatedAt     time.Time  `json:"created_at"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
}

// RenameCredentialRequest is the request for renaming a credential
type RenameCredentialRequest struct {
	FriendlyName string `json:"friendly_name" binding:"required,min=1,max=64"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// HandleRegisterBegin initiates WebAuthn registration
// POST /mfa/webauthn/register/begin
func (h *WebAuthnHandlers) HandleRegisterBegin(c *gin.Context) {
	var req RegisterBeginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// Set default display name if not provided
	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Username
	}

	// Begin registration
	options, err := h.service.BeginRegistration(
		c.Request.Context(),
		req.UserID,
		req.Username,
		displayName,
		req.FriendlyName,
	)
	if err != nil {
		h.logger.Error("Failed to begin WebAuthn registration",
			zap.String("user_id", req.UserID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "failed_to_begin_registration",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, RegisterBeginResponse{
		Options: &CredentialCreationOptionsRaw{options.PublicKey},
		Status:  options.Status,
		Message: options.Message,
	})
}

// HandleRegisterFinish completes WebAuthn registration
// POST /mfa/webauthn/register/finish
func (h *WebAuthnHandlers) HandleRegisterFinish(c *gin.Context) {
	var req RegisterFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// Parse the CredentialCreationResponse from JSON
	var response protocol.CredentialCreationResponse
	if err := parseJSONFromBytes([]byte(req.Response), &response); err != nil {
		h.logger.Error("Failed to parse registration response",
			zap.String("user_id", req.UserID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_response",
			Message: "Failed to parse credential creation response",
		})
		return
	}

	// Finish registration
	credential, err := h.service.FinishRegistration(
		c.Request.Context(),
		req.UserID,
		&response,
	)
	if err != nil {
		h.logger.Error("Failed to finish WebAuthn registration",
			zap.String("user_id", req.UserID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "registration_failed",
			Message: err.Error(),
		})
		return
	}

	h.logger.Info("WebAuthn registration completed",
		zap.String("user_id", req.UserID.String()),
		zap.String("credential_id", credential.CredentialID),
	)

	c.JSON(http.StatusOK, RegisterFinishResponse{
		Success:      true,
		CredentialID: credential.CredentialID,
		FriendlyName: credential.FriendlyName,
		Message:      "Credential registered successfully",
	})
}

// HandleLoginBegin initiates WebAuthn login
// POST /mfa/webauthn/login/begin
func (h *WebAuthnHandlers) HandleLoginBegin(c *gin.Context) {
	var req LoginBeginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// Begin login
	options, err := h.service.BeginLogin(
		c.Request.Context(),
		req.UserID,
	)
	if err != nil {
		h.logger.Error("Failed to begin WebAuthn login",
			zap.String("user_id", req.UserID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "failed_to_begin_login",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, LoginBeginResponse{
		Options: &CredentialAssertionOptionsRaw{options.PublicKey},
		Status:  options.Status,
		Message: options.Message,
	})
}

// HandleLoginFinish completes WebAuthn login
// POST /mfa/webauthn/login/finish
func (h *WebAuthnHandlers) HandleLoginFinish(c *gin.Context) {
	var req LoginFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// Parse the CredentialAssertionResponse from JSON
	var response protocol.CredentialAssertionResponse
	if err := parseJSONFromBytes([]byte(req.Response), &response); err != nil {
		h.logger.Error("Failed to parse login response",
			zap.String("user_id", req.UserID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_response",
			Message: "Failed to parse credential assertion response",
		})
		return
	}

	// Finish login
	credential, err := h.service.FinishLogin(
		c.Request.Context(),
		req.UserID,
		&response,
	)
	if err != nil {
		h.logger.Error("Failed to finish WebAuthn login",
			zap.String("user_id", req.UserID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "authentication_failed",
			Message: err.Error(),
		})
		return
	}

	h.logger.Info("WebAuthn login completed",
		zap.String("user_id", req.UserID.String()),
		zap.String("credential_id", credential.CredentialID),
	)

	c.JSON(http.StatusOK, LoginFinishResponse{
		Success:      true,
		Message:      "Authentication successful",
		CredentialID: credential.CredentialID,
		FriendlyName: credential.FriendlyName,
	})
}

// HandleListCredentials lists all WebAuthn credentials for the authenticated user
// GET /mfa/webauthn/credentials
// Requires JWT authentication - user_id is extracted from the JWT token
func (h *WebAuthnHandlers) HandleListCredentials(c *gin.Context) {
	// Extract user ID from JWT context (set by RBAC middleware)
	userIDStr, err := auth.GetUserFromContext(c)
	if err != nil {
		h.logger.Warn("Failed to get user from context",
			zap.Error(err),
		)
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "authentication_required",
			Message: "Valid JWT token required",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.logger.Error("Invalid user ID in JWT",
			zap.String("user_id", userIDStr),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid user_id in token"})
		return
	}

	// Get credentials for the authenticated user only
	credentials, err := h.store.ListCredentials(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to list credentials",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "failed_to_list_credentials",
		})
		return
	}

	// Convert to response format
	credInfos := make([]*CredentialInfo, len(credentials))
	for i, cred := range credentials {
		authenticator := GetAuthenticatorInfo(cred.AAGUID)

		credInfos[i] = &CredentialInfo{
			ID:             cred.ID,
			CredentialID:   cred.CredentialID,
			FriendlyName:   cred.FriendlyName,
			Authenticator:  authenticator.Name,
			IsPasskey:      authenticator.IsPasskey,
			BackupEligible: cred.BackupEligible,
			BackupState:    cred.BackupState,
			CreatedAt:      cred.CreatedAt,
			LastUsedAt:     cred.LastUsedAt,
		}
	}

	c.JSON(http.StatusOK, CredentialsResponse{
		Credentials: credInfos,
		Count:       len(credInfos),
	})
}

// HandleDeleteCredential deletes a WebAuthn credential
// DELETE /mfa/webauthn/credentials/:id
// Requires JWT authentication - verifies the authenticated user owns the credential
func (h *WebAuthnHandlers) HandleDeleteCredential(c *gin.Context) {
	// Parse credential ID from path
	credentialID := c.Param("id")
	if credentialID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "credential_id is required"})
		return
	}

	// Extract authenticated user ID from JWT context
	userIDStr, err := auth.GetUserFromContext(c)
	if err != nil {
		h.logger.Warn("Failed to get user from context",
			zap.Error(err),
		)
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "authentication_required",
			Message: "Valid JWT token required",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.logger.Error("Invalid user ID in JWT",
			zap.String("user_id", userIDStr),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid user_id in token"})
		return
	}

	// Verify ownership before deletion - get the credential first
	cred, err := h.store.GetCredentialByID(c.Request.Context(), credentialID)
	if err != nil {
		h.logger.Error("Failed to get credential for ownership check",
			zap.String("credential_id", credentialID),
			zap.Error(err),
		)
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "credential_not_found",
		})
		return
	}

	// Verify the authenticated user owns this credential
	if cred.UserID != userID {
		h.logger.Warn("Attempted deletion of credential owned by another user",
			zap.String("authenticated_user_id", userID.String()),
			zap.String("credential_owner_id", cred.UserID.String()),
			zap.String("credential_id", credentialID),
		)
		c.JSON(http.StatusForbidden, ErrorResponse{
			Error:   "access_denied",
			Message: "You do not have permission to delete this credential",
		})
		return
	}

	// Delete credential with ownership verified
	err = h.store.DeleteCredentialByCredentialID(c.Request.Context(), credentialID, userID)
	if err != nil {
		h.logger.Error("Failed to delete credential",
			zap.String("user_id", userID.String()),
			zap.String("credential_id", credentialID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "failed_to_delete_credential",
		})
		return
	}

	h.logger.Info("WebAuthn credential deleted",
		zap.String("user_id", userID.String()),
		zap.String("credential_id", credentialID),
	)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Credential deleted successfully",
	})
}

// HandleRenameCredential renames a WebAuthn credential
// PUT /mfa/webauthn/credentials/:id/name
// Requires JWT authentication - verifies the authenticated user owns the credential
func (h *WebAuthnHandlers) HandleRenameCredential(c *gin.Context) {
	// Parse credential ID from path
	credentialID := c.Param("id")
	if credentialID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "credential_id is required"})
		return
	}

	// Extract authenticated user ID from JWT context
	userIDStr, err := auth.GetUserFromContext(c)
	if err != nil {
		h.logger.Warn("Failed to get user from context",
			zap.Error(err),
		)
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "authentication_required",
			Message: "Valid JWT token required",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.logger.Error("Invalid user ID in JWT",
			zap.String("user_id", userIDStr),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid user_id in token"})
		return
	}

	var req RenameCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// Get the credential for ownership verification
	cred, err := h.store.GetCredentialByID(c.Request.Context(), credentialID)
	if err != nil {
		h.logger.Error("Failed to get credential",
			zap.String("credential_id", credentialID),
			zap.Error(err),
		)
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "credential_not_found",
		})
		return
	}

	// Verify ownership - check if the authenticated user owns this credential
	if cred.UserID != userID {
		h.logger.Warn("Attempted rename of credential owned by another user",
			zap.String("authenticated_user_id", userID.String()),
			zap.String("credential_owner_id", cred.UserID.String()),
			zap.String("credential_id", credentialID),
		)
		c.JSON(http.StatusForbidden, ErrorResponse{
			Error:   "access_denied",
			Message: "You do not have permission to modify this credential",
		})
		return
	}

	// Update friendly name
	cred.FriendlyName = req.FriendlyName

	if err := h.store.UpdateCredential(c.Request.Context(), cred); err != nil {
		h.logger.Error("Failed to update credential",
			zap.String("user_id", userID.String()),
			zap.String("credential_id", credentialID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "failed_to_update_credential",
		})
		return
	}

	h.logger.Info("WebAuthn credential renamed",
		zap.String("user_id", userID.String()),
		zap.String("credential_id", credentialID),
		zap.String("new_name", req.FriendlyName),
	)

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"message":       "Credential renamed successfully",
		"friendly_name": req.FriendlyName,
	})
}

// parseJSONFromBytes parses JSON from a byte slice
// This helper is needed because the go-webauthn library uses custom JSON unmarshaling
func parseJSONFromBytes(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// GetUserIDFromContext is a helper that extracts user ID from context
// This is a convenience wrapper around auth.GetUserFromContext
func GetUserIDFromContext(c *gin.Context) (uuid.UUID, error) {
	userIDStr, err := auth.GetUserFromContext(c)
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(userIDStr)
}
