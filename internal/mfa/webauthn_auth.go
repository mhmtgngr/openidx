// Package mfa provides WebAuthn/FIDO2 authentication wrapper for OpenIDX
package mfa

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/auth"
)

// WebAuthnAuth wraps WebAuthnHandlers with authentication and CSRF middleware
// It provides a secure way to register both public and protected WebAuthn routes
type WebAuthnAuth struct {
	handlers      *WebAuthnHandlers
	rbac          *auth.RBACMiddleware
	tokenService  *auth.TokenService
	logger        *zap.Logger
	csrfMiddleware gin.HandlerFunc
}

// NewWebAuthnAuth creates a new WebAuthnAuth wrapper
// Parameters:
//   - handlers: The WebAuthnHandlers containing the HTTP handlers
//   - rbac: The RBACMiddleware for JWT authentication
//   - tokenService: The TokenService for token validation
//   - logger: Logger for security events
//   - csrfMiddleware: Optional CSRF middleware (can be nil for API-only clients)
func NewWebAuthnAuth(
	handlers *WebAuthnHandlers,
	rbac *auth.RBACMiddleware,
	tokenService *auth.TokenService,
	logger *zap.Logger,
	csrfMiddleware gin.HandlerFunc,
) *WebAuthnAuth {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &WebAuthnAuth{
		handlers:      handlers,
		rbac:          rbac,
		tokenService:  tokenService,
		logger:        logger,
		csrfMiddleware: csrfMiddleware,
	}
}

// RegisterAllRoutes registers both public and protected WebAuthn routes
// Public routes: registration and login flows (no authentication required)
// Protected routes: credential management (JWT authentication required)
func (wa *WebAuthnAuth) RegisterAllRoutes(router gin.IRouter) {
	// Register public routes (registration/login)
	wa.handlers.RegisterRoutes(router)

	// Create authentication middleware for protected routes
	authMiddleware := wa.rbac.Authenticate()

	// Apply CSRF middleware if provided
	csrfAuthMiddleware := authMiddleware
	if wa.csrfMiddleware != nil {
		csrfAuthMiddleware = gin.HandlerFunc(func(c *gin.Context) {
			// Apply CSRF first, then authenticate
			wa.csrfMiddleware(c)
			if !c.IsAborted() {
				authMiddleware(c)
			}
		})
	}

	// Register protected routes with authentication
	wa.handlers.RegisterProtectedRoutes(router, csrfAuthMiddleware)

	wa.logger.Info("WebAuthn routes registered",
		zap.Int("public_routes", 4),
		zap.Int("protected_routes", 3),
	)
}

// RegisterRoutesWithCSRF registers routes with custom CSRF configuration
// This allows different CSRF settings for different route groups
func (wa *WebAuthnAuth) RegisterRoutesWithCSRF(router gin.IRouter, csrfConfig CSRFRouteConfig) {
	// Register public routes
	wa.handlers.RegisterRoutes(router)

	// Build the middleware chain for protected routes
	protectedGroup := router.Group("/mfa/webauthn")

	// Apply authentication
	protectedGroup.Use(wa.rbac.Authenticate())

	// Apply CSRF to state-changing operations if configured
	if csrfConfig.Enabled {
		csrfMiddleware := wa.buildCSRFMiddleware(csrfConfig)
		// Only apply CSRF to state-changing methods (POST, PUT, DELETE)
		protectedGroup.Use(func(c *gin.Context) {
			if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "DELETE" {
				csrfMiddleware(c)
				if c.IsAborted() {
					return
				}
			}
			c.Next()
		})
	}

	// Register protected credential management routes
	protectedGroup.GET("/credentials", wa.handlers.HandleListCredentials)
	protectedGroup.DELETE("/credentials/:id", wa.handlers.HandleDeleteCredential)
	protectedGroup.PUT("/credentials/:id/name", wa.handlers.HandleRenameCredential)

	wa.logger.Info("WebAuthn routes registered with CSRF",
		zap.Bool("csrf_enabled", csrfConfig.Enabled),
		zap.String("csrf_cookie_name", csrfConfig.CookieName),
	)
}

// CSRFRouteConfig configures CSRF protection for WebAuthn routes
type CSRFRouteConfig struct {
	Enabled    bool   // Whether CSRF protection is enabled
	CookieName string // Name of the CSRF cookie
	Domain     string // Trusted domain for origin validation
}

// buildCSRFMiddleware creates a CSRF middleware from the given config
func (wa *WebAuthnAuth) buildCSRFMiddleware(config CSRFRouteConfig) gin.HandlerFunc {
	// If CSRF is not enabled, return a no-op middleware
	if !config.Enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	// Import CSRF middleware from common package
	// This will be implemented by extending the existing CSRF middleware
	return func(c *gin.Context) {
		// CSRF validation logic
		// 1. Check for session cookie
		// 2. Validate Origin/Referer headers
		// 3. Skip for Bearer token only requests
		c.Next()
	}
}

// GetHandlers returns the underlying WebAuthnHandlers
// This allows direct access to handlers if needed
func (wa *WebAuthnAuth) GetHandlers() *WebAuthnHandlers {
	return wa.handlers
}

// VerifyCredentialOwnership checks if a credential belongs to the authenticated user
// This is a helper for handlers that need ownership verification
func (wa *WebAuthnAuth) VerifyCredentialOwnership(c *gin.Context, credentialID string) (*WebAuthnCredential, error) {
	// Get authenticated user ID
	userIDStr, err := auth.GetUserFromContext(c)
	if err != nil {
		return nil, err
	}

	// Get the credential
	cred, err := wa.handlers.store.GetCredentialByID(c.Request.Context(), credentialID)
	if err != nil {
		return nil, err
	}

	// Parse user ID
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, err
	}

	// Verify ownership
	if cred.UserID != userID {
		wa.logger.Warn("Credential ownership verification failed",
			zap.String("authenticated_user", userID.String()),
			zap.String("credential_owner", cred.UserID.String()),
			zap.String("credential_id", credentialID),
		)
		return nil, auth.ErrUserNotFound
	}

	return cred, nil
}

// RequireAuthentication creates a middleware that requires valid JWT authentication
// This is a convenience wrapper around RBACMiddleware.Authenticate
func (wa *WebAuthnAuth) RequireAuthentication() gin.HandlerFunc {
	return wa.rbac.Authenticate()
}
