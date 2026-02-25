// Package mfa provides unit tests for WebAuthn authentication wrapper
package mfa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/auth"
)

// mockTokenService is a mock implementation of TokenService for testing
type mockTokenService struct {
	validToken   bool
	expiredToken bool
	userID       string
	tenantID     string
	roles        []string
	shouldFail   bool
}

func (m *mockTokenService) ValidateAccessToken(ctx context.Context, tokenString string) (*auth.Claims, error) {
	if m.shouldFail {
		return nil, auth.ErrTokenInvalid
	}
	if m.expiredToken {
		return nil, auth.ErrTokenExpired
	}
	if !m.validToken {
		return nil, auth.ErrTokenInvalid
	}

	return &auth.Claims{
		Subject:   m.userID,
		TenantID:  m.tenantID,
		Roles:     m.roles,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}, nil
}

// TestNewWebAuthnAuth tests the constructor
func TestNewWebAuthnAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)
	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	handlers := NewWebAuthnHandlers(service, store, logger)
	rbac := auth.NewRBACMiddleware(auth.RBACConfig{
		Logger: logger,
	})
	tokenService := &mockTokenService{
		validToken: true,
		userID:     "user123",
	}

	t.Run("valid creation with all parameters", func(t *testing.T) {
		wa, err := NewWebAuthnAuthWithValidator(handlers, rbac, tokenService, logger, nil)
		require.NoError(t, err)

		assert.NotNil(t, wa)
		assert.Equal(t, handlers, wa.handlers)
		assert.Equal(t, rbac, wa.rbac)
		assert.NotNil(t, wa.tokenValidator)
		assert.Nil(t, wa.csrfMiddleware)
	})

	t.Run("valid creation with CSRF middleware", func(t *testing.T) {
		csrfMiddleware := func(c *gin.Context) {}
		wa, err := NewWebAuthnAuthWithValidator(handlers, rbac, tokenService, logger, csrfMiddleware)
		require.NoError(t, err)

		assert.NotNil(t, wa)
		assert.NotNil(t, wa.csrfMiddleware)
	})

	t.Run("MustNewWebAuthnAuthWithValidator panics on nil handlers", func(t *testing.T) {
		assert.Panics(t, func() {
			MustNewWebAuthnAuthWithValidator(nil, rbac, tokenService, logger, nil)
		})
	})

	t.Run("MustNewWebAuthnAuthWithValidator panics on nil rbac", func(t *testing.T) {
		assert.Panics(t, func() {
			MustNewWebAuthnAuthWithValidator(handlers, nil, tokenService, logger, nil)
		})
	})

	t.Run("MustNewWebAuthnAuthWithValidator panics on nil validator", func(t *testing.T) {
		assert.Panics(t, func() {
			MustNewWebAuthnAuthWithValidator(handlers, rbac, nil, logger, nil)
		})
	})

	t.Run("creation with nil logger", func(t *testing.T) {
		wa, err := NewWebAuthnAuthWithValidator(handlers, rbac, tokenService, nil, nil)
		require.NoError(t, err)

		assert.NotNil(t, wa)
		assert.NotNil(t, wa.logger) // Should create nop logger
	})

	t.Run("returns error when handlers is nil", func(t *testing.T) {
		wa, err := NewWebAuthnAuthWithValidator(nil, rbac, tokenService, logger, nil)

		assert.Error(t, err)
		assert.Nil(t, wa)
		assert.Contains(t, err.Error(), "handlers")
	})

	t.Run("returns error when rbac is nil", func(t *testing.T) {
		wa, err := NewWebAuthnAuthWithValidator(handlers, nil, tokenService, logger, nil)

		assert.Error(t, err)
		assert.Nil(t, wa)
		assert.Contains(t, err.Error(), "rbac")
	})

	t.Run("returns error when validator is nil", func(t *testing.T) {
		wa, err := NewWebAuthnAuthWithValidator(handlers, rbac, nil, logger, nil)

		assert.Error(t, err)
		assert.Nil(t, wa)
		assert.Contains(t, err.Error(), "validator")
	})
}

// TestWebAuthnAuth_RegisterAllRoutes tests route registration
func TestWebAuthnAuth_RegisterAllRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)
	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	handlers := NewWebAuthnHandlers(service, store, logger)
	tokenService := &mockTokenService{
		validToken: true,
		userID:     "user123",
	}
	rbac := auth.NewRBACMiddleware(auth.RBACConfig{
		TokenValidator: tokenService,
		Logger:         logger,
	})

	wa := MustNewWebAuthnAuthWithValidator(handlers, rbac, tokenService, logger, nil)

	router := gin.New()
	wa.RegisterAllRoutes(router)

	t.Run("public routes are registered", func(t *testing.T) {
		routes := router.Routes()

		// Check public registration/login routes
		publicRoutes := []string{
			"POST /mfa/webauthn/register/begin",
			"POST /mfa/webauthn/register/finish",
			"POST /mfa/webauthn/login/begin",
			"POST /mfa/webauthn/login/finish",
		}

		routeMap := make(map[string]bool)
		for _, r := range routes {
			routeMap[r.Method+" "+r.Path] = true
		}

		for _, expected := range publicRoutes {
			assert.True(t, routeMap[expected], "Expected route %s not found", expected)
		}
	})

	t.Run("protected routes are registered", func(t *testing.T) {
		routes := router.Routes()

		// Check protected credential management routes
		protectedRoutes := []string{
			"GET /mfa/webauthn/credentials",
			"DELETE /mfa/webauthn/credentials/:id",
			"PUT /mfa/webauthn/credentials/:id/name",
		}

		routeMap := make(map[string]bool)
		for _, r := range routes {
			routeMap[r.Method+" "+r.Path] = true
		}

		for _, expected := range protectedRoutes {
			assert.True(t, routeMap[expected], "Expected route %s not found", expected)
		}
	})
}

// TestWebAuthnAuth_GetHandlers tests the GetHandlers method
func TestWebAuthnAuth_GetHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)
	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	handlers := NewWebAuthnHandlers(service, store, logger)
	rbac := auth.NewRBACMiddleware(auth.RBACConfig{Logger: logger})

	mockValidator := &mockTokenService{validToken: true, userID: "test"}
	wa := MustNewWebAuthnAuthWithValidator(handlers, rbac, mockValidator, logger, nil)

	t.Run("returns the underlying handlers", func(t *testing.T) {
		result := wa.GetHandlers()

		assert.Equal(t, handlers, result)
		assert.Same(t, handlers, result)
	})
}

// TestWebAuthnAuth_VerifyCredentialOwnership tests ownership verification
func TestWebAuthnAuth_VerifyCredentialOwnership(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)
	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	handlers := NewWebAuthnHandlers(service, store, logger)
	rbac := auth.NewRBACMiddleware(auth.RBACConfig{Logger: logger})

	mockValidator := &mockTokenService{validToken: true, userID: "test"}
	wa := MustNewWebAuthnAuthWithValidator(handlers, rbac, mockValidator, logger, nil)

	userID := uuid.New()
	otherUserID := uuid.New()

	// Create credentials
	cred := &WebAuthnCredential{
		ID:           uuid.New(),
		CredentialID: "test-credential-id",
		PublicKey:    []byte("test-public-key"),
		UserID:       userID,
		UserHandle:   userID[:],
		SignCount:    0,
		Transports:   []string{"internal"},
		FriendlyName: "My Passkey",
		CreatedAt:    time.Now(),
	}
	err = store.CreateCredential(context.Background(), cred)
	require.NoError(t, err)

	t.Run("valid ownership verification", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		auth.SetUserID(c, userID.String())
		auth.SetTenantID(c, "tenant1")
		auth.SetRoles(c, []string{"user"})

		result, err := wa.VerifyCredentialOwnership(c, cred.CredentialID)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, userID, result.UserID)
	})

	t.Run("ownership verification fails for different user", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		auth.SetUserID(c, otherUserID.String())
		auth.SetTenantID(c, "tenant1")
		auth.SetRoles(c, []string{"user"})

		result, err := wa.VerifyCredentialOwnership(c, cred.CredentialID)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, auth.ErrUserNotFound)
	})

	t.Run("ownership verification fails with no user in context", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		// No user set in context

		result, err := wa.VerifyCredentialOwnership(c, cred.CredentialID)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, auth.ErrUserNotFound)
	})

	t.Run("ownership verification fails for non-existent credential", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		auth.SetUserID(c, userID.String())
		auth.SetTenantID(c, "tenant1")
		auth.SetRoles(c, []string{"user"})

		result, err := wa.VerifyCredentialOwnership(c, "non-existent-credential")

		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

// TestWebAuthnAuth_RequireAuthentication tests the authentication middleware
func TestWebAuthnAuth_RequireAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)
	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	handlers := NewWebAuthnHandlers(service, store, logger)

	tokenService := &mockTokenService{
		validToken: true,
		userID:     "user123",
	}
	rbac := auth.NewRBACMiddleware(auth.RBACConfig{
		TokenValidator: tokenService,
		Logger:         logger,
	})

	wa := MustNewWebAuthnAuthWithValidator(handlers, rbac, tokenService, logger, nil)

	t.Run("RequireAuthentication returns middleware", func(t *testing.T) {
		middleware := wa.RequireAuthentication()

		assert.NotNil(t, middleware)

		// Test that middleware is a valid gin.HandlerFunc
		router := gin.New()
		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// This should not panic
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should succeed (200) because token is valid
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestWebAuthnAuth_RegisterRoutesWithCSRF tests CSRF route registration
func TestWebAuthnAuth_RegisterRoutesWithCSRF(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)
	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	handlers := NewWebAuthnHandlers(service, store, logger)
	tokenService := &mockTokenService{
		validToken: true,
		userID:     "user123",
	}
	rbac := auth.NewRBACMiddleware(auth.RBACConfig{
		TokenValidator: tokenService,
		Logger:         logger,
	})

	wa := MustNewWebAuthnAuthWithValidator(handlers, rbac, tokenService, logger, nil)

	t.Run("register routes with CSRF enabled", func(t *testing.T) {
		router := gin.New()
		csrfConfig := CSRFRouteConfig{
			Enabled:    true,
			CookieName: "csrf_token",
			Domain:     "localhost",
		}

		wa.RegisterRoutesWithCSRF(router, csrfConfig)

		routes := router.Routes()

		// Verify routes are registered
		routeMap := make(map[string]bool)
		for _, r := range routes {
			routeMap[r.Method+" "+r.Path] = true
		}

		// Should have the protected routes
		assert.True(t, routeMap["GET /mfa/webauthn/credentials"])
		assert.True(t, routeMap["DELETE /mfa/webauthn/credentials/:id"])
		assert.True(t, routeMap["PUT /mfa/webauthn/credentials/:id/name"])
	})

	t.Run("register routes with CSRF disabled", func(t *testing.T) {
		router := gin.New()
		csrfConfig := CSRFRouteConfig{
			Enabled:    false,
			CookieName: "",
			Domain:     "",
		}

		wa.RegisterRoutesWithCSRF(router, csrfConfig)

		routes := router.Routes()

		// Verify routes are still registered
		routeMap := make(map[string]bool)
		for _, r := range routes {
			routeMap[r.Method+" "+r.Path] = true
		}

		// Should have the protected routes even without CSRF
		assert.True(t, routeMap["GET /mfa/webauthn/credentials"])
		assert.True(t, routeMap["DELETE /mfa/webauthn/credentials/:id"])
		assert.True(t, routeMap["PUT /mfa/webauthn/credentials/:id/name"])
	})
}

// TestCSRFRouteConfig tests the CSRF configuration struct
func TestCSRFRouteConfig(t *testing.T) {
	t.Run("create CSRF config with all fields", func(t *testing.T) {
		config := CSRFRouteConfig{
			Enabled:    true,
			CookieName: "csrf_cookie",
			Domain:     "example.com",
		}

		assert.True(t, config.Enabled)
		assert.Equal(t, "csrf_cookie", config.CookieName)
		assert.Equal(t, "example.com", config.Domain)
	})

	t.Run("create empty CSRF config", func(t *testing.T) {
		config := CSRFRouteConfig{}

		assert.False(t, config.Enabled)
		assert.Empty(t, config.CookieName)
		assert.Empty(t, config.Domain)
	})
}

// TestWebAuthnAuth_Integration tests integration scenarios
func TestWebAuthnAuth_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)
	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	handlers := NewWebAuthnHandlers(service, store, logger)

	t.Run("full request flow with valid authentication", func(t *testing.T) {
		userID := uuid.New()

		// Create a credential for the user
		cred := &WebAuthnCredential{
			ID:           uuid.New(),
			CredentialID: "test-credential-id",
			PublicKey:    []byte("test-public-key"),
			UserID:       userID,
			UserHandle:   userID[:],
			SignCount:    0,
			Transports:   []string{"internal"},
			FriendlyName: "My Passkey",
			CreatedAt:    time.Now(),
		}
		err = store.CreateCredential(context.Background(), cred)
		require.NoError(t, err)

		// Generate a valid JWT token for the user
		tokenService := &mockTokenService{
			validToken: true,
			userID:     userID.String(),
			tenantID:   "tenant1",
			roles:      []string{"user"},
		}

		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: tokenService,
			Logger:         logger,
		})

		wa := MustNewWebAuthnAuthWithValidator(handlers, rbac, tokenService, logger, nil)

		router := gin.New()
		wa.RegisterAllRoutes(router)

		// Test GET /mfa/webauthn/credentials
		req := httptest.NewRequest("GET", "/mfa/webauthn/credentials", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "My Passkey")
	})

	t.Run("protected endpoint returns 401 without auth", func(t *testing.T) {
		tokenService := &mockTokenService{
			validToken: false,
			userID:     "user123",
		}

		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: tokenService,
			Logger:         logger,
		})

		wa := MustNewWebAuthnAuthWithValidator(handlers, rbac, tokenService, logger, nil)

		router := gin.New()
		wa.RegisterAllRoutes(router)

		// Test GET /mfa/webauthn/credentials without auth
		req := httptest.NewRequest("GET", "/mfa/webauthn/credentials", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("protected endpoint returns 401 with expired token", func(t *testing.T) {
		tokenService := &mockTokenService{
			validToken:   false,
			expiredToken: true,
			userID:       "user123",
		}

		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: tokenService,
			Logger:         logger,
		})

		wa := MustNewWebAuthnAuthWithValidator(handlers, rbac, tokenService, logger, nil)

		router := gin.New()
		wa.RegisterAllRoutes(router)

		req := httptest.NewRequest("GET", "/mfa/webauthn/credentials", nil)
		req.Header.Set("Authorization", "Bearer expired-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// TestWebAuthnAuth_MultipleUsers tests credential isolation between users
func TestWebAuthnAuth_MultipleUsers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)
	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	handlers := NewWebAuthnHandlers(service, store, logger)

	// Create two users with different credentials
	user1ID := uuid.New()
	user2ID := uuid.New()

	cred1 := &WebAuthnCredential{
		ID:           uuid.New(),
		CredentialID: "user1-credential",
		PublicKey:    []byte("user1-key"),
		UserID:       user1ID,
		UserHandle:   user1ID[:],
		SignCount:    0,
		Transports:   []string{"internal"},
		FriendlyName: "User 1 Passkey",
		CreatedAt:    time.Now(),
	}
	err = store.CreateCredential(context.Background(), cred1)
	require.NoError(t, err)

	cred2 := &WebAuthnCredential{
		ID:           uuid.New(),
		CredentialID: "user2-credential",
		PublicKey:    []byte("user2-key"),
		UserID:       user2ID,
		UserHandle:   user2ID[:],
		SignCount:    0,
		Transports:   []string{"internal"},
		FriendlyName: "User 2 Passkey",
		CreatedAt:    time.Now(),
	}
	err = store.CreateCredential(context.Background(), cred2)
	require.NoError(t, err)

	t.Run("user1 can only see their own credentials", func(t *testing.T) {
		tokenService := &mockTokenService{
			validToken: true,
			userID:     user1ID.String(),
			tenantID:   "tenant1",
			roles:      []string{"user"},
		}

		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: tokenService,
			Logger:         logger,
		})

		wa := MustNewWebAuthnAuthWithValidator(handlers, rbac, tokenService, logger, nil)

		router := gin.New()
		wa.RegisterAllRoutes(router)

		req := httptest.NewRequest("GET", "/mfa/webauthn/credentials", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "User 1 Passkey")
		assert.NotContains(t, w.Body.String(), "User 2 Passkey")
	})

	t.Run("user2 can only see their own credentials", func(t *testing.T) {
		tokenService := &mockTokenService{
			validToken: true,
			userID:     user2ID.String(),
			tenantID:   "tenant1",
			roles:      []string{"user"},
		}

		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: tokenService,
			Logger:         logger,
		})

		wa := MustNewWebAuthnAuthWithValidator(handlers, rbac, tokenService, logger, nil)

		router := gin.New()
		wa.RegisterAllRoutes(router)

		req := httptest.NewRequest("GET", "/mfa/webauthn/credentials", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "User 2 Passkey")
		assert.NotContains(t, w.Body.String(), "User 1 Passkey")
	})
}

// Benchmark_WebAuthnAuth_VerifyOwnership benchmarks ownership verification
func Benchmark_WebAuthnAuth_VerifyOwnership(b *testing.B) {
	gin.SetMode(gin.TestMode)

	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)
	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, _ := NewWebAuthnService(config, store, logger)

	handlers := NewWebAuthnHandlers(service, store, logger)
	rbac := auth.NewRBACMiddleware(auth.RBACConfig{Logger: logger})

	mockValidator := &mockTokenService{validToken: true, userID: "test"}
	wa := MustNewWebAuthnAuthWithValidator(handlers, rbac, mockValidator, logger, nil)

	userID := uuid.New()
	cred := &WebAuthnCredential{
		ID:           uuid.New(),
		CredentialID: "bench-credential",
		PublicKey:    []byte("bench-key"),
		UserID:       userID,
		UserHandle:   userID[:],
		SignCount:    0,
		Transports:   []string{"internal"},
		FriendlyName: "Bench Passkey",
		CreatedAt:    time.Now(),
	}
	store.CreateCredential(context.Background(), cred)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	auth.SetUserID(c, userID.String())
	auth.SetTenantID(c, "tenant1")
	auth.SetRoles(c, []string{"user"})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = wa.VerifyCredentialOwnership(c, cred.CredentialID)
	}
}
