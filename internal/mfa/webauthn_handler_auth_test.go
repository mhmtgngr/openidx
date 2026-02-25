// Package mfa provides unit tests for WebAuthn handler authentication scenarios
package mfa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/middleware"
)

// mockValidatorForHandlers is a mock token validator for handler tests
type mockValidatorForHandlers struct {
	validToken   bool
	expiredToken bool
	invalidToken bool
	userID       string
	tenantID     string
	roles        []string
}

func (m *mockValidatorForHandlers) ValidateAccessToken(ctx context.Context, tokenString string) (*auth.Claims, error) {
	if m.invalidToken {
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

// setupAuthenticatedRouter creates a router with authenticated WebAuthn routes
func setupAuthenticatedRouter(t *testing.T, validator auth.TokenValidator) *gin.Engine {
	gin.SetMode(gin.TestMode)

	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)
	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	handlers := NewWebAuthnHandlers(service, store, logger)

	rbac := auth.NewRBACMiddleware(auth.RBACConfig{
		TokenValidator: validator,
		Logger:         logger,
	})

	router := gin.New()
	handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

	return router
}

// TestHandleListCredentials_AuthenticationScenarios tests various authentication scenarios
func TestHandleListCredentials_AuthenticationScenarios(t *testing.T) {
	t.Run("returns 401 when authorization header is missing", func(t *testing.T) {
		validator := &mockValidatorForHandlers{validToken: true}
		router := setupAuthenticatedRouter(t, validator)

		req := httptest.NewRequest("GET", "/mfa/webauthn/credentials", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var resp ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "missing authorization header", resp.Error)
	})

	t.Run("returns 401 when authorization header format is invalid", func(t *testing.T) {
		validator := &mockValidatorForHandlers{validToken: true}
		router := setupAuthenticatedRouter(t, validator)

		req := httptest.NewRequest("GET", "/mfa/webauthn/credentials", nil)
		req.Header.Set("Authorization", "InvalidFormat token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 401 when token is expired", func(t *testing.T) {
		validator := &mockValidatorForHandlers{
			validToken:   false,
			expiredToken: true,
		}
		router := setupAuthenticatedRouter(t, validator)

		req := httptest.NewRequest("GET", "/mfa/webauthn/credentials", nil)
		req.Header.Set("Authorization", "Bearer expired-token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var resp ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "token is expired", resp.Error)
	})

	t.Run("returns 401 when token is invalid", func(t *testing.T) {
		validator := &mockValidatorForHandlers{
			validToken:   false,
			invalidToken: true,
		}
		router := setupAuthenticatedRouter(t, validator)

		req := httptest.NewRequest("GET", "/mfa/webauthn/credentials", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var resp ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "invalid token", resp.Error)
	})

	t.Run("returns empty list for authenticated user with no credentials", func(t *testing.T) {
		userID := uuid.New()
		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     userID.String(),
			tenantID:   "tenant1",
		}
		router := setupAuthenticatedRouter(t, validator)

		req := httptest.NewRequest("GET", "/mfa/webauthn/credentials", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CredentialsResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Empty(t, resp.Credentials)
		assert.Equal(t, 0, resp.Count)
	})

	t.Run("returns user's credentials for authenticated user", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		logger := zap.NewNop()
		store := NewInMemoryWebAuthnStore(logger)

		userID := uuid.New()
		cred := &WebAuthnCredential{
			ID:           uuid.New(),
			CredentialID: "test-credential-id",
			PublicKey:    []byte("test-public-key"),
			UserID:       userID,
			UserHandle:   userID[:],
			SignCount:    5,
			Transports:   []string{"internal"},
			FriendlyName: "My Passkey",
			CreatedAt:    time.Now(),
		}
		err := store.CreateCredential(context.Background(), cred)
		require.NoError(t, err)

		config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
		service, err := NewWebAuthnService(config, store, logger)
		require.NoError(t, err)

		handlers := NewWebAuthnHandlers(service, store, logger)

		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     userID.String(),
			tenantID:   "tenant1",
		}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		router := gin.New()
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		req := httptest.NewRequest("GET", "/mfa/webauthn/credentials", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CredentialsResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Len(t, resp.Credentials, 1)
		assert.Equal(t, "My Passkey", resp.Credentials[0].FriendlyName)
		assert.Equal(t, 1, resp.Count)
	})

	t.Run("returns 400 when user ID in token is invalid UUID", func(t *testing.T) {
		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     "not-a-valid-uuid",
			tenantID:   "tenant1",
		}
		router := setupAuthenticatedRouter(t, validator)

		req := httptest.NewRequest("GET", "/mfa/webauthn/credentials", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "invalid user_id in token", resp.Error)
	})
}

// TestHandleDeleteCredential_AuthenticationAndOwnership tests delete with auth and ownership
func TestHandleDeleteCredential_AuthenticationAndOwnership(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)
	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	handlers := NewWebAuthnHandlers(service, store, logger)

	userID := uuid.New()
	otherUserID := uuid.New()

	cred := &WebAuthnCredential{
		ID:           uuid.New(),
		CredentialID: "cred-to-delete",
		PublicKey:    []byte("test-public-key"),
		UserID:       userID,
		UserHandle:   userID[:],
		SignCount:    0,
		Transports:   []string{"internal"},
		FriendlyName: "Deletable Passkey",
		CreatedAt:    time.Now(),
	}
	err = store.CreateCredential(context.Background(), cred)
	require.NoError(t, err)

	t.Run("requires authentication", func(t *testing.T) {
		validator := &mockValidatorForHandlers{validToken: true}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		router := gin.New()
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		req := httptest.NewRequest("DELETE", "/mfa/webauthn/credentials/cred-to-delete", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 404 when credential does not exist", func(t *testing.T) {
		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     userID.String(),
			tenantID:   "tenant1",
		}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		router := gin.New()
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		req := httptest.NewRequest("DELETE", "/mfa/webauthn/credentials/non-existent", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns 403 when user does not own the credential", func(t *testing.T) {
		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     otherUserID.String(),
			tenantID:   "tenant1",
		}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		router := gin.New()
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		req := httptest.NewRequest("DELETE", "/mfa/webauthn/credentials/cred-to-delete", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)

		var resp ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "access_denied", resp.Error)
		assert.Contains(t, resp.Message, "permission")
	})

	t.Run("deletes credential when user owns it", func(t *testing.T) {
		// Create a fresh credential for this test
		deleteCred := &WebAuthnCredential{
			ID:           uuid.New(),
			CredentialID: "cred-to-delete-success",
			PublicKey:    []byte("test-public-key"),
			UserID:       userID,
			UserHandle:   userID[:],
			SignCount:    0,
			Transports:   []string{"internal"},
			FriendlyName: "Delete Success",
			CreatedAt:    time.Now(),
		}
		err = store.CreateCredential(context.Background(), deleteCred)
		require.NoError(t, err)

		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     userID.String(),
			tenantID:   "tenant1",
		}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		router := gin.New()
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		req := httptest.NewRequest("DELETE", "/mfa/webauthn/credentials/cred-to-delete-success", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp["success"].(bool))

		// Verify credential is deleted
		_, err = store.GetCredentialByID(context.Background(), "cred-to-delete-success")
		assert.Error(t, err)
	})
}

// TestHandleRenameCredential_AuthenticationAndOwnership tests rename with auth and ownership
func TestHandleRenameCredential_AuthenticationAndOwnership(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)
	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	handlers := NewWebAuthnHandlers(service, store, logger)

	userID := uuid.New()
	otherUserID := uuid.New()

	cred := &WebAuthnCredential{
		ID:           uuid.New(),
		CredentialID: "cred-to-rename",
		PublicKey:    []byte("test-public-key"),
		UserID:       userID,
		UserHandle:   userID[:],
		SignCount:    0,
		Transports:   []string{"internal"},
		FriendlyName: "Original Name",
		CreatedAt:    time.Now(),
	}
	err = store.CreateCredential(context.Background(), cred)
	require.NoError(t, err)

	t.Run("requires authentication", func(t *testing.T) {
		validator := &mockValidatorForHandlers{validToken: true}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		router := gin.New()
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/cred-to-rename/name", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 400 for invalid request body", func(t *testing.T) {
		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     userID.String(),
			tenantID:   "tenant1",
		}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		router := gin.New()
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/cred-to-rename/name", strings.NewReader("invalid json"))
		req.Header.Set("Authorization", "Bearer valid-token")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 404 when credential does not exist", func(t *testing.T) {
		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     userID.String(),
			tenantID:   "tenant1",
		}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		router := gin.New()
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		body := `{"friendly_name": "New Name"}`
		req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/non-existent/name", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer valid-token")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns 403 when user does not own the credential", func(t *testing.T) {
		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     otherUserID.String(),
			tenantID:   "tenant1",
		}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		router := gin.New()
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		body := `{"friendly_name": "Hacker Name"}`
		req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/cred-to-rename/name", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer valid-token")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)

		var resp ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "access_denied", resp.Error)
	})

	t.Run("renames credential when user owns it", func(t *testing.T) {
		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     userID.String(),
			tenantID:   "tenant1",
		}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		router := gin.New()
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		newName := "Renamed Passkey"
		body := `{"friendly_name": "` + newName + `"}`
		req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/cred-to-rename/name", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer valid-token")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp["success"].(bool))
		assert.Equal(t, newName, resp["friendly_name"])

		// Verify name was changed
		updated, err := store.GetCredentialByID(context.Background(), "cred-to-rename")
		require.NoError(t, err)
		assert.Equal(t, newName, updated.FriendlyName)
	})

	t.Run("validates friendly name length", func(t *testing.T) {
		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     userID.String(),
			tenantID:   "tenant1",
		}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		router := gin.New()
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		// Empty name should fail validation
		body := `{"friendly_name": ""}`
		req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/cred-to-rename/name", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer valid-token")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestCSRFProtection_Scenarios tests CSRF bypass protection attempts
func TestCSRFProtection_Scenarios(t *testing.T) {
	t.Run("CSRF token validation for state-changing operations", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		logger := zap.NewNop()
		store := NewInMemoryWebAuthnStore(logger)
		config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
		service, err := NewWebAuthnService(config, store, logger)
		require.NoError(t, err)

		handlers := NewWebAuthnHandlers(service, store, logger)

		userID := uuid.New()
		cred := &WebAuthnCredential{
			ID:           uuid.New(),
			CredentialID: "csrf-test-cred",
			PublicKey:    []byte("test-public-key"),
			UserID:       userID,
			UserHandle:   userID[:],
			SignCount:    0,
			Transports:   []string{"internal"},
			FriendlyName: "CSRF Test",
			CreatedAt:    time.Now(),
		}
		err = store.CreateCredential(context.Background(), cred)
		require.NoError(t, err)

		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     userID.String(),
			tenantID:   "tenant1",
		}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		router := gin.New()
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		// Note: In a real implementation with CSRF middleware, this would fail
		// without CSRF token. For now, we verify the route exists and requires auth
		t.Run("DELETE requires auth even without CSRF", func(t *testing.T) {
			req := httptest.NewRequest("DELETE", "/mfa/webauthn/credentials/csrf-test-cred", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})

		t.Run("PUT requires auth even without CSRF", func(t *testing.T) {
			body := `{"friendly_name": "Test"}`
			req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/csrf-test-cred/name", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	})

	t.Run("Bearer-only requests bypass CSRF check", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		logger := zap.NewNop()
		store := NewInMemoryWebAuthnStore(logger)
		config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
		service, err := NewWebAuthnService(config, store, logger)
		require.NoError(t, err)

		handlers := NewWebAuthnHandlers(service, store, logger)

		userID := uuid.New()
		cred := &WebAuthnCredential{
			ID:           uuid.New(),
			CredentialID: "bearer-csrf-cred",
			PublicKey:    []byte("test-public-key"),
			UserID:       userID,
			UserHandle:   userID[:],
			SignCount:    0,
			Transports:   []string{"internal"},
			FriendlyName: "Bearer CSRF Test",
			CreatedAt:    time.Now(),
		}
		err = store.CreateCredential(context.Background(), cred)
		require.NoError(t, err)

		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     userID.String(),
			tenantID:   "tenant1",
		}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		// Create CSRF middleware with session cookie checking
		csrfConfig := middleware.CSRFConfig{
			Enabled:           true,
			TrustedDomain:     "localhost",
			SessionCookieNames: []string{"_openidx_mfa_session"},
		}
		csrfMiddleware := middleware.CSRFProtection(csrfConfig, logger)

		// Chain CSRF and auth middleware
		router := gin.New()

		// Apply CSRF then auth
		router.Use(func(c *gin.Context) {
			// Only apply CSRF to state-changing methods
			if c.Request.Method == "DELETE" || c.Request.Method == "PUT" || c.Request.Method == "POST" {
				csrfMiddleware(c)
				if c.IsAborted() {
					return
				}
			}
			c.Next()
		})

		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		t.Run("Bearer token request with valid Origin header succeeds", func(t *testing.T) {
			body := `{"friendly_name": "Updated Name"}`
			req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/bearer-csrf-cred/name", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Origin", "http://localhost:8080")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			// Should succeed because:
			// 1. No session cookie present (Bearer-only request)
			// 2. Origin header is valid
			assert.Equal(t, http.StatusOK, w.Code)

			var resp map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.True(t, resp["success"].(bool))
		})

		t.Run("Bearer token request with valid Referer header succeeds", func(t *testing.T) {
			// Create another credential for this test
			cred2 := &WebAuthnCredential{
				ID:           uuid.New(),
				CredentialID: "referer-test-cred",
				PublicKey:    []byte("test-public-key"),
				UserID:       userID,
				UserHandle:   userID[:],
				SignCount:    0,
				Transports:   []string{"internal"},
				FriendlyName: "Referer Test",
				CreatedAt:    time.Now(),
			}
			err = store.CreateCredential(context.Background(), cred2)
			require.NoError(t, err)

			body := `{"friendly_name": "Updated Via Referer"}`
			req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/referer-test-cred/name", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Referer", "http://localhost:8080/test")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			// Should succeed because:
			// 1. No session cookie present (Bearer-only request)
			// 2. Referer header is valid (fallback when Origin is missing)
			assert.Equal(t, http.StatusOK, w.Code)
		})

		t.Run("Bearer token request without Origin or Referer succeeds when no session cookie", func(t *testing.T) {
			// This test verifies that Bearer-only requests (no session cookie)
			// are allowed even without Origin/Referer headers
			// This is intentional: API clients using Bearer tokens don't always send Origin/Referer
			cred3 := &WebAuthnCredential{
				ID:           uuid.New(),
				CredentialID: "no-origin-cred",
				PublicKey:    []byte("test-public-key"),
				UserID:       userID,
				UserHandle:   userID[:],
				SignCount:    0,
				Transports:   []string{"internal"},
				FriendlyName: "No Origin Test",
				CreatedAt:    time.Now(),
			}
			err = store.CreateCredential(context.Background(), cred3)
			require.NoError(t, err)

			body := `{"friendly_name": "API Client Works"}`
			req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/no-origin-cred/name", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer valid-token")
			// No Origin or Referer header - typical for API clients
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			// Should succeed because no session cookie means this is an API client
			// API clients using Bearer tokens are inherently CSRF-safe
			assert.Equal(t, http.StatusOK, w.Code)

			var resp map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.True(t, resp["success"].(bool))
		})

		t.Run("Bearer token request with invalid Origin is blocked when session cookie present", func(t *testing.T) {
			cred4 := &WebAuthnCredential{
				ID:           uuid.New(),
				CredentialID: "invalid-origin-cred",
				PublicKey:    []byte("test-public-key"),
				UserID:       userID,
				UserHandle:   userID[:],
				SignCount:    0,
				Transports:   []string{"internal"},
				FriendlyName: "Invalid Origin Test",
				CreatedAt:    time.Now(),
			}
			err = store.CreateCredential(context.Background(), cred4)
			require.NoError(t, err)

			body := `{"friendly_name": "Attack Attempt"}`
			req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/invalid-origin-cred/name", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Origin", "http://evil.com")
			// Add session cookie - this triggers CSRF protection
			req.AddCookie(&http.Cookie{Name: "_openidx_mfa_session", Value: "session123"})
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			// Should be blocked because Origin is from untrusted domain AND session cookie is present
			assert.Equal(t, http.StatusForbidden, w.Code)
		})

		t.Run("Bearer token request with invalid Referer is blocked when session cookie present", func(t *testing.T) {
			cred5 := &WebAuthnCredential{
				ID:           uuid.New(),
				CredentialID: "invalid-referer-cred",
				PublicKey:    []byte("test-public-key"),
				UserID:       userID,
				UserHandle:   userID[:],
				SignCount:    0,
				Transports:   []string{"internal"},
				FriendlyName: "Invalid Referer Test",
				CreatedAt:    time.Now(),
			}
			err = store.CreateCredential(context.Background(), cred5)
			require.NoError(t, err)

			body := `{"friendly_name": "Attack Via Referer"}`
			req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/invalid-referer-cred/name", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Referer", "http://evil.com/attack")
			// Add session cookie - this triggers CSRF protection
			req.AddCookie(&http.Cookie{Name: "_openidx_mfa_session", Value: "session123"})
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			// Should be blocked because Referer is from untrusted domain AND session cookie is present
			assert.Equal(t, http.StatusForbidden, w.Code)
		})

		t.Run("Bearer token with valid Origin and session cookie succeeds", func(t *testing.T) {
			cred6 := &WebAuthnCredential{
				ID:           uuid.New(),
				CredentialID: "valid-origin-session-cred",
				PublicKey:    []byte("test-public-key"),
				UserID:       userID,
				UserHandle:   userID[:],
				SignCount:    0,
				Transports:   []string{"internal"},
				FriendlyName: "Valid Origin With Session",
				CreatedAt:    time.Now(),
			}
			err = store.CreateCredential(context.Background(), cred6)
			require.NoError(t, err)

			body := `{"friendly_name": "Legitimate Browser Request"}`
			req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/valid-origin-session-cred/name", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Origin", "http://localhost:8080")
			// Add session cookie - CSRF validation should pass with valid Origin
			req.AddCookie(&http.Cookie{Name: "_openidx_mfa_session", Value: "session123"})
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			// Should succeed because Origin is valid even with session cookie
			assert.Equal(t, http.StatusOK, w.Code)

			var resp map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.True(t, resp["success"].(bool))
		})

		t.Run("Bearer token with valid Referer and session cookie succeeds", func(t *testing.T) {
			cred7 := &WebAuthnCredential{
				ID:           uuid.New(),
				CredentialID: "valid-referer-session-cred",
				PublicKey:    []byte("test-public-key"),
				UserID:       userID,
				UserHandle:   userID[:],
				SignCount:    0,
				Transports:   []string{"internal"},
				FriendlyName: "Valid Referer With Session",
				CreatedAt:    time.Now(),
			}
			err = store.CreateCredential(context.Background(), cred7)
			require.NoError(t, err)

			body := `{"friendly_name": "Legitimate Browser Request With Referer"}`
			req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/valid-referer-session-cred/name", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Referer", "http://localhost:8080/page")
			// Add session cookie - CSRF validation should pass with valid Referer (fallback)
			req.AddCookie(&http.Cookie{Name: "_openidx_mfa_session", Value: "session123"})
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			// Should succeed because Referer is valid even with session cookie
			assert.Equal(t, http.StatusOK, w.Code)

			var resp map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.True(t, resp["success"].(bool))
		})
	})

	t.Run("Session cookie requests require valid Origin/Referer", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		logger := zap.NewNop()
		store := NewInMemoryWebAuthnStore(logger)
		config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
		service, err := NewWebAuthnService(config, store, logger)
		require.NoError(t, err)

		handlers := NewWebAuthnHandlers(service, store, logger)

		userID := uuid.New()
		cred := &WebAuthnCredential{
			ID:           uuid.New(),
			CredentialID: "session-csrf-cred",
			PublicKey:    []byte("test-public-key"),
			UserID:       userID,
			UserHandle:   userID[:],
			SignCount:    0,
			Transports:   []string{"internal"},
			FriendlyName: "Session CSRF Test",
			CreatedAt:    time.Now(),
		}
		err = store.CreateCredential(context.Background(), cred)
		require.NoError(t, err)

		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     userID.String(),
			tenantID:   "tenant1",
		}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		csrfConfig := middleware.CSRFConfig{
			Enabled:           true,
			TrustedDomain:     "localhost",
			SessionCookieNames: []string{"_openidx_mfa_session"},
		}
		csrfMiddleware := middleware.CSRFProtection(csrfConfig, logger)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			if c.Request.Method == "DELETE" || c.Request.Method == "PUT" || c.Request.Method == "POST" {
				csrfMiddleware(c)
				if c.IsAborted() {
					return
				}
			}
			c.Next()
		})
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		t.Run("Request with session cookie and valid Origin succeeds", func(t *testing.T) {
			body := `{"friendly_name": "Session Updated"}`
			req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/session-csrf-cred/name", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Origin", "http://localhost:8080")
			// Add session cookie
			req.AddCookie(&http.Cookie{Name: "_openidx_mfa_session", Value: "session123"})
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			// Should succeed because session cookie AND valid Origin
			assert.Equal(t, http.StatusOK, w.Code)
		})

		t.Run("Request with session cookie but no Origin/Referer is blocked", func(t *testing.T) {
			cred2 := &WebAuthnCredential{
				ID:           uuid.New(),
				CredentialID: "session-no-origin-cred",
				PublicKey:    []byte("test-public-key"),
				UserID:       userID,
				UserHandle:   userID[:],
				SignCount:    0,
				Transports:   []string{"internal"},
				FriendlyName: "Session No Origin",
				CreatedAt:    time.Now(),
			}
			err = store.CreateCredential(context.Background(), cred2)
			require.NoError(t, err)

			body := `{"friendly_name": "CSRF Attack"}`
			req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/session-no-origin-cred/name", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer valid-token")
			// No Origin or Referer header - potential CSRF attack
			req.AddCookie(&http.Cookie{Name: "_openidx_mfa_session", Value: "session123"})
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			// Should be blocked because session cookie present but no Origin/Referer
			assert.Equal(t, http.StatusForbidden, w.Code)
		})
	})
}

// TestGetUserIDFromContext tests the helper function
func TestGetUserIDFromContext(t *testing.T) {
	t.Run("extracts valid user ID from context", func(t *testing.T) {
		gin.SetMode(gin.TestMode)

		userID := uuid.New()
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		auth.SetUserID(c, userID.String())

		result, err := GetUserIDFromContext(c)

		assert.NoError(t, err)
		assert.Equal(t, userID, result)
	})

	t.Run("returns error when no user in context", func(t *testing.T) {
		gin.SetMode(gin.TestMode)

		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		// No user set

		result, err := GetUserIDFromContext(c)

		assert.Error(t, err)
		assert.Equal(t, uuid.Nil, result)
		assert.ErrorIs(t, err, auth.ErrUserNotFound)
	})

	t.Run("returns error when user ID is invalid UUID", func(t *testing.T) {
		gin.SetMode(gin.TestMode)

		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		auth.SetUserID(c, "not-a-uuid")

		result, err := GetUserIDFromContext(c)

		assert.Error(t, err)
		assert.Equal(t, uuid.Nil, result)
	})
}

// TestCrossUserIsolation tests that users cannot access each other's credentials
func TestCrossUserIsolation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)
	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	handlers := NewWebAuthnHandlers(service, store, logger)

	// Create multiple users with credentials
	users := make([]uuid.UUID, 3)
	credentials := make([]string, 3)

	for i := 0; i < 3; i++ {
		users[i] = uuid.New()
		cred := &WebAuthnCredential{
			ID:           uuid.New(),
			CredentialID: uuid.New().String(),
			PublicKey:    []byte("test-key"),
			UserID:       users[i],
			UserHandle:   users[i][:],
			SignCount:    0,
			Transports:   []string{"internal"},
			FriendlyName: "User " + string(rune('1'+i)) + " Credential",
			CreatedAt:    time.Now(),
		}
		credentials[i] = cred.CredentialID
		err = store.CreateCredential(context.Background(), cred)
		require.NoError(t, err)
	}

	t.Run("user 1 can only see user 1 credentials", func(t *testing.T) {
		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     users[0].String(),
			tenantID:   "tenant1",
		}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		router := gin.New()
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		req := httptest.NewRequest("GET", "/mfa/webauthn/credentials", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CredentialsResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Len(t, resp.Credentials, 1)
		assert.Equal(t, credentials[0], resp.Credentials[0].CredentialID)
	})

	t.Run("user 2 cannot delete user 1 credential", func(t *testing.T) {
		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     users[1].String(),
			tenantID:   "tenant1",
		}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		router := gin.New()
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		req := httptest.NewRequest("DELETE", "/mfa/webauthn/credentials/"+credentials[0], nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("user 3 cannot rename user 2 credential", func(t *testing.T) {
		validator := &mockValidatorForHandlers{
			validToken: true,
			userID:     users[2].String(),
			tenantID:   "tenant1",
		}
		rbac := auth.NewRBACMiddleware(auth.RBACConfig{
			TokenValidator: validator,
			Logger:         logger,
		})

		router := gin.New()
		handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

		body := `{"friendly_name": "Hacked"}`
		req := httptest.NewRequest("PUT", "/mfa/webauthn/credentials/"+credentials[1]+"/name", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer valid-token")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

// Benchmark_HandleListCredentials benchmarks listing credentials
func Benchmark_HandleListCredentials(b *testing.B) {
	gin.SetMode(gin.TestMode)

	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)
	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, _ := NewWebAuthnService(config, store, logger)

	handlers := NewWebAuthnHandlers(service, store, logger)

	userID := uuid.New()

	// Create 100 credentials
	for i := 0; i < 100; i++ {
		cred := &WebAuthnCredential{
			ID:           uuid.New(),
			CredentialID: uuid.New().String(),
			PublicKey:    []byte("test-key"),
			UserID:       userID,
			UserHandle:   userID[:],
			SignCount:    uint32(i),
			Transports:   []string{"internal"},
			FriendlyName: "Credential " + string(rune('0'+i)),
			CreatedAt:    time.Now(),
		}
		store.CreateCredential(context.Background(), cred)
	}

	validator := &mockValidatorForHandlers{
		validToken: true,
		userID:     userID.String(),
		tenantID:   "tenant1",
	}
	rbac := auth.NewRBACMiddleware(auth.RBACConfig{
		TokenValidator: validator,
		Logger:         logger,
	})

	router := gin.New()
	handlers.RegisterProtectedRoutes(router, rbac.Authenticate())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/mfa/webauthn/credentials", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
