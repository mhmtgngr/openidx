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
