// Package oauth provides comprehensive unit tests for OAuth 2.0 service
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// ============================================================
// Authorization Flow Tests
// ============================================================

func TestAuthorizeFlow_ParseRequest(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		expectError    bool
		errorContains  string
		validateReq    func(*testing.T, *FlowAuthorizeRequest)
	}{
		{
			name:        "Valid authorization code request",
			queryParams: "client_id=test-client&redirect_uri=https://example.com/callback&response_type=code&scope=openid+profile&state=test-state",
			expectError: false,
			validateReq: func(t *testing.T, req *FlowAuthorizeRequest) {
				assert.Equal(t, "test-client", req.ClientID)
				assert.Equal(t, "https://example.com/callback", req.RedirectURI)
				assert.Equal(t, "code", req.ResponseType)
				assert.Equal(t, "openid profile", req.Scope)
				assert.Equal(t, "test-state", req.State)
			},
		},
		{
			name:           "Missing client_id",
			queryParams:    "redirect_uri=https://example.com/callback&response_type=code",
			expectError:    true,
			errorContains:  "client_id is required",
		},
		{
			name:           "Missing redirect_uri",
			queryParams:    "client_id=test-client&response_type=code",
			expectError:    true,
			errorContains:  "redirect_uri is required",
		},
		{
			name:           "Missing response_type",
			queryParams:    "client_id=test-client&redirect_uri=https://example.com/callback",
			expectError:    true,
			errorContains:  "response_type is required",
		},
		{
			name:        "Valid token response_type",
			queryParams: "client_id=test-client&redirect_uri=https://example.com/callback&response_type=token",
			expectError: false,
			validateReq: func(t *testing.T, req *FlowAuthorizeRequest) {
				assert.Equal(t, "token", req.ResponseType)
			},
		},
		{
			name:        "Valid id_token response_type (OIDC)",
			queryParams: "client_id=test-client&redirect_uri=https://example.com/callback&response_type=id_token&nonce=test-nonce",
			expectError: false,
			validateReq: func(t *testing.T, req *FlowAuthorizeRequest) {
				assert.Equal(t, "id_token", req.ResponseType)
				assert.Equal(t, "test-nonce", req.Nonce)
			},
		},
		{
			name:        "PKCE with S256 method",
			queryParams: "client_id=test-client&redirect_uri=https://example.com/callback&response_type=code&code_challenge=test-challenge&code_challenge_method=S256",
			expectError: false,
			validateReq: func(t *testing.T, req *FlowAuthorizeRequest) {
				assert.Equal(t, "test-challenge", req.CodeChallenge)
				assert.Equal(t, "S256", req.CodeChallengeMethod)
			},
		},
		{
			name:        "PKCE defaults to plain when method not specified",
			queryParams: "client_id=test-client&redirect_uri=https://example.com/callback&response_type=code&code_challenge=test-challenge",
			expectError: false,
			validateReq: func(t *testing.T, req *FlowAuthorizeRequest) {
				assert.Equal(t, "test-challenge", req.CodeChallenge)
				assert.Equal(t, "plain", req.CodeChallengeMethod)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			router := gin.New()

			flow := &AuthorizeFlow{logger: zap.NewNop()}
			var capturedReq *FlowAuthorizeRequest
			var capturedErr error

			router.GET("/test", func(c *gin.Context) {
				capturedReq, capturedErr = flow.parseRequest(c)
			})

			req := httptest.NewRequest("GET", "/test?"+tt.queryParams, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if tt.expectError {
				assert.Error(t, capturedErr)
				if tt.errorContains != "" {
					assert.Contains(t, capturedErr.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, capturedErr)
				if tt.validateReq != nil {
					tt.validateReq(t, capturedReq)
				}
			}
		})
	}
}

func TestAuthorizeFlow_ValidateResponseType(t *testing.T) {
	tests := []struct {
		name         string
		grantTypes   []string
		responseType string
		expected     bool
	}{
		{
			name:         "Authorization code supported",
			grantTypes:   []string{"authorization_code", "refresh_token"},
			responseType: "code",
			expected:     true,
		},
		{
			name:         "Authorization code not supported",
			grantTypes:   []string{"client_credentials"},
			responseType: "code",
			expected:     false,
		},
		{
			name:         "Token (implicit) supported",
			grantTypes:   []string{"implicit"},
			responseType: "token",
			expected:     true,
		},
		{
			name:         "Empty grant types",
			grantTypes:   []string{},
			responseType: "code",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := &AuthorizeFlow{}
			client := &Client{
				GrantTypes: tt.grantTypes,
			}

			result := flow.validateResponseType(client, tt.responseType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuthorizeFlow_ValidatePKCE(t *testing.T) {
	tests := []struct {
		name          string
		client        *Client
		req           *FlowAuthorizeRequest
		expectedError bool
		errorContains string
	}{
		{
			name: "No PKCE required, no challenge provided",
			client: &Client{
				PKCERequired: false,
			},
			req: &FlowAuthorizeRequest{
				CodeChallenge: "",
			},
			expectedError: false,
		},
		{
			name: "PKCE required but not provided",
			client: &Client{
				PKCERequired: true,
			},
			req: &FlowAuthorizeRequest{
				CodeChallenge: "",
			},
			expectedError: true,
			errorContains: "PKCE is required",
		},
		{
			name: "Valid code challenge length",
			client: &Client{
				PKCERequired: false,
			},
			req: &FlowAuthorizeRequest{
				CodeChallenge:       strings.Repeat("a", 43),
				CodeChallengeMethod: "S256",
			},
			expectedError: false,
		},
		{
			name: "Code challenge too short",
			client: &Client{
				PKCERequired: false,
			},
			req: &FlowAuthorizeRequest{
				CodeChallenge:       "short",
				CodeChallengeMethod: "S256",
			},
			expectedError: true,
			errorContains: "must be between 43 and 128 characters",
		},
		{
			name: "Code challenge too long",
			client: &Client{
				PKCERequired: false,
			},
			req: &FlowAuthorizeRequest{
				CodeChallenge:       strings.Repeat("a", 129),
				CodeChallengeMethod: "S256",
			},
			expectedError: true,
			errorContains: "must be between 43 and 128 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := &AuthorizeFlow{logger: zap.NewNop()}
			err := flow.validatePKCE(tt.client, tt.req)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthorizeFlow_RedirectWithCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name         string
		redirectURI  string
		code         string
		state        string
		expectedCode int
		expectedLoc  string
	}{
		{
			name:         "Redirect with code and state",
			redirectURI:  "https://example.com/callback",
			code:         "auth-code-123",
			state:        "state-456",
			expectedCode:  http.StatusFound,
			expectedLoc:  "https://example.com/callback?code=auth-code-123&state=state-456",
		},
		{
			name:         "Redirect with code, no state",
			redirectURI:  "https://example.com/callback",
			code:         "auth-code-123",
			state:        "",
			expectedCode:  http.StatusFound,
			expectedLoc:  "https://example.com/callback?code=auth-code-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			flow := &AuthorizeFlow{logger: zap.NewNop()}

			router.GET("/test", func(c *gin.Context) {
				flow.redirectWithCode(c, tt.redirectURI, tt.code, tt.state)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedCode, w.Code)
			loc := w.Header().Get("Location")
			assert.Equal(t, tt.expectedLoc, loc)
		})
	}
}

func TestAuthorizeFlow_RedirectError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name            string
		req             *FlowAuthorizeRequest
		errorCode       string
		description     string
		expectedCode    int
		expectedBody    string
		expectedRedirect string
	}{
		{
			name: "Error with redirect URI",
			req: &FlowAuthorizeRequest{
				RedirectURI: "https://example.com/callback",
				State:       "state-123",
			},
			errorCode:       "invalid_request",
			description:     "Missing required parameter",
			expectedCode:    http.StatusFound,
			expectedRedirect: "https://example.com/callback?error=invalid_request&error_description=Missing+required+parameter&state=state-123",
		},
		{
			name: "Error without redirect URI returns JSON",
			req: &FlowAuthorizeRequest{
				RedirectURI: "",
			},
			errorCode:    "invalid_request",
			description:  "Missing client_id",
			expectedCode: http.StatusBadRequest,
			expectedBody: `{"error":"invalid_request","error_description":"Missing client_id"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			flow := &AuthorizeFlow{logger: zap.NewNop()}

			router.GET("/test", func(c *gin.Context) {
				flow.redirectError(c, tt.req, tt.errorCode, tt.description)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedCode, w.Code)

			if tt.expectedRedirect != "" {
				loc := w.Header().Get("Location")
				assert.Equal(t, tt.expectedRedirect, loc)
			}
			if tt.expectedBody != "" {
				assert.JSONEq(t, tt.expectedBody, w.Body.String())
			}
		})
	}
}

// ============================================================
// Token Flow Tests
// ============================================================

func TestTokenFlow_IsScopeSubset(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		allowed   string
		expected  bool
	}{
		{
			name:      "Empty requested scope is valid",
			requested: "",
			allowed:   "openid profile email",
			expected:  true,
		},
		{
			name:      "Empty allowed scope with non-empty requested",
			requested: "openid",
			allowed:   "",
			expected:  false,
		},
		{
			name:      "Exact match",
			requested: "openid profile",
			allowed:   "openid profile",
			expected:  true,
		},
		{
			name:      "Subset is valid",
			requested: "openid",
			allowed:   "openid profile email",
			expected:  true,
		},
		{
			name:      "Requested has scope not in allowed",
			requested: "openid admin",
			allowed:   "openid profile",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isScopeSubset(tt.requested, tt.allowed)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTokenFlow_HashHalf(t *testing.T) {
	t.Run("Hash produces consistent output", func(t *testing.T) {
		result := hashHalf("test-token")
		result2 := hashHalf("test-token")
		assert.Equal(t, result, result2)
	})

	t.Run("Different inputs produce different hashes", func(t *testing.T) {
		result := hashHalf("token1")
		result2 := hashHalf("token2")
		assert.NotEqual(t, result, result2)
	})

	t.Run("Hash is base64url encoded", func(t *testing.T) {
		result := hashHalf("any-token")
		// Should not contain + or / which are in base64 but not base64url
		assert.NotContains(t, result, "+")
		assert.NotContains(t, result, "/")
		// Should not have padding
		assert.NotContains(t, result, "=")
	})
}

// ============================================================
// Token Generation Tests
// ============================================================

func TestGenerateRandomToken_Uniqueness(t *testing.T) {
	t.Run("32 bytes", func(t *testing.T) {
		tokens := make(map[string]bool)
		for i := 0; i < 100; i++ {
			token := GenerateRandomToken(32)
			assert.NotEmpty(t, token)
			assert.False(t, tokens[token], "Token should be unique")
			tokens[token] = true
		}
	})

	t.Run("16 bytes", func(t *testing.T) {
		tokens := make(map[string]bool)
		for i := 0; i < 100; i++ {
			token := GenerateRandomToken(16)
			assert.NotEmpty(t, token)
			assert.False(t, tokens[token], "Token should be unique")
			tokens[token] = true
		}
	})
}

func TestGenerateAuthorizationCode(t *testing.T) {
	t.Run("Generates valid code", func(t *testing.T) {
		code, err := GenerateAuthorizationCode()
		assert.NoError(t, err)
		assert.NotEmpty(t, code)
		assert.GreaterOrEqual(t, len(code), 43)
	})

	t.Run("Codes are unique", func(t *testing.T) {
		codes := make(map[string]bool)
		for i := 0; i < 100; i++ {
			code, err := GenerateAuthorizationCode()
			assert.NoError(t, err)
			assert.False(t, codes[code], "Code should be unique")
			codes[code] = true
		}
	})

	t.Run("Code is base64url encoded", func(t *testing.T) {
		code, err := GenerateAuthorizationCode()
		assert.NoError(t, err)
		// Check for valid base64url characters only
		for _, c := range code {
			assert.True(t, isValidPKCEChar(c), "Invalid character in code: %c", c)
		}
	})
}

// ============================================================
// PKCE Validation Tests
// ============================================================

func TestValidatePKCE(t *testing.T) {
	validVerifier := generateValidCodeVerifier()
	validChallengeS256 := calculateS256Challenge(validVerifier)

	tests := []struct {
		name                string
		codeVerifier        string
		codeChallenge       string
		codeChallengeMethod string
		expectError         bool
		errorContains       string
	}{
		{
			name:                "Valid S256 PKCE",
			codeVerifier:        validVerifier,
			codeChallenge:       validChallengeS256,
			codeChallengeMethod: "S256",
			expectError:         false,
		},
		{
			name:                "Invalid S256 challenge mismatch",
			codeVerifier:        generateValidCodeVerifier(),
			codeChallenge:       validChallengeS256,
			codeChallengeMethod: "S256",
			expectError:         true,
			errorContains:       "does not match",
		},
		{
			name:                "Valid plain PKCE",
			codeVerifier:        validVerifier,
			codeChallenge:       validVerifier,
			codeChallengeMethod: "plain",
			expectError:         false,
		},
		{
			name:                "Invalid plain challenge mismatch",
			codeVerifier:        generateValidCodeVerifier(),
			codeChallenge:       validVerifier,
			codeChallengeMethod: "plain",
			expectError:         true,
			errorContains:       "does not match",
		},
		{
			name:                "No PKCE used",
			codeVerifier:        "",
			codeChallenge:       "",
			codeChallengeMethod: "",
			expectError:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePKCE(tt.codeVerifier, tt.codeChallenge, tt.codeChallengeMethod)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsValidPKCEChar(t *testing.T) {
	tests := []struct {
		name     string
		char     rune
		expected bool
	}{
		{"Lowercase letter", 'a', true},
		{"Uppercase letter", 'Z', true},
		{"Digit", '5', true},
		{"Hyphen", '-', true},
		{"Period", '.', true},
		{"Underscore", '_', true},
		{"Tilde", '~', true},
		{"At sign", '@', false},
		{"Hash", '#', false},
		{"Dollar sign", '$', false},
		{"Space", ' ', false},
		{"Plus", '+', false},
		{"Slash", '/', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidPKCEChar(tt.char)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConstantTimeStringCompare(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{"Equal strings", "hello", "hello", true},
		{"Different strings", "hello", "world", false},
		{"Different lengths", "hello", "hi", false},
		{"Empty strings", "", "", true},
		{"One empty", "", "hello", false},
		{"Same content different case", "Hello", "hello", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := constantTimeStringCompare(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================
// Session Management Tests
// ============================================================

func TestStore_AuthorizationCodeLifecycle(t *testing.T) {
	mini := miniredis.RunT(t)
	defer mini.Close()

	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	defer client.Close()

	redisWrapper := &database.RedisClient{Client: client}
	store := NewStore(redisWrapper, zap.NewNop())
	ctx := context.Background()

	t.Run("Store and retrieve authorization code", func(t *testing.T) {
		code := &StoredAuthorizationCode{
			Code:                "test-code-123",
			ClientID:            "test-client",
			UserID:              "user-123",
			RedirectURI:         "https://example.com/callback",
			Scope:               "openid profile",
			State:               "state-456",
			Nonce:               "nonce-789",
			CodeChallenge:       "challenge-abc",
			CodeChallengeMethod: "S256",
			ExpiresAt:           time.Now().Add(10 * time.Minute),
			CreatedAt:           time.Now(),
			Used:                false,
		}

		err := store.StoreAuthorizationCode(ctx, code, 10*time.Minute)
		require.NoError(t, err)

		retrieved, err := store.GetAuthorizationCode(ctx, code.Code)
		assert.NoError(t, err)
		assert.Equal(t, "test-code-123", retrieved.Code)
		assert.Equal(t, "test-client", retrieved.ClientID)
		assert.Equal(t, "user-123", retrieved.UserID)
		assert.False(t, retrieved.Used)
	})

	t.Run("Consume authorization code marks as used", func(t *testing.T) {
		code := &StoredAuthorizationCode{
			Code:        "consume-test-code",
			ClientID:    "test-client",
			UserID:      "user-123",
			RedirectURI: "https://example.com/callback",
			Scope:       "openid",
			ExpiresAt:   time.Now().Add(10 * time.Minute),
			CreatedAt:   time.Now(),
			Used:        false,
		}

		err := store.StoreAuthorizationCode(ctx, code, 10*time.Minute)
		require.NoError(t, err)

		err = store.ConsumeAuthorizationCode(ctx, code.Code)
		assert.NoError(t, err)

		_, err = store.GetAuthorizationCode(ctx, code.Code)
		assert.Error(t, err)
		assert.Equal(t, ErrCodeNotFound, err)
	})

	t.Run("Delete authorization code", func(t *testing.T) {
		code := &StoredAuthorizationCode{
			Code:        "delete-test-code",
			ClientID:    "test-client",
			UserID:      "user-123",
			RedirectURI: "https://example.com/callback",
			Scope:       "openid",
			ExpiresAt:   time.Now().Add(10 * time.Minute),
			CreatedAt:   time.Now(),
			Used:        false,
		}

		err := store.StoreAuthorizationCode(ctx, code, 10*time.Minute)
		require.NoError(t, err)

		err = store.DeleteAuthorizationCode(ctx, code.Code)
		assert.NoError(t, err)

		_, err = store.GetAuthorizationCode(ctx, code.Code)
		assert.Error(t, err)
		assert.Equal(t, ErrCodeNotFound, err)
	})

	t.Run("Expired authorization code", func(t *testing.T) {
		code := &StoredAuthorizationCode{
			Code:        "expired-code",
			ClientID:    "test-client",
			UserID:      "user-123",
			RedirectURI: "https://example.com/callback",
			Scope:       "openid",
			ExpiresAt:   time.Now().Add(-1 * time.Minute),
			CreatedAt:   time.Now().Add(-2 * time.Minute),
			Used:        false,
		}

		err := store.StoreAuthorizationCode(ctx, code, time.Minute)
		require.NoError(t, err)

		_, err = store.GetAuthorizationCode(ctx, code.Code)
		assert.Error(t, err)
		assert.Equal(t, ErrCodeExpired, err)
	})

	t.Run("Already used authorization code", func(t *testing.T) {
		code := &StoredAuthorizationCode{
			Code:        "already-used-code",
			ClientID:    "test-client",
			UserID:      "user-123",
			RedirectURI: "https://example.com/callback",
			Scope:       "openid",
			ExpiresAt:   time.Now().Add(10 * time.Minute),
			CreatedAt:   time.Now(),
			Used:        true,
		}

		err := store.StoreAuthorizationCode(ctx, code, 10*time.Minute)
		require.NoError(t, err)

		_, err = store.GetAuthorizationCode(ctx, code.Code)
		assert.Error(t, err)
		assert.Equal(t, ErrCodeAlreadyUsed, err)
	})
}

func TestStore_AccessTokenLifecycle(t *testing.T) {
	mini := miniredis.RunT(t)
	defer mini.Close()

	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	defer client.Close()

	redisWrapper := &database.RedisClient{Client: client}
	store := NewStore(redisWrapper, zap.NewNop())
	ctx := context.Background()

	t.Run("Store and retrieve access token", func(t *testing.T) {
		token := &AccessTokenData{
			Token:     "access-token-123",
			ClientID:  "test-client",
			UserID:    "user-123",
			Scope:     "openid profile email",
			ExpiresAt: time.Now().Add(1 * time.Hour),
			CreatedAt: time.Now(),
		}

		err := store.StoreAccessToken(ctx, token, time.Hour)
		require.NoError(t, err)

		retrieved, err := store.GetAccessToken(ctx, token.Token)
		assert.NoError(t, err)
		assert.Equal(t, "access-token-123", retrieved.Token)
		assert.Equal(t, "test-client", retrieved.ClientID)
		assert.Equal(t, "user-123", retrieved.UserID)
	})

	t.Run("Revoke access token", func(t *testing.T) {
		token := &AccessTokenData{
			Token:     "revoke-token-123",
			ClientID:  "test-client",
			UserID:    "user-123",
			Scope:     "openid",
			ExpiresAt: time.Now().Add(1 * time.Hour),
			CreatedAt: time.Now(),
		}

		err := store.StoreAccessToken(ctx, token, time.Hour)
		require.NoError(t, err)

		err = store.RevokeAccessToken(ctx, token.Token)
		assert.NoError(t, err)

		_, err = store.GetAccessToken(ctx, token.Token)
		assert.Error(t, err)
	})

	t.Run("Expired access token", func(t *testing.T) {
		token := &AccessTokenData{
			Token:     "expired-access-token",
			ClientID:  "test-client",
			UserID:    "user-123",
			Scope:     "openid",
			ExpiresAt: time.Now().Add(-1 * time.Minute),
			CreatedAt: time.Now().Add(-2 * time.Minute),
		}

		err := store.StoreAccessToken(ctx, token, time.Minute)
		require.NoError(t, err)

		_, err = store.GetAccessToken(ctx, token.Token)
		assert.Error(t, err)
	})
}

func TestStore_RefreshTokenLifecycle(t *testing.T) {
	mini := miniredis.RunT(t)
	defer mini.Close()

	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	defer client.Close()

	redisWrapper := &database.RedisClient{Client: client}
	store := NewStore(redisWrapper, zap.NewNop())
	ctx := context.Background()

	t.Run("Store and retrieve refresh token", func(t *testing.T) {
		token := &StoredRefreshToken{
			Token:     "refresh-token-123",
			ClientID:  "test-client",
			UserID:    "user-123",
			Scope:     "openid profile offline_access",
			ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
			CreatedAt: time.Now(),
			Revoked:   false,
		}

		err := store.StoreRefreshToken(ctx, token, "test-family-123", 30*24*time.Hour)
		require.NoError(t, err)

		retrieved, err := store.GetRefreshToken(ctx, token.Token)
		assert.NoError(t, err)
		assert.Equal(t, "refresh-token-123", retrieved.Token)
		assert.Equal(t, "test-family-123", retrieved.FamilyID)
		assert.Equal(t, "test-client", retrieved.ClientID)
		assert.False(t, retrieved.Revoked)
	})

	t.Run("Revoke refresh token", func(t *testing.T) {
		token := &StoredRefreshToken{
			Token:     "revoke-refresh-123",
			ClientID:  "test-client",
			UserID:    "user-123",
			Scope:     "openid",
			ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
			CreatedAt: time.Now(),
			Revoked:   false,
		}

		err := store.StoreRefreshToken(ctx, token, "revoke-family-xyz", 30*24*time.Hour)
		require.NoError(t, err)

		err = store.RevokeRefreshToken(ctx, token.Token)
		assert.NoError(t,	err)

		_, err = store.GetRefreshToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Equal(t, ErrTokenInvalidated, err)
	})

	t.Run("Retrieve non-existent refresh token", func(t *testing.T) {
		_, err := store.GetRefreshToken(ctx, "non-existent-token")
		assert.Error(t, err)
		assert.Equal(t, ErrRefreshTokenNotFound, err)
	})

	t.Run("Expired refresh token", func(t *testing.T) {
		token := &StoredRefreshToken{
			Token:     "expired-refresh-token",
			ClientID:  "test-client",
			UserID:    "user-123",
			Scope:     "openid",
			ExpiresAt: time.Now().Add(-1 * time.Hour),
			CreatedAt: time.Now().Add(-2 * time.Hour),
			Revoked:   false,
		}

		err := store.StoreRefreshToken(ctx, token, "expired-family", time.Minute)
		require.NoError(t, err)

		_, err = store.GetRefreshToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Equal(t, ErrRefreshTokenExpired, err)
	})
}

func TestStore_RevokeUserTokens(t *testing.T) {
	mini := miniredis.RunT(t)
	defer mini.Close()

	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	defer client.Close()

	redisWrapper := &database.RedisClient{Client: client}
	store := NewStore(redisWrapper, zap.NewNop())
	ctx := context.Background()

	userID := "user-revoke-test"

	// Create multiple tokens for the user
	for i := 0; i < 3; i++ {
		token := &AccessTokenData{
			Token:     fmt.Sprintf("user-token-%d", i),
			ClientID:  "test-client",
			UserID:    userID,
			Scope:     "openid",
			ExpiresAt: time.Now().Add(1 * time.Hour),
			CreatedAt: time.Now(),
		}
		err := store.StoreAccessToken(ctx, token, time.Hour)
		require.NoError(t, err)
	}

	// Verify tokens exist
	token, err := store.GetAccessToken(ctx, "user-token-0")
	assert.NoError(t, err)
	assert.Equal(t, userID, token.UserID)

	// Revoke all user tokens
	err = store.RevokeUserTokens(ctx, userID)
	assert.NoError(t, err)

	// Verify tokens are gone
	_, err = store.GetAccessToken(ctx, "user-token-0")
	assert.Error(t, err)
	_, err = store.GetAccessToken(ctx, "user-token-1")
	assert.Error(t, err)
	_, err = store.GetAccessToken(ctx, "user-token-2")
	assert.Error(t, err)
}

// ============================================================
// Client Authentication and Validation Tests
// ============================================================

func TestClientRepository_ValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name        string
		client      *Client
		redirectURI string
		expected    bool
	}{
		{
			name: "Exact match",
			client: &Client{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			redirectURI: "https://example.com/callback",
			expected:    true,
		},
		{
			name: "Multiple redirect URIs - second matches",
			client: &Client{
				RedirectURIs: []string{
					"https://app1.example.com/callback",
					"https://app2.example.com/callback",
				},
			},
			redirectURI: "https://app2.example.com/callback",
			expected:    true,
		},
		{
			name: "Wildcard subdomain matches",
			client: &Client{
				RedirectURIs: []string{"https://*.example.com/callback"},
			},
			redirectURI: "https://app.example.com/callback",
			expected:    true,
		},
		{
			name: "Wildcard with nested subdomain",
			client: &Client{
				RedirectURIs: []string{"https://*.example.com/callback"},
			},
			redirectURI: "https://sub.app.example.com/callback",
			expected:    true,
		},
		{
			name: "Wildcard doesn't match different domain",
			client: &Client{
				RedirectURIs: []string{"https://*.example.com/callback"},
			},
			redirectURI: "https://evil.com/callback",
			expected:    false,
		},
		{
			name: "Path mismatch",
			client: &Client{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			redirectURI: "https://example.com/other",
			expected:    false,
		},
		{
			name: "Protocol mismatch (http vs https)",
			client: &Client{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			redirectURI: "http://example.com/callback",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &ClientRepository{}
			result := repo.ValidateRedirectURI(tt.client, tt.redirectURI)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClientRepository_ValidateGrantType(t *testing.T) {
	tests := []struct {
		name      string
		client    *Client
		grantType string
		expected  bool
	}{
		{
			name: "Supported grant type",
			client: &Client{
				GrantTypes: []string{"authorization_code", "refresh_token"},
			},
			grantType: "authorization_code",
			expected:   true,
		},
		{
			name: "Unsupported grant type",
			client: &Client{
				GrantTypes: []string{"authorization_code"},
			},
			grantType: "client_credentials",
			expected:   false,
		},
		{
			name: "Empty grant types list",
			client: &Client{
				GrantTypes: []string{},
			},
			grantType: "authorization_code",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &ClientRepository{}
			result := repo.ValidateGrantType(tt.client, tt.grantType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClientRepository_ValidateScope(t *testing.T) {
	tests := []struct {
		name     string
		client   *Client
		scope    string
		expected bool
	}{
		{
			name: "Single allowed scope",
			client: &Client{
				Scopes: []string{"openid", "profile", "email"},
			},
			scope:    "openid",
			expected: true,
		},
		{
			name: "Multiple allowed scopes",
			client: &Client{
				Scopes: []string{"openid", "profile", "email"},
			},
			scope:    "openid profile email",
			expected: true,
		},
		{
			name: "Subset of allowed scopes",
			client: &Client{
				Scopes: []string{"openid", "profile", "email", "address"},
			},
			scope:    "openid profile",
			expected: true,
		},
		{
			name: "Contains disallowed scope",
			client: &Client{
				Scopes: []string{"openid", "profile"},
			},
			scope:    "openid admin",
			expected: false,
		},
		{
			name: "Empty scope is valid",
			client: &Client{
				Scopes: []string{"openid"},
			},
			scope:    "",
			expected: true,
		},
		{
			name: "All scopes disallowed",
			client: &Client{
				Scopes: []string{},
			},
			scope:    "openid",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &ClientRepository{}
			result := repo.ValidateScope(tt.client, tt.scope)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================
// Utility Function Tests
// ============================================================

func TestBuildRedirectURI(t *testing.T) {
	tests := []struct {
		name           string
		baseURI        string
		code           string
		state          string
		errorCode      string
		errorDesc      string
		expectedResult string
		expectError    bool
	}{
		{
			name:           "Success with code and state",
			baseURI:        "https://example.com/callback",
			code:           "auth-code-123",
			state:          "state-456",
			expectedResult: "https://example.com/callback?code=auth-code-123&state=state-456",
			expectError:    false,
		},
		{
			name:           "Success with code only",
			baseURI:        "https://example.com/callback",
			code:           "auth-code-123",
			state:          "",
			expectedResult: "https://example.com/callback?code=auth-code-123",
			expectError:    false,
		},
		{
			name:           "Error with state",
			baseURI:        "https://example.com/callback",
			errorCode:      "access_denied",
			errorDesc:      "User denied access",
			state:          "state-789",
			expectedResult: "https://example.com/callback?error=access_denied&error_description=User+denied+access&state=state-789",
			expectError:    false,
		},
		{
			name:        "Invalid base URI",
			baseURI:     ":invalid-url",
			code:        "code",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := BuildRedirectURI(tt.baseURI, tt.code, tt.state, tt.errorCode, tt.errorDesc)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}

func TestBuildScopeString_Extended(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		expected string
	}{
		{
			name:     "Simple scopes",
			scopes:   []string{"openid", "profile", "email"},
			expected: "openid profile email",
		},
		{
			name:     "Empty scopes",
			scopes:   []string{},
			expected: "",
		},
		{
			name:     "Single scope",
			scopes:   []string{"openid"},
			expected: "openid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildScopeString(tt.scopes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================
// TokenResponse and ErrorResponse Tests
// ============================================================

func TestTokenResponse_JSON(t *testing.T) {
	t.Run("Full token response", func(t *testing.T) {
		resp := &TokenResponse{
			AccessToken:  "access-token-123",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refresh-token-456",
			IDToken:      "id-token-789",
			Scope:        "openid profile",
		}

		j, err := json.Marshal(resp)
		require.NoError(t, err)

		var data map[string]interface{}
		err = json.Unmarshal(j, &data)
		require.NoError(t, err)

		assert.Equal(t, "access-token-123", data["access_token"])
		assert.Equal(t, "Bearer", data["token_type"])
		assert.Equal(t, float64(3600), data["expires_in"])
		assert.Equal(t, "refresh-token-456", data["refresh_token"])
		assert.Equal(t, "id-token-789", data["id_token"])
		assert.Equal(t, "openid profile", data["scope"])
	})

	t.Run("Minimal token response", func(t *testing.T) {
		resp := &TokenResponse{
			AccessToken: "access-token-abc",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		j, err := json.Marshal(resp)
		require.NoError(t, err)

		var data map[string]interface{}
		err = json.Unmarshal(j, &data)
		require.NoError(t, err)

		assert.Equal(t, "access-token-abc", data["access_token"])
		assert.Equal(t, "Bearer", data["token_type"])
		assert.Equal(t, float64(3600), data["expires_in"])
		_, hasRefresh := data["refresh_token"]
		assert.False(t, hasRefresh)
		_, hasIDToken := data["id_token"]
		assert.False(t, hasIDToken)
	})
}

func TestTokenErrorResponse_AllErrorCodes(t *testing.T) {
	errorCodes := []string{
		TokenErrorInvalidRequest,
		TokenErrorInvalidClient,
		TokenErrorInvalidGrant,
		TokenErrorUnauthorizedClient,
		TokenErrorUnsupportedGrantType,
		TokenErrorInvalidScope,
		TokenErrorServerError,
	}

	for _, code := range errorCodes {
		t.Run(code, func(t *testing.T) {
			resp := TokenErrorResponse{
				Error:            code,
				ErrorDescription: "Test error description",
			}

			j, err := json.Marshal(resp)
			require.NoError(t, err)

			var decoded TokenErrorResponse
			err = json.Unmarshal(j, &decoded)
			require.NoError(t, err)

			assert.Equal(t, code, decoded.Error)
			assert.Equal(t, "Test error description", decoded.ErrorDescription)
		})
	}
}

// ============================================================
// OAuth 2.0 Constants Tests
// ============================================================

func TestOAuthConstants(t *testing.T) {
	t.Run("Token error constants match RFC 6749", func(t *testing.T) {
		assert.Equal(t, "invalid_request", TokenErrorInvalidRequest)
		assert.Equal(t, "invalid_client", TokenErrorInvalidClient)
		assert.Equal(t, "invalid_grant", TokenErrorInvalidGrant)
		assert.Equal(t, "unauthorized_client", TokenErrorUnauthorizedClient)
		assert.Equal(t, "unsupported_grant_type", TokenErrorUnsupportedGrantType)
		assert.Equal(t, "invalid_scope", TokenErrorInvalidScope)
		assert.Equal(t, "server_error", TokenErrorServerError)
	})

	t.Run("Default token lifetimes", func(t *testing.T) {
		assert.Equal(t, 10*time.Minute, DefaultAuthCodeTTL)
		assert.Equal(t, 30*24*time.Hour, DefaultRefreshTokenTTL)
		assert.Equal(t, time.Hour, DefaultAccessTokenTTL)
	})
}

// ============================================================
// Test Helpers
// ============================================================

func generateValidCodeVerifier() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func calculateS256Challenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func generateValidChallenge(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

// ============================================================
// Edge Cases and Error Handling Tests
// ============================================================

func TestEdgeCases(t *testing.T) {
	t.Run("Empty scope string handling", func(t *testing.T) {
		repo := &ClientRepository{}
		client := &Client{Scopes: []string{"openid"}}
		result := repo.ValidateScope(client, "")
		assert.True(t, result, "Empty scope should be valid")
	})

	t.Run("Scope with only spaces", func(t *testing.T) {
		repo := &ClientRepository{}
		client := &Client{Scopes: []string{"openid"}}
		result := repo.ValidateScope(client, "   ")
		assert.True(t, result, "Only-space scope should be valid")
	})

	t.Run("Multiple consecutive spaces in scope", func(t *testing.T) {
		requested := "openid  profile"
		allowed := "openid profile"
		result := isScopeSubset(requested, allowed)
		assert.True(t, result, "Should handle multiple spaces")
	})

	t.Run("Redirect URI with fragment", func(t *testing.T) {
		uri := "https://example.com/callback#fragment"
		result, err := BuildRedirectURI(uri, "code", "state", "", "")
		assert.NoError(t, err)
		assert.Contains(t, result, "code=code")
		assert.Contains(t, result, "state=state")
	})
}

// ============================================================
// Security-focused Tests
// ============================================================

func TestSecurityFeatures(t *testing.T) {
	mini := miniredis.RunT(t)
	defer mini.Close()

	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	defer client.Close()

	redisWrapper := &database.RedisClient{Client: client}
	store := NewStore(redisWrapper, zap.NewNop())
	ctx := context.Background()

	t.Run("PKCE prevents code interception attack", func(t *testing.T) {
		correctVerifier := generateValidCodeVerifier()
		correctChallenge := calculateS256Challenge(correctVerifier)
		wrongVerifier := generateValidCodeVerifier()

		// Attacker's wrong verifier should fail
		err := ValidatePKCEVerifier(wrongVerifier, correctChallenge, "S256")
		assert.Error(t, err)

		// Only correct verifier works
		err = ValidatePKCEVerifier(correctVerifier, correctChallenge, "S256")
		assert.NoError(t, err)
	})

	t.Run("Single-use authorization codes", func(t *testing.T) {
		code := &StoredAuthorizationCode{
			Code:        "single-use-code",
			ClientID:    "test-client",
			UserID:      "user-123",
			RedirectURI: "https://example.com/callback",
			Scope:       "openid",
			ExpiresAt:   time.Now().Add(10 * time.Minute),
			CreatedAt:   time.Now(),
			Used:        false,
		}

		err := store.StoreAuthorizationCode(ctx, code, 10*time.Minute)
		require.NoError(t, err)

		// First use succeeds
		err = store.ConsumeAuthorizationCode(ctx, code.Code)
		assert.NoError(t, err)

		// Second use fails (replay attack prevention)
		err = store.ConsumeAuthorizationCode(ctx, code.Code)
		assert.Error(t, err)
	})
}

// ============================================================
// Concurrency Tests
// ============================================================

func TestConcurrentTokenGeneration(t *testing.T) {
	store := &Store{}
	tokenSet := make(map[string]bool)
	results := make(chan string, 100)

	// Generate tokens concurrently
	for i := 0; i < 100; i++ {
		go func() {
			results <- store.GenerateToken()
		}()
	}

	// Collect all tokens
	for i := 0; i < 100; i++ {
		token := <-results
		assert.False(t, tokenSet[token], "Token should be unique")
		tokenSet[token] = true
	}

	assert.Len(t, tokenSet, 100)
}

// ============================================================
// Store Tests
// ============================================================

func TestStore_GenerateToken(t *testing.T) {
	store := &Store{}

	t.Run("Generates unique tokens", func(t *testing.T) {
		tokens := make(map[string]bool)
		for i := 0; i < 100; i++ {
			token := store.GenerateToken()
			assert.NotEmpty(t, token)
			assert.False(t, tokens[token], "Token should be unique")
			tokens[token] = true
		}
		assert.Len(t, tokens, 100)
	})

	t.Run("Tokens are reasonable length", func(t *testing.T) {
		token := store.GenerateToken()
		assert.GreaterOrEqual(t, len(token), 32)
		assert.LessOrEqual(t, len(token), 64)
	})
}

// ============================================================
// Custom Type Tests
// ============================================================

func TestUserInfo(t *testing.T) {
	userInfo := &UserInfo{
		Sub:           "user-123",
		Name:          "Test User",
		GivenName:     "Test",
		FamilyName:    "User",
		Email:         "test@example.com",
		EmailVerified: true,
		Picture:       "https://example.com/avatar.jpg",
	}

	j, err := json.Marshal(userInfo)
	require.NoError(t, err)

	var decoded UserInfo
	err = json.Unmarshal(j, &decoded)
	require.NoError(t, err)

	assert.Equal(t, userInfo.Sub, decoded.Sub)
	assert.Equal(t, userInfo.Name, decoded.Name)
	assert.Equal(t, userInfo.Email, decoded.Email)
	assert.Equal(t, userInfo.EmailVerified, decoded.EmailVerified)
}

func TestOIDCDiscovery(t *testing.T) {
	discovery := &OIDCDiscovery{
		Issuer:                            "https://accounts.example.com",
		AuthorizationEndpoint:             "https://accounts.example.com/oauth/authorize",
		TokenEndpoint:                     "https://accounts.example.com/oauth/token",
		UserInfoEndpoint:                  "https://accounts.example.com/oauth/userinfo",
		JwksURI:                           "https://accounts.example.com/.well-known/jwks.json",
		ScopesSupported:                   []string{"openid", "profile", "email"},
		ResponseTypesSupported:            []string{"code", "id_token", "token"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256", "plain"},
	}

	j, err := json.Marshal(discovery)
	require.NoError(t, err)

	var decoded OIDCDiscovery
	err = json.Unmarshal(j, &decoded)
	require.NoError(t, err)

	assert.Equal(t, discovery.Issuer, decoded.Issuer)
	assert.Contains(t, decoded.ScopesSupported, "openid")
	assert.Contains(t, decoded.CodeChallengeMethodsSupported, "S256")
}

// ============================================================
// Additional Helper Functions Tests
// ============================================================

func TestGenerateClientID_Extended(t *testing.T) {
	ids := make(map[string]bool)

	// Generate multiple IDs and verify uniqueness
	for i := 0; i < 1000; i++ {
		id := generateClientID()
		assert.NotEmpty(t, id)
		assert.False(t, ids[id], "Client ID should be unique")
		ids[id] = true
		assert.LessOrEqual(t, len(id), 24) // Base64URL of 16 bytes
	}
}

func TestGenerateClientSecret_Extended(t *testing.T) {
	secrets := make(map[string]bool)

	for i := 0; i < 1000; i++ {
		secret := generateClientSecret()
		assert.NotEmpty(t, secret)
		assert.False(t, secrets[secret], "Client secret should be unique")
		secrets[secret] = true
		assert.GreaterOrEqual(t, len(secret), 43) // RFC 7636 minimum
		assert.LessOrEqual(t, len(secret), 44)   // Base64URL of 32 bytes
	}
}

func TestHashClientSecret_Extended(t *testing.T) {
	secret := "test-secret-value"

	hash1 := hashClientSecret(secret)
	hash2 := hashClientSecret(secret)

	assert.Equal(t, hash1, hash2, "Same secret should produce same hash")
	assert.NotEqual(t, secret, hash1, "Hash should not match secret")
	assert.LessOrEqual(t, len(hash1), 44) // SHA256 base64url encoded
}

// ============================================================
// DefaultScopes Tests
// ============================================================

func TestDefaultScopes_Extended(t *testing.T) {
	tests := []struct {
		name      string
		grantType string
		check     func(*testing.T, []string)
	}{
		{
			name:      "Authorization code grant",
			grantType: "authorization_code",
			check: func(t *testing.T, scopes []string) {
				assert.Contains(t, scopes, "openid")
			},
		},
		{
			name:      "Client credentials grant",
			grantType: "client_credentials",
			check: func(t *testing.T, scopes []string) {
				assert.Empty(t, scopes)
			},
		},
		{
			name:      "Refresh token grant",
			grantType: "refresh_token",
			check: func(t *testing.T, scopes []string) {
				assert.Contains(t, scopes, "openid")
			},
		},
		{
			name:      "Unknown grant type",
			grantType: "unknown",
			check: func(t *testing.T, scopes []string) {
				assert.Contains(t, scopes, "openid")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scopes := DefaultScopes(tt.grantType)
			tt.check(t, scopes)
		})
	}
}

// ============================================================
// OAuth2 Configuration Tests
// ============================================================

func TestOAuth2Config_StandardGrantTypes(t *testing.T) {
	standardGrantTypes := []string{
		"authorization_code",
		"client_credentials",
		"refresh_token",
	}

	for _, gt := range standardGrantTypes {
		t.Run(gt+" is recognized", func(t *testing.T) {
			client := &Client{GrantTypes: []string{gt}}
			repo := &ClientRepository{}
			assert.NotNil(t, repo.ValidateGrantType(client, gt))
		})
	}
}

func TestOAuth2Config_StandardScopes(t *testing.T) {
	standardOIDCScopes := []string{
		"openid",
		"profile",
		"email",
		"address",
		"phone",
		"offline_access",
	}

	for _, scope := range standardOIDCScopes {
		t.Run(scope+" is valid OIDC scope", func(t *testing.T) {
			client := &Client{Scopes: standardOIDCScopes}
			repo := &ClientRepository{}
			assert.True(t, repo.ValidateScope(client, scope))
		})
	}
}

// ============================================================
// UserSession Tests
// ============================================================

func TestUserSession_Extended(t *testing.T) {
	session := UserSession{
		UserID:    "user-123",
		Email:     "user@example.com",
		Name:      "Test User",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	assert.Equal(t, "user-123", session.UserID)
	assert.Equal(t, "user@example.com", session.Email)
	assert.True(t, time.Now().Before(session.ExpiresAt))
}

// ============================================================
// Error Response Tests
// ============================================================

func TestOAuthErrorResponses_MatchRFC6749(t *testing.T) {
	// RFC 6749 Section 4.1.2.1 defines these error codes
	authorizationErrorCodes := map[string]string{
		ErrorInvalidRequest:         "The request is missing a required parameter",
		ErrorUnauthorizedClient:     "The client is not authorized",
		ErrorAccessDenied:           "The resource owner denied the request",
		ErrorUnsupportedResponseType: "The authorization server does not support this response type",
		ErrorInvalidScope:           "The requested scope is invalid",
		ErrorServerError:            "The authorization server encountered an error",
	}

	for code, desc := range authorizationErrorCodes {
		t.Run(code+" error code", func(t *testing.T) {
			resp := AuthorizationErrorResponse{
				Error:            code,
				ErrorDescription: desc,
			}

			j, err := json.Marshal(resp)
			require.NoError(t, err)

			var decoded AuthorizationErrorResponse
			err = json.Unmarshal(j, &decoded)
			require.NoError(t, err)

			assert.Equal(t, code, decoded.Error)
			assert.Equal(t, desc, decoded.ErrorDescription)
		})
	}
}
