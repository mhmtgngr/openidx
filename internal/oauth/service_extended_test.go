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
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// ============================================================
// Authorization Flow Tests
// ============================================================

// ============================================================
// Token Flow Tests
// ============================================================

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
		assert.NoError(t, err)

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

// ============================================================
// OAuth 2.0 Constants Tests
// ============================================================

func TestOAuthConstants(t *testing.T) {
	t.Run("Token error constants match RFC 6749", func(t *testing.T) {
		assert.Equal(t, "invalid_request", ErrorInvalidRequest)
		assert.Equal(t, "invalid_client", ErrorInvalidClient)
		assert.Equal(t, "invalid_grant", ErrorInvalidGrant)
		assert.Equal(t, "unauthorized_client", ErrorUnauthorizedClient)
		assert.Equal(t, "unsupported_grant_type", ErrorUnsupportedGrantType)
		assert.Equal(t, "invalid_scope", ErrorInvalidScope)
		assert.Equal(t, "server_error", ErrorServerError)
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
		err := ValidatePKCE(wrongVerifier, correctChallenge, "S256")
		assert.Error(t, err)

		// Only correct verifier works
		err = ValidatePKCE(correctVerifier, correctChallenge, "S256")
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

// ============================================================
// DefaultScopes Tests
// ============================================================

// ============================================================
// OAuth2 Configuration Tests
// ============================================================

// ============================================================
// UserSession Tests
// ============================================================

// ============================================================
// Error Response Tests
// ============================================================
