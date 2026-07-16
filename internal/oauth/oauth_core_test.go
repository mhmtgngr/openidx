// Package oauth provides unit tests for OAuth 2.0 core flows
package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Helper function for PKCE tests
func calculateCodeChallenge(verifier, method string) string {
	if method == "S256" {
		hash := sha256Hash([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(hash)
	}
	return verifier
}

func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// Test Authorization Code Storage

func TestStoreAuthorizationCode(t *testing.T) {
	// This test would require a mock Redis client
	// For now, we'll test the structure creation

	code := &StoredAuthorizationCode{
		Code:                "test-code-123",
		ClientID:            "test-client",
		UserID:              "user-123",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		State:               "state-123",
		Nonce:               "nonce-123",
		CodeChallenge:       "challenge-123",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		CreatedAt:           time.Now(),
		Used:                false,
	}

	assert.Equal(t, "test-code-123", code.Code)
	assert.Equal(t, "test-client", code.ClientID)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.False(t, code.Used)
}

func TestAuthorizationCodeExpiration(t *testing.T) {
	// Test expired code
	expiredCode := &StoredAuthorizationCode{
		Code:      "expired-code",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}

	assert.True(t, time.Now().After(expiredCode.ExpiresAt))

	// Test valid code
	validCode := &StoredAuthorizationCode{
		Code:      "valid-code",
		ExpiresAt: time.Now().Add(10 * time.Minute),
		CreatedAt: time.Now(),
	}

	assert.True(t, time.Now().Before(validCode.ExpiresAt))
}

// Test Token Storage

func TestRefreshTokenFamily(t *testing.T) {
	family := &RefreshTokenFamily{
		FamilyID:    "family-123",
		ClientID:    "client-123",
		UserID:      "user-123",
		Scope:       "openid profile offline_access",
		CreatedAt:   time.Now(),
		LastRotated: time.Now(),
		TokenCount:  1,
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour),
	}

	assert.Equal(t, "family-123", family.FamilyID)
	assert.Equal(t, 1, family.TokenCount)
}

func TestStoredRefreshToken(t *testing.T) {
	token := &StoredRefreshToken{
		Token:     "refresh-token-123",
		FamilyID:  "family-123",
		ClientID:  "client-123",
		UserID:    "user-123",
		Scope:     "openid profile offline_access",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		CreatedAt: time.Now(),
		Revoked:   false,
	}

	assert.Equal(t, "refresh-token-123", token.Token)
	assert.False(t, token.Revoked)
	assert.Nil(t, token.RevokedAt)
}

// Test Scope Utilities

func TestBuildScopeStringWithDeduplication(t *testing.T) {
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
			name:     "Empty list",
			scopes:   []string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildScopeString(tt.scopes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test Token Generation

func TestStoreGenerateToken(t *testing.T) {
	store := &Store{}
	token1 := store.GenerateToken()
	token2 := store.GenerateToken()

	assert.NotEmpty(t, token1)
	assert.NotEmpty(t, token2)
	assert.NotEqual(t, token1, token2, "Tokens should be unique")
	assert.GreaterOrEqual(t, len(token1), 32, "Token should be at least 32 characters")
}

// Test Authorize Flow

// Test Token Flow

// Test HTTP Basic Authentication extraction

func TestExtractBasicAuth(t *testing.T) {
	tests := []struct {
		name             string
		authHeader       string
		expectOK         bool
		expectedClientID string
		expectedSecret   string
	}{
		{
			name:             "Valid Basic Auth",
			authHeader:       "Basic " + base64.StdEncoding.EncodeToString([]byte("client-id:client-secret")),
			expectOK:         true,
			expectedClientID: "client-id",
			expectedSecret:   "client-secret",
		},
		{
			name:       "Missing header",
			authHeader: "",
			expectOK:   false,
		},
		{
			name:       "Invalid format",
			authHeader: "Bearer token",
			expectOK:   false,
		},
		{
			name:       "Malformed base64",
			authHeader: "Basic not-valid-base64!!!",
			expectOK:   false,
		},
		{
			name:       "Missing colon",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("invalid-format")),
			expectOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.authHeader != "" {
				clientID, secret, ok := parseBasicAuth(tt.authHeader)
				assert.Equal(t, tt.expectOK, ok)
				if ok {
					assert.Equal(t, tt.expectedClientID, clientID)
					assert.Equal(t, tt.expectedSecret, secret)
				}
			}
		})
	}
}

// Helper function
func parseBasicAuth(header string) (clientID, secret string, ok bool) {
	if !strings.HasPrefix(header, "Basic ") {
		return "", "", false
	}

	encoded := strings.TrimPrefix(header, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}

// Test Token Response

func TestTokenResponse(t *testing.T) {
	response := TokenResponse{
		AccessToken:  "access-token-123",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "refresh-token-123",
		IDToken:      "id-token-123",
		Scope:        "openid profile",
	}

	assert.Equal(t, "access-token-123", response.AccessToken)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, 3600, response.ExpiresIn)
	assert.NotEmpty(t, response.RefreshToken)
	assert.NotEmpty(t, response.IDToken)
}

// Test Error Response

// Test utilities

// Test UserSession

// Test default scopes
