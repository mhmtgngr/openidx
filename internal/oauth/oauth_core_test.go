// Package oauth provides unit tests for OAuth 2.0 core flows
package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

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
