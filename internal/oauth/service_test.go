// Package oauth provides OAuth 2.0 and OpenID Connect provider functionality
package oauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestGenerateRandomToken tests random token generation
func TestGenerateRandomToken(t *testing.T) {
	t.Run("generates non-empty token", func(t *testing.T) {
		token := GenerateRandomToken(32)
		assert.NotEmpty(t, token)
	})

	t.Run("generates unique tokens", func(t *testing.T) {
		token1 := GenerateRandomToken(32)
		token2 := GenerateRandomToken(32)
		assert.NotEqual(t, token1, token2)
	})

	t.Run("different lengths produce different size tokens", func(t *testing.T) {
		short := GenerateRandomToken(8)
		long := GenerateRandomToken(64)
		assert.Less(t, len(short), len(long))
	})
}

// TestOAuthClientModel tests the OAuthClient struct
func TestOAuthClientModel(t *testing.T) {
	client := &OAuthClient{
		ID:            "client-001",
		ClientID:      "my-app",
		ClientSecret:  "secret-123",
		Name:          "My Application",
		Description:   "Test application",
		Type:          "confidential",
		RedirectURIs:  []string{"http://localhost:3000/callback"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email"},
	}

	assert.Equal(t, "client-001", client.ID)
	assert.Equal(t, "my-app", client.ClientID)
	assert.Equal(t, "confidential", client.Type)
	assert.Len(t, client.RedirectURIs, 1)
	assert.Len(t, client.GrantTypes, 2)
	assert.Len(t, client.Scopes, 3)
}

// TestAuthorizationCodeModel tests the AuthorizationCode struct
func TestAuthorizationCodeModel(t *testing.T) {
	now := time.Now()
	code := &AuthorizationCode{
		Code:                "abc123",
		ClientID:            "my-app",
		UserID:              "user-001",
		RedirectURI:         "http://localhost:3000/callback",
		Scope:               "openid profile",
		State:               "random-state",
		Nonce:               "random-nonce",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(10 * time.Minute),
		CreatedAt:           now,
	}

	assert.Equal(t, "abc123", code.Code)
	assert.Equal(t, "my-app", code.ClientID)
	assert.Equal(t, "user-001", code.UserID)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.True(t, code.ExpiresAt.After(now))
}

// TestAccessTokenModel tests the AccessToken struct
func TestAccessTokenModel(t *testing.T) {
	now := time.Now()
	token := &AccessToken{
		Token:     "access-token-xyz",
		ClientID:  "my-app",
		UserID:    "user-001",
		Scope:     "openid profile email",
		ExpiresAt: now.Add(1 * time.Hour),
		CreatedAt: now,
	}

	assert.Equal(t, "access-token-xyz", token.Token)
	assert.Equal(t, "my-app", token.ClientID)
	assert.True(t, token.ExpiresAt.After(now))
}

// TestRefreshTokenModel tests the RefreshToken struct
func TestRefreshTokenModel(t *testing.T) {
	now := time.Now()
	token := &RefreshToken{
		Token:     "refresh-token-xyz",
		ClientID:  "my-app",
		UserID:    "user-001",
		Scope:     "openid profile email offline_access",
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	assert.Equal(t, "refresh-token-xyz", token.Token)
	assert.True(t, token.ExpiresAt.After(now))
	assert.Contains(t, token.Scope, "offline_access")
}

// TestTokenExpiration tests token expiration logic
func TestTokenExpiration(t *testing.T) {
	now := time.Now()

	t.Run("active token", func(t *testing.T) {
		token := &AccessToken{
			ExpiresAt: now.Add(1 * time.Hour),
		}
		assert.True(t, token.ExpiresAt.After(now))
	})

	t.Run("expired token", func(t *testing.T) {
		token := &AccessToken{
			ExpiresAt: now.Add(-1 * time.Hour),
		}
		assert.True(t, token.ExpiresAt.Before(now))
	})
}
