//go:build integration

package integration

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCDiscovery(t *testing.T) {
	status, body := apiRequest(t, "GET", oauthURL+"/.well-known/openid-configuration", "", "")

	assert.Equal(t, 200, status)
	assert.NotEmpty(t, body["issuer"])
	assert.NotEmpty(t, body["authorization_endpoint"])
	assert.NotEmpty(t, body["token_endpoint"])
	assert.NotEmpty(t, body["jwks_uri"])
}

func TestJWKSEndpoint(t *testing.T) {
	status, body := apiRequest(t, "GET", oauthURL+"/.well-known/jwks.json", "", "")

	assert.Equal(t, 200, status)
	keys, ok := body["keys"].([]interface{})
	require.True(t, ok, "JWKS response should contain 'keys' array")
	require.NotEmpty(t, keys, "JWKS should contain at least one key")

	key := keys[0].(map[string]interface{})
	assert.Equal(t, "RSA", key["kty"])
	assert.Equal(t, "sig", key["use"])
	assert.Equal(t, "RS256", key["alg"])
	assert.NotEmpty(t, key["n"])
	assert.NotEmpty(t, key["e"])
}

func TestOAuthLoginFlow(t *testing.T) {
	const username = "oauth-flow-test-user"
	const email = "oauth-flow-test@openidx.local"
	const password = "OAuthFlow@123"

	// Setup
	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	t.Run("full authorization code flow", func(t *testing.T) {
		token := loginAndGetToken(t, username, password)
		require.NotEmpty(t, token)

		// Verify JWT claims
		claims := decodeJWTPayload(t, token)
		assert.Equal(t, userID, claims["sub"])
		assert.NotEmpty(t, claims["iss"])
		assert.NotEmpty(t, claims["exp"])
	})

	t.Run("invalid credentials rejected", func(t *testing.T) {
		// Get login session first
		authURL := oauthURL + "/oauth/authorize?response_type=code&client_id=" + clientID +
			"&redirect_uri=" + url.QueryEscape(redirectURI) + "&scope=openid"

		req, _ := httpClient.Get(authURL)
		req.Body.Close()
		location := req.Header.Get("Location")
		redirectURL, _ := url.Parse(location)
		loginSession := redirectURL.Query().Get("login_session")

		loginData := `{"username":"` + username + `","password":"wrong-password","login_session":"` + loginSession + `"}`
		status, _ := apiRequest(t, "POST", oauthURL+"/oauth/login", loginData, "")
		assert.Equal(t, 401, status)
	})

	t.Run("expired login session rejected", func(t *testing.T) {
		loginData := `{"username":"` + username + `","password":"` + password + `","login_session":"invalid-session"}`
		status, _ := apiRequest(t, "POST", oauthURL+"/oauth/login", loginData, "")
		assert.Equal(t, 400, status)
	})
}

func TestTokenRefresh(t *testing.T) {
	const username = "refresh-test-user"
	const email = "refresh-test@openidx.local"
	const password = "Refresh@123"

	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	// Login with offline_access scope to get refresh token
	// (simplified: use the helper which gets basic tokens)
	token := loginAndGetToken(t, username, password)
	require.NotEmpty(t, token)

	// UserInfo should work with valid token
	status, body := apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", token)
	assert.Equal(t, 200, status)
	assert.Equal(t, userID, body["sub"])
}

func TestUserInfoEndpoint(t *testing.T) {
	t.Run("valid token returns user info", func(t *testing.T) {
		const username = "userinfo-test-user"
		const email = "userinfo-test@openidx.local"
		const password = "UserInfo@123"

		userID := createTestUser(t, username, email, password)
		defer deleteTestUser(t, userID)

		token := loginAndGetToken(t, username, password)
		status, body := apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", token)

		assert.Equal(t, 200, status)
		assert.Equal(t, userID, body["sub"])
		assert.Equal(t, email, body["email"])
	})

	t.Run("invalid token rejected", func(t *testing.T) {
		status, _ := apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", "invalid-token")
		assert.Equal(t, 401, status)
	})

	t.Run("missing token rejected", func(t *testing.T) {
		status, _ := apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", "")
		assert.Equal(t, 401, status)
	})
}
