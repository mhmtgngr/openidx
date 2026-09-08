//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// J7 — the leaver.
//
// "Disable or kill-switch a user and everything is severed" is the journey the
// readiness guide marks ✅ with no automated proof behind it, and the one whose
// failure is worst: it is what an organisation runs on the day somebody is
// fired, or the hour an account is found compromised.
//
// It has three halves, and this file drives all three against the running
// services, because they fail independently:
//
//   - NEW LOGINS. The password grant must refuse a disabled account. This half
//     has always worked; it is here so that a regression in it is not masked by
//     the other two passing.
//   - THE REFRESH GRANT. A refresh token outlives its access token, so without
//     a check the leaver keeps minting fresh access tokens until the refresh
//     token expires — days, not minutes. handleRefreshTokenGrant re-reads the
//     user and refuses; this pins that.
//   - THE ACCESS TOKEN ALREADY ISSUED. This is the half that was missing.
//     deprovisionUser published `revoked_session:<id>` markers, which the
//     REFRESH grant honours and /oauth/userinfo does not read. userinfo
//     consults the per-user revocation cutoff and the per-token blacklist, and
//     no sever path wrote the cutoff — so the token in the leaver's browser
//     kept answering for the rest of its hour while the console showed the
//     account disabled. An access-review revocation, the least urgent control
//     in the product, already wrote it. The kill switch did not.
//
// The order matters in the assertions below: a test that only checked the login
// and the refresh would have passed for the whole time the third half was
// broken, which is exactly how it stayed broken.

// disableUser flips a user to disabled through the ordinary admin update — the
// same path the console's toggle takes, so the test exercises the product's
// leaver flow rather than an UPDATE the product never runs.
//
// Read-modify-write, because PUT binds a whole User and the identity model
// carries BOTH `active` (SCIM) and `enabled` (the OpenIDX extension, and the
// field UpdateUser reads when it decides to deprovision). Sending a bare
// {"active": false} would leave every other field at its zero value and set
// `enabled` false by accident rather than on purpose — a disable that passed
// for the wrong reason.
func disableUser(t *testing.T, userID string) {
	t.Helper()
	token := getAdminToken(t)

	status, current := apiRequest(t, "GET", identityURL+"/api/v1/identity/users/"+userID, "", token)
	require.Equal(t, 200, status, "reading the user before disabling failed: %v", current)

	current["active"] = false
	current["enabled"] = false
	updated, err := json.Marshal(current)
	require.NoError(t, err, "re-encode the user")

	status, body := apiRequest(t, "PUT",
		identityURL+"/api/v1/identity/users/"+userID, string(updated), token)
	require.Equal(t, 200, status, "disabling the user failed: %v", body)

	// Prove the disable landed. Every assertion below is about what a disabled
	// account can still do; if the account is not actually disabled they all
	// pass vacuously.
	status, after := apiRequest(t, "GET", identityURL+"/api/v1/identity/users/"+userID, "", token)
	require.Equal(t, 200, status, "re-reading the user failed: %v", after)
	require.Equal(t, false, after["enabled"], "the user is still enabled after the disable: %v", after)
}

// loginForTokenPair returns the access AND refresh token, which
// loginAndGetToken does not — and the refresh token is half of what this test
// is about.
func loginForTokenPair(t *testing.T, username, password string) (accessToken, refreshToken string) {
	t.Helper()

	loginSession, verifier := beginAuthorizeForLogin(t, "openid profile email offline_access", nil)
	code := submitLoginForCode(t, username, password, loginSession)
	require.NotEmpty(t, code, "login returned no authorization code")

	status, tokenBody := exchangeCodeWithPKCE(t, code, verifier)
	require.Equal(t, 200, status, "token exchange failed: %v", tokenBody)

	accessToken, _ = tokenBody["access_token"].(string)
	refreshToken, _ = tokenBody["refresh_token"].(string)
	require.NotEmpty(t, accessToken, "no access_token: %v", tokenBody)
	return accessToken, refreshToken
}

func TestLeaverLosesEveryFormOfAccess(t *testing.T) {
	nonce := fmt.Sprintf("%d", time.Now().UnixNano())
	username := "leaver-" + nonce
	const password = "LeaverIntegration!2026"

	userID := createTestUser(t, username, username+"@example.com", password)
	t.Cleanup(func() { deleteTestUser(t, userID) })

	accessToken, refreshToken := loginForTokenPair(t, username, password)

	// The control before the change: while the account is live, the token it
	// just minted works. Without this the assertions after the disable could be
	// passing because the token never worked at all.
	status, body := apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", accessToken)
	require.Equal(t, 200, status, "a live user's own access token was refused: %v", body)

	disableUser(t, userID)

	t.Run("no new login", func(t *testing.T) {
		loginSession, _ := beginAuthorizeForLogin(t, "openid", nil)
		loginData := fmt.Sprintf(`{"username":%q,"password":%q,"login_session":%q}`,
			username, password, loginSession)
		status, body := apiRequest(t, "POST", oauthURL+"/oauth/login", loginData, "")
		assert.NotEqual(t, 200, status,
			"a disabled account signed in with its old password: %v", body)
	})

	t.Run("no fresh token from the refresh grant", func(t *testing.T) {
		if refreshToken == "" {
			t.Skip("no refresh token issued for this client; the refresh half is covered by internal/oauth's handler tests")
		}
		status, body := formRequest(t, oauthURL+"/oauth/token", url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		assert.NotEqual(t, 200, status,
			"a disabled user's refresh token minted a fresh access token: %v", body)
		if errStr, ok := body["error"].(string); ok {
			assert.Equal(t, "invalid_grant", errStr, "unexpected error for a disabled user: %v", body)
		}
	})

	// THE ONE THAT WAS BROKEN. Everything above passed for as long as this did
	// not, which is why it is asserted separately and says so.
	t.Run("the access token already in their browser stops working", func(t *testing.T) {
		status, body := apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", accessToken)
		assert.Equal(t, 401, status,
			"the account is disabled and its outstanding access token still answers /oauth/userinfo. "+
				"Every sever path (deprovisionUser, the kill switch) must write the per-user "+
				"revocation cutoff, not only the revoked_session markers the refresh grant reads: %v", body)
	})

	// A resource server that trusts introspection must get the same answer, or
	// the token is dead at the IdP and alive everywhere that asks about it.
	t.Run("introspection reports it inactive", func(t *testing.T) {
		status, body := formRequest(t, oauthURL+"/oauth/introspect", url.Values{
			"token":     {accessToken},
			"client_id": {clientID},
		})
		if status == 401 || status == 400 {
			t.Skipf("this deployment requires client authentication on /oauth/introspect (status %d); "+
				"the userinfo assertion above covers the same marker", status)
		}
		require.Equal(t, 200, status, "introspection failed: %v", body)
		assert.Equal(t, false, body["active"],
			"introspection reports a disabled user's token as active; a resource server would still admit them: %v", body)
	})
}
