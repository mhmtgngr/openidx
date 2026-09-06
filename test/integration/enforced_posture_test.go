//go:build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Definition of Done's posture (docs/PROJECT-READINESS-GUIDE.md §6.2):
// ACCESS_ASSIGNMENT_ENFORCE=true and the server-rendered login deleted.
//
// Neither had ever been exercised. Before this file, `grep -rn
// ACCESS_ASSIGNMENT_ENFORCE test/ .github/` returned nothing — the one flag
// the DoD turns on was covered by no automated verification at all, so
// "assignment is a grant" was a claim about a configuration nobody had run.
// The harness now exports it for the WHOLE suite (see ci.yml), which is safe
// because the gate only denies for an application with require_assignment=true
// and no seeded application sets it; this test creates one that does.
//
// The application and its client are seeded straight into the database rather
// than through the admin API: the integration harness boots identity-service
// and oauth-service only, so there is no admin API to POST to, and the gate
// reads these two rows and nothing else.

// seedEnforcedApplication registers an application that requires assignment,
// plus the public OAuth client that fronts it, and returns (applicationID,
// clientID). Both rows land in the default organization — the one the harness
// resolves for every request via DEFAULT_ORG_FALLBACK.
func seedEnforcedApplication(t *testing.T, db *pgxpool.Pool, nonce string) (string, string) {
	t.Helper()
	const defaultOrgID = "00000000-0000-0000-0000-000000000010"
	client := "enforced-" + nonce

	// The client is public + PKCE so it takes the same authorize path the
	// admin console does; a confidential client would exercise a different one.
	bypassExec(t, db, `
		INSERT INTO oauth_clients (client_id, name, description, type, redirect_uris,
		                           grant_types, response_types, scopes, pkce_required, org_id)
		VALUES ($1, $2, 'Assignment-gated integration fixture', 'public',
		        '["http://localhost:3000/callback"]'::jsonb,
		        '["authorization_code"]'::jsonb,
		        '["code"]'::jsonb,
		        '["openid", "profile", "email"]'::jsonb,
		        true, $3::uuid)`, client, client, defaultOrgID)

	var appID string
	bypassQueryRow(t, db, &appID, `
		INSERT INTO applications (client_id, name, type, protocol, base_url, redirect_uris,
		                          enabled, require_assignment, org_id)
		VALUES ($1, $2, 'web', 'openid-connect', 'http://localhost:3000',
		        ARRAY['http://localhost:3000/callback'], true, true, $3::uuid)
		RETURNING id::text`, client, client, defaultOrgID)
	require.NotEmpty(t, appID, "seeded application has no id")

	// Prove the fixture is what the gate will read. Without this, a silently
	// defaulted require_assignment would turn the denial assertions below into
	// a test that passes for the wrong reason.
	var requires bool
	require.NoError(t, db.QueryRow(context.Background(),
		`SELECT require_assignment FROM applications WHERE id = $1`, appID).Scan(&requires))
	require.True(t, requires, "fixture application did not persist require_assignment=true")

	return appID, client
}

// beginAuthorizeForClient runs GET /oauth/authorize for an arbitrary client and
// returns the login_session the redirect carries. It is beginAuthorizeForLogin
// with the client id as a parameter instead of the package constant.
func beginAuthorizeForClient(t *testing.T, client string) string {
	t.Helper()
	_, challenge := pkcePair()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {client},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile email"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req, err := http.NewRequest("GET", oauthURL+"/oauth/authorize?"+q.Encode(), nil)
	require.NoError(t, err)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	require.Contains(t, []int{http.StatusOK, http.StatusFound}, resp.StatusCode,
		"authorize for %s: status %d body %s", client, resp.StatusCode, string(body))
	session := extractLoginSession(resp, body)
	require.NotEmpty(t, session, "authorize for %s returned no login_session (status %d body %s)",
		client, resp.StatusCode, string(body))
	return session
}

// loginAttempt posts credentials to /oauth/login and returns the raw outcome.
// submitLoginForCode fails the test on anything but 200 and on a missing code;
// this test has to OBSERVE a refusal, so it needs the status back instead.
func loginAttempt(t *testing.T, username, password, loginSession string) (int, map[string]interface{}) {
	t.Helper()
	payload := fmt.Sprintf(`{"username":%q,"password":%q,"login_session":%q}`,
		username, password, loginSession)
	return apiRequest(t, "POST", oauthURL+"/oauth/login", payload, "")
}

// TestEnforcedAssignmentDeniesAndAudits is the J3 exit test: under
// ACCESS_ASSIGNMENT_ENFORCE=true an unassigned user gets NO authorization code
// for an application that requires assignment, the refusal is durably
// recorded, and assigning the user makes the same flow succeed.
func TestEnforcedAssignmentDeniesAndAudits(t *testing.T) {
	db := integrationDB(t)
	defer db.Close()

	nonce := fmt.Sprintf("%d", time.Now().UnixNano())
	appID, appClientID := seedEnforcedApplication(t, db, nonce)

	const password = "Enforced@123"
	username := "enforced-user-" + nonce
	userID := createTestUser(t, username, username+"@openidx.local", password)

	t.Cleanup(func() {
		bypassExec(t, db, "DELETE FROM user_application_assignments WHERE application_id = $1::uuid", appID)
		bypassExec(t, db, "DELETE FROM unified_audit_events WHERE details->>'application_id' = $1", appID)
		deleteTestUser(t, userID)
		bypassExec(t, db, "DELETE FROM applications WHERE id = $1::uuid", appID)
		bypassExec(t, db, "DELETE FROM oauth_clients WHERE client_id = $1", appClientID)
	})

	// --- unassigned: the flow must not produce a code -----------------------
	status, body := loginAttempt(t, username, password, beginAuthorizeForClient(t, appClientID))
	assert.Equal(t, http.StatusForbidden, status,
		"an unassigned user got %d from /oauth/login for an application that requires assignment: %v", status, body)
	if errStr, _ := body["error"].(string); errStr != "" {
		assert.Equal(t, "access_denied", errStr, "denial should be access_denied, got %v", body)
	}
	assert.Empty(t, extractAuthCode(body), "a code was issued to an unassigned user under enforcement: %v", body)

	// --- and the refusal is durably recorded --------------------------------
	// unified_audit_events is where the gate writes (audit_events is org-scoped
	// and its RLS policy rejects these writes — see
	// internal/oauth/assignment_audit.go). Under enforcement the event_type is
	// the "denied" one, not "would_deny"; asserting the exact type is what
	// catches an enforcement path that has gone quieter than report mode.
	require.Eventually(t, func() bool {
		var denials int
		err := db.QueryRow(context.Background(), `
			SELECT COUNT(*) FROM unified_audit_events
			WHERE event_type = 'access.assignment.denied'
			  AND details->>'application_id' = $1
			  AND details->>'user_id' = $2`, appID, userID).Scan(&denials)
		return err == nil && denials > 0
	}, 10*time.Second, 250*time.Millisecond,
		"no access.assignment.denied record for the refused login; these rows are the only evidence an operator has that the gate acted")

	// --- assigned: the same flow succeeds ------------------------------------
	// The positive control. Without it a gate that denied EVERYTHING would pass
	// the assertions above.
	bypassExec(t, db, `
		INSERT INTO user_application_assignments (user_id, application_id, org_id)
		SELECT $1::uuid, $2::uuid, org_id FROM applications WHERE id = $2::uuid
		ON CONFLICT DO NOTHING`, userID, appID)

	status, body = loginAttempt(t, username, password, beginAuthorizeForClient(t, appClientID))
	require.Equal(t, http.StatusOK, status, "assigned user was refused: %v", body)
	assert.NotEmpty(t, extractAuthCode(body), "assigned user got no authorization code: %v", body)
}

// TestServerRenderedLoginIsGone is the other half of DoD §6.2. The routes are
// asserted absent in-process by internal/oauth/routes_legacy_login_test.go;
// this checks the running service, because a route table and a deployed binary
// are not the same claim.
func TestServerRenderedLoginIsGone(t *testing.T) {
	for _, probe := range []struct {
		method string
		path   string
	}{
		{"GET", "/oauth/login?login_session=whatever"},
		{"POST", "/oauth/authorize/callback"},
		{"POST", "/oauth/authorize/mfa"},
		{"POST", "/oauth/authorize/mfa/method"},
		{"POST", "/oauth/authorize/mfa/send"},
		{"POST", "/oauth/authorize/mfa/push"},
		{"GET", "/oauth/authorize/mfa/wait"},
	} {
		t.Run(probe.method+" "+probe.path, func(t *testing.T) {
			req, err := http.NewRequest(probe.method, oauthURL+probe.path, strings.NewReader(""))
			require.NoError(t, err)
			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)

			assert.Equal(t, http.StatusNotFound, resp.StatusCode,
				"%s %s answered %d; the server-rendered login is a second credential pipeline and must be gone",
				probe.method, probe.path, resp.StatusCode)
			assert.NotContains(t, string(raw), "<form",
				"%s %s returned an HTML form", probe.method, probe.path)
		})
	}

	// Positive control: the SPA's JSON login API is NOT the page being deleted
	// and must still answer. Without this, a service that 404'd everything
	// would pass the loop above.
	status, _ := apiRequest(t, "POST", oauthURL+"/oauth/login", `{"login_session":""}`, "")
	assert.NotEqual(t, http.StatusNotFound, status,
		"POST /oauth/login is the SPA's login API and must survive the deletion")
}

// TestAuthorizeRedirectsToTheOneLoginUI proves the replacement works end to
// end: a browser hitting either authorize endpoint is sent to OAUTH_LOGIN_URL
// with a login_session that /oauth/login can actually read.
//
// The v2 half is the one that was broken: storeAuthorizationRequest wrote an
// HMSet hash under "auth_request:<id>" while POST /oauth/login reads a JSON
// string under "login_session:<id>", so the v2 hop never completed for any
// client. Following the redirect through to a code is what proves the repair;
// asserting only the Location would have passed before it.
func TestAuthorizeRedirectsToTheOneLoginUI(t *testing.T) {
	for _, endpoint := range []string{"/oauth/authorize", "/oauth/authorize/v2"} {
		t.Run(endpoint, func(t *testing.T) {
			_, challenge := pkcePair()
			q := url.Values{
				"response_type":         {"code"},
				"client_id":             {clientID},
				"redirect_uri":          {redirectURI},
				"scope":                 {"openid profile email"},
				"code_challenge":        {challenge},
				"code_challenge_method": {"S256"},
			}
			req, err := http.NewRequest("GET", oauthURL+endpoint+"?"+q.Encode(), nil)
			require.NoError(t, err)
			// httpClient does not follow redirects (CheckRedirect), which is
			// what lets this read the Location the browser would have followed.
			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)

			require.Equal(t, http.StatusFound, resp.StatusCode,
				"%s should redirect to the login UI, got %d: %s", endpoint, resp.StatusCode, string(raw))
			loc, err := url.Parse(resp.Header.Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, "/login", loc.Path,
				"%s redirected to %q, want the one login UI", endpoint, resp.Header.Get("Location"))
			assert.NotEqual(t, redirectURI, resp.Header.Get("Location"),
				"%s sent the browser back to the client's own redirect_uri — that shape needs a login page at the client", endpoint)
			session := loc.Query().Get("login_session")
			require.NotEmpty(t, session,
				"%s carries no login_session, so the login page has nothing to submit", endpoint)

			status, body := loginAttempt(t, adminUsername, adminPassword, session)
			require.Equal(t, http.StatusOK, status,
				"the login_session %s handed out was not usable at POST /oauth/login: %v", endpoint, body)
			assert.NotEmpty(t, extractAuthCode(body),
				"login with %s's session produced no authorization code: %v", endpoint, body)
		})
	}
}
