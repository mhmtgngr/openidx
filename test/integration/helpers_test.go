//go:build integration

// Package integration provides end-to-end integration tests for OpenIDX services.
// These tests require running PostgreSQL, Redis, and OpenIDX services.
// Run with: go test -v -tags=integration ./test/integration/...
package integration

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Service URLs (configurable via environment variables)
var (
	oauthURL    = envOrDefault("OAUTH_URL", "http://localhost:8006")
	identityURL = envOrDefault("IDENTITY_URL", "http://localhost:8001")
	clientID    = "admin-console"
	// Must match the redirect_uri the admin-console client is seeded with
	// (deployments seed migration v10) — previously /login, which never
	// matched, so authorize returned invalid_request.
	redirectURI = "http://localhost:3000/callback"

	// Admin credentials seeded by migration v10. The password is hard-coded
	// in the seed (bcrypt hash); these are the dev/test defaults and are
	// expected to be rotated in real deployments. Override with env vars if
	// the seed is different in your environment.
	adminUsername = envOrDefault("INTEGRATION_ADMIN_USERNAME", "admin")
	adminPassword = envOrDefault("INTEGRATION_ADMIN_PASSWORD", "Admin@123")
)

// adminTokenOnce + adminTokenCached memoize getAdminToken so we only run the
// OAuth dance once per test binary.
var (
	adminTokenOnce   sync.Once
	adminTokenCached string
	adminTokenErr    error
)

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// httpClient is a shared HTTP client with reasonable timeouts
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // Don't follow redirects
	},
}

// apiRequest makes an HTTP request and returns status code and body
func apiRequest(t *testing.T, method, url string, body string, token string) (int, map[string]interface{}) {
	t.Helper()

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	var result map[string]interface{}
	if len(respBody) > 0 {
		json.Unmarshal(respBody, &result) // Ignore errors for non-JSON responses
	}

	return resp.StatusCode, result
}

// formRequest makes a form-encoded POST request (for OAuth token endpoint)
func formRequest(t *testing.T, endpoint string, data url.Values) (int, map[string]interface{}) {
	t.Helper()

	resp, err := httpClient.PostForm(endpoint, data)
	if err != nil {
		t.Fatalf("Form request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	return resp.StatusCode, result
}

// decodeJWTPayload extracts and decodes the payload from a JWT token
func decodeJWTPayload(t *testing.T, token string) map[string]interface{} {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("Invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	payload := parts[1]
	// Add padding
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("Failed to decode JWT payload: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		t.Fatalf("Failed to parse JWT claims: %v", err)
	}

	return claims
}

// pkcePair returns a fresh (verifier, challenge) pair using S256.
func pkcePair() (verifier, challenge string) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// rand.Read failing is essentially impossible; fall back to a fixed
		// (test-only) verifier so the test fails on the assertion rather than
		// silently.
		b = []byte("integration-test-fallback-verifier")
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// getAdminToken runs the full PKCE OAuth code flow as the seeded admin user
// once per process and returns the access_token. Use this to make admin-only
// requests (e.g., createTestUser hits POST /api/v1/identity/users which is
// gated behind the admin role per the #79 deny-by-default fix).
func getAdminToken(t *testing.T) string {
	t.Helper()
	adminTokenOnce.Do(func() {
		adminTokenCached, adminTokenErr = doAdminLogin()
	})
	if adminTokenErr != nil {
		t.Fatalf("getAdminToken: %v", adminTokenErr)
	}
	return adminTokenCached
}

func doAdminLogin() (string, error) {
	verifier, challenge := pkcePair()

	// Step 1: /oauth/authorize — request a code with PKCE. Public clients
	// render an HTML page unless we set Accept: application/json, in which
	// case the server hands back { "login_session": "..." } instead.
	authURL := fmt.Sprintf(
		"%s/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email&code_challenge=%s&code_challenge_method=S256",
		oauthURL, clientID, url.QueryEscape(redirectURI), challenge,
	)
	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return "", fmt.Errorf("build authorize request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("authorize: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 302 {
		return "", fmt.Errorf("authorize: status %d body %s", resp.StatusCode, string(body))
	}
	loginSession := extractLoginSession(resp, body)
	if loginSession == "" {
		return "", fmt.Errorf("authorize: no login_session in response (status %d body %s)", resp.StatusCode, string(body))
	}

	// Step 2: /oauth/login — submit credentials.
	loginPayload := fmt.Sprintf(`{"username":%q,"password":%q,"login_session":%q}`, adminUsername, adminPassword, loginSession)
	req, _ = http.NewRequest("POST", oauthURL+"/oauth/login", strings.NewReader(loginPayload))
	req.Header.Set("Content-Type", "application/json")
	resp, err = httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("login: %w", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("login: status %d body %s", resp.StatusCode, string(body))
	}
	var loginResp map[string]interface{}
	_ = json.Unmarshal(body, &loginResp)
	code := extractAuthCode(loginResp)
	if code == "" {
		return "", fmt.Errorf("login: no authorization code in response: %s", string(body))
	}

	// Step 3: /oauth/token — exchange the code (with PKCE verifier) for tokens.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	resp, err = httpClient.PostForm(oauthURL+"/oauth/token", form)
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("token: status %d body %s", resp.StatusCode, string(body))
	}
	var tokResp map[string]interface{}
	if err := json.Unmarshal(body, &tokResp); err != nil {
		return "", fmt.Errorf("token: decode: %w", err)
	}
	tok, _ := tokResp["access_token"].(string)
	if tok == "" {
		return "", fmt.Errorf("token: response missing access_token: %s", string(body))
	}
	return tok, nil
}

// extractLoginSession pulls the login_session value from either an
// Accept-JSON 200 response body or, as a fallback, a 302 Location header.
func extractLoginSession(resp *http.Response, body []byte) string {
	if resp.StatusCode == 200 && len(body) > 0 {
		var j map[string]interface{}
		if json.Unmarshal(body, &j) == nil {
			if s, _ := j["login_session"].(string); s != "" {
				return s
			}
		}
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		if u, err := url.Parse(loc); err == nil {
			return u.Query().Get("login_session")
		}
	}
	return ""
}

// extractAuthCode pulls the authorization code from either a `code` field
// directly or a `redirect_url` containing `?code=...`.
func extractAuthCode(body map[string]interface{}) string {
	if c, _ := body["code"].(string); c != "" {
		return c
	}
	if r, _ := body["redirect_url"].(string); r != "" {
		if u, err := url.Parse(r); err == nil {
			return u.Query().Get("code")
		}
	}
	return ""
}

// createTestUser creates a user for testing and returns the user ID. It
// authenticates as the seeded admin so the request passes the post-#79
// deny-by-default admin-API authz gate, and sends a SCIM-shaped payload so
// `internal/identity/models.User` can actually bind the values (the previous
// snake_case keys silently dropped username/email — every insert went in
// with empty strings and the second one collided on users_email_key).
func createTestUser(t *testing.T, username, email, password string) string {
	t.Helper()
	token := getAdminToken(t)

	// SCIM 2.0 shape (matches the User struct's `json:"…"` tags):
	//   userName, name.{givenName,familyName}, active, emails[].{value,primary}.
	userData := fmt.Sprintf(`{
		"userName": %q,
		"name": {"givenName": "Integration", "familyName": "Test"},
		"active": true,
		"emails": [{"value": %q, "primary": true}]
	}`, username, email)

	status, body := apiRequest(t, "POST", identityURL+"/api/v1/identity/users", userData, token)

	if status != 201 {
		t.Fatalf("Failed to create test user: status %d, body %v", status, body)
	}

	id, ok := body["id"].(string)
	if !ok {
		t.Fatal("User response missing 'id' field")
	}

	// Set password (admin-only). The set-password endpoint takes a flat
	// {"password": "..."} body — keeps the snake_case style its own handler
	// uses, distinct from the SCIM user payload above.
	passData := fmt.Sprintf(`{"password": %q}`, password)
	apiRequest(t, "POST", fmt.Sprintf("%s/api/v1/identity/users/%s/set-password", identityURL, id), passData, token)

	return id
}

// deleteTestUser removes a test user (admin-only).
func deleteTestUser(t *testing.T, userID string) {
	t.Helper()
	token := getAdminToken(t)
	apiRequest(t, "DELETE", identityURL+"/api/v1/identity/users/"+userID, "", token)
}

// beginAuthorizeForLogin issues GET /oauth/authorize for the seeded
// admin-console (public) client with `Accept: application/json` and an S256
// PKCE challenge, returning the `login_session` the test must POST back to
// /oauth/login and the matching PKCE verifier the test will need at the
// token-exchange step.
//
// Public clients without the JSON Accept header now get a rendered HTML 200
// (the SPA login page) instead of a 302, and the seeded admin-console client
// requires PKCE — inline test flows that hard-coded `require.Equal(302, ...)`
// and skipped `code_verifier` therefore broke at step 1.
func beginAuthorizeForLogin(t *testing.T, scope string, extra url.Values) (loginSession, codeVerifier string) {
	t.Helper()
	verifier, challenge := pkcePair()

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {scope},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	authURL := oauthURL + "/oauth/authorize?" + q.Encode()
	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		t.Fatalf("build authorize request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: expected 200 or 302, got %d body %s", resp.StatusCode, string(body))
	}
	loginSession = extractLoginSession(resp, body)
	if loginSession == "" {
		t.Fatalf("authorize: no login_session in response (status %d body %s)", resp.StatusCode, string(body))
	}
	return loginSession, verifier
}

// submitLoginForCode posts credentials to /oauth/login and returns the
// authorization code extracted from either a direct `code` field or a
// `redirect_url` containing `?code=...`.
func submitLoginForCode(t *testing.T, username, password, loginSession string) string {
	t.Helper()
	loginData := fmt.Sprintf(`{"username":%q,"password":%q,"login_session":%q}`,
		username, password, loginSession)
	status, body := apiRequest(t, "POST", oauthURL+"/oauth/login", loginData, "")
	if status != http.StatusOK {
		t.Fatalf("login: status %d body %v", status, body)
	}
	code := extractAuthCode(body)
	if code == "" {
		t.Fatalf("login: no authorization code in response: %v", body)
	}
	return code
}

// exchangeCodeWithPKCE swaps an authorization code (issued from a flow that
// began with beginAuthorizeForLogin) for a token response, sending the
// matching PKCE verifier.
func exchangeCodeWithPKCE(t *testing.T, code, verifier string) (int, map[string]interface{}) {
	t.Helper()
	return formRequest(t, oauthURL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
}

// loginAndGetToken performs the full PKCE OAuth code flow as the given user
// and returns an access token. The shape mirrors doAdminLogin:
//   - Accept: application/json on /oauth/authorize so the public admin-console
//     client gets the 302 SPA flow instead of the rendered HTML login page;
//   - S256 PKCE because the seeded admin-console client requires it;
//   - tolerant login_session/code extraction (json body OR redirect Location).
//
// The pre-#75 version expected an unconditional 302 with no Accept header and
// no PKCE — handleAuthorize now returns 200 HTML for that exact request shape,
// and the token endpoint requires the code_verifier, so the old helper failed
// at step 1 in every test that used it.
func loginAndGetToken(t *testing.T, username, password string) string {
	t.Helper()

	verifier, challenge := pkcePair()

	// Step 1: Initiate authorization (with PKCE + Accept: application/json).
	authURL := fmt.Sprintf(
		"%s/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email&code_challenge=%s&code_challenge_method=S256",
		oauthURL, clientID, url.QueryEscape(redirectURI), challenge,
	)
	req, _ := http.NewRequest("GET", authURL, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Authorization request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 302 {
		t.Fatalf("authorize: status %d body %s", resp.StatusCode, string(body))
	}
	loginSession := extractLoginSession(resp, body)
	if loginSession == "" {
		t.Fatalf("authorize: no login_session in response (status %d body %s)", resp.StatusCode, string(body))
	}

	// Step 2: Login
	loginData := fmt.Sprintf(`{"username":%q,"password":%q,"login_session":%q}`,
		username, password, loginSession)

	status, loginBody := apiRequest(t, "POST", oauthURL+"/oauth/login", loginData, "")
	if status != 200 {
		t.Fatalf("Login failed: status %d, body %v", status, loginBody)
	}

	code := extractAuthCode(loginBody)
	if code == "" {
		t.Fatalf("login: no authorization code in response: %v", loginBody)
	}

	// Step 3: Exchange code for tokens (with PKCE verifier).
	status, tokenBody := formRequest(t, oauthURL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})

	if status != 200 {
		t.Fatalf("Token exchange failed: status %d, body %v", status, tokenBody)
	}

	accessToken, ok := tokenBody["access_token"].(string)
	if !ok {
		t.Fatal("Token response missing access_token")
	}

	return accessToken
}
