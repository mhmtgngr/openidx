//go:build integration

// Package integration provides end-to-end integration tests for OpenIDX services.
// These tests require running PostgreSQL, Redis, and OpenIDX services.
// Run with: go test -v -tags=integration ./test/integration/...
package integration

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Service URLs (configurable via environment variables)
var (
	oauthURL    = envOrDefault("OAUTH_URL", "http://localhost:8006")
	identityURL = envOrDefault("IDENTITY_URL", "http://localhost:8001")
	clientID    = "admin-console"
	redirectURI = "http://localhost:3000/login"
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

// createTestUser creates a user for testing and returns the user ID
func createTestUser(t *testing.T, username, email, password string) string {
	t.Helper()

	userData := fmt.Sprintf(`{
		"username": %q,
		"email": %q,
		"first_name": "Integration",
		"last_name": "Test",
		"enabled": true,
		"email_verified": true
	}`, username, email)

	status, body := apiRequest(t, "POST", identityURL+"/api/v1/identity/users", userData, "")

	if status != 201 {
		t.Fatalf("Failed to create test user: status %d, body %v", status, body)
	}

	id, ok := body["id"].(string)
	if !ok {
		t.Fatal("User response missing 'id' field")
	}

	// Set password
	passData := fmt.Sprintf(`{"password": %q}`, password)
	apiRequest(t, "POST", fmt.Sprintf("%s/api/v1/identity/users/%s/set-password", identityURL, id), passData, "")

	return id
}

// deleteTestUser removes a test user
func deleteTestUser(t *testing.T, userID string) {
	t.Helper()
	apiRequest(t, "DELETE", identityURL+"/api/v1/identity/users/"+userID, "", "")
}

// loginAndGetToken performs the full OAuth flow and returns an access token
func loginAndGetToken(t *testing.T, username, password string) string {
	t.Helper()

	// Step 1: Initiate authorization
	authURL := fmt.Sprintf("%s/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email",
		oauthURL, clientID, url.QueryEscape(redirectURI))

	req, _ := http.NewRequest("GET", authURL, nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Authorization request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 302 {
		t.Fatalf("Expected 302 redirect, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	redirectURL, _ := url.Parse(location)
	loginSession := redirectURL.Query().Get("login_session")
	if loginSession == "" {
		t.Fatal("No login_session in redirect URL")
	}

	// Step 2: Login
	loginData := fmt.Sprintf(`{"username":%q,"password":%q,"login_session":%q}`,
		username, password, loginSession)

	status, loginBody := apiRequest(t, "POST", oauthURL+"/oauth/login", loginData, "")
	if status != 200 {
		t.Fatalf("Login failed: status %d, body %v", status, loginBody)
	}

	redirectWithCode, _ := loginBody["redirect_url"].(string)
	codeURL, _ := url.Parse(redirectWithCode)
	code := codeURL.Query().Get("code")
	if code == "" {
		t.Fatal("No auth code in login response redirect URL")
	}

	// Step 3: Exchange code for tokens
	status, tokenBody := formRequest(t, oauthURL+"/oauth/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
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
