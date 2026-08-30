package oauth

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

// TestAuthorizationRedirectURL covers the redirect the login page navigates on
// once an authorization code exists.
func TestAuthorizationRedirectURL(t *testing.T) {
	tests := []struct {
		name        string
		redirectURI string
		code        string
		state       string
		wantCode    string
		wantState   string
		wantEmpty   bool
	}{
		{name: "code and state", redirectURI: "https://app.example.com/callback", code: "abc123", state: "xyz", wantCode: "abc123", wantState: "xyz"},
		{name: "no state", redirectURI: "https://app.example.com/callback", code: "abc123", wantCode: "abc123"},
		{name: "preserves existing query", redirectURI: "https://app.example.com/callback?tenant=acme", code: "abc123", wantCode: "abc123"},
		{name: "unparsable redirect_uri", redirectURI: "://nope", code: "abc123", wantEmpty: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authorizationRedirectURL(tt.redirectURI, tt.code, tt.state)
			if tt.wantEmpty {
				if got != "" {
					t.Fatalf("authorizationRedirectURL() = %q, want empty", got)
				}
				return
			}
			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("result is not a URL: %v", err)
			}
			if u.Query().Get("code") != tt.wantCode {
				t.Errorf("code = %q, want %q", u.Query().Get("code"), tt.wantCode)
			}
			if u.Query().Get("state") != tt.wantState {
				t.Errorf("state = %q, want %q", u.Query().Get("state"), tt.wantState)
			}
			if strings.Contains(tt.redirectURI, "tenant=acme") && u.Query().Get("tenant") != "acme" {
				t.Errorf("existing query param dropped: %q", got)
			}
		})
	}
}

// TestAuthorizationCodeResponse pins the JSON contract of every browser-facing
// login step: the console only navigates when redirect_url is present, so a
// response missing it strands the user (the MFA screen used to do exactly that).
func TestAuthorizationCodeResponse(t *testing.T) {
	body := authorizationCodeResponse("https://app.example.com/callback?code=abc", "")
	if _, ok := body["redirect_url"]; !ok {
		t.Fatal("response must always carry redirect_url")
	}
	if _, ok := body["trusted_browser_id"]; ok {
		t.Error("trusted_browser_id must be omitted when no browser was trusted")
	}

	body = authorizationCodeResponse("https://app.example.com/callback?code=abc", "tb-1")
	if body["trusted_browser_id"] != "tb-1" {
		t.Errorf("trusted_browser_id = %v, want tb-1", body["trusted_browser_id"])
	}
}

// TestSingleAuthorizationCodeIssuancePath guards the regression this file was
// written for: the MFA flow once minted its own code into a bare "auth_code:"
// Redis key that nothing reads, instead of persisting it via
// CreateAuthorizationCode like every other login path. Authorization codes must
// be issued in exactly one place.
func TestSingleAuthorizationCodeIssuancePath(t *testing.T) {
	src, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("read service.go: %v", err)
	}
	if strings.Contains(string(src), `"auth_code:"`) {
		t.Error(`service.go writes a bare "auth_code:" Redis key — authorization codes must go through CreateAuthorizationCode (the token endpoint consumes oauth_authorization_codes)`)
	}
	// The MFA flow must not issue on its own: it delegates to the shared path.
	fn := string(src)[strings.Index(string(src), "func (s *Service) issueAuthorizationCodeWithTrust("):]
	fn = fn[:strings.Index(fn, "\n}\n")]
	if !strings.Contains(fn, "s.issueAuthorizationCode(") {
		t.Error("issueAuthorizationCodeWithTrust must delegate to issueAuthorizationCode")
	}
	if strings.Contains(fn, "CreateAuthorizationCode") || strings.Contains(fn, "GenerateRandomToken") {
		t.Error("issueAuthorizationCodeWithTrust must not mint or persist a code of its own")
	}
}
