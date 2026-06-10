//go:build integration

package integration

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// freshLoginSession obtains a one-shot login_session by hitting /oauth/authorize
// with Accept: application/json. The PKCE pair is unique per call so the
// session won't collide with another test.
func freshLoginSession(t *testing.T) string {
	t.Helper()

	_, challenge := pkcePair()
	authURL := fmt.Sprintf(
		"%s/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email&code_challenge=%s&code_challenge_method=S256",
		oauthURL, clientID, url.QueryEscape(redirectURI), challenge,
	)
	req, _ := http.NewRequest("GET", authURL, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("freshLoginSession: authorize: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 302 {
		t.Fatalf("freshLoginSession: status %d body %s", resp.StatusCode, string(body))
	}
	s := extractLoginSession(resp, body)
	if s == "" {
		t.Fatalf("freshLoginSession: empty session in response: status %d body %s", resp.StatusCode, string(body))
	}
	return s
}

// TestMagicLink_Create covers POST /oauth/magic-link. The endpoint MUST
// always return 200 for any "could-be-an-email" input so attackers can't
// enumerate registered emails — but it must still fail loudly when its own
// inputs are wrong (missing fields, invalid session).
func TestMagicLink_Create(t *testing.T) {
	t.Run("rejects missing email", func(t *testing.T) {
		body := `{"login_session":"sess-xyz"}`
		status, _ := apiRequest(t, "POST", oauthURL+"/oauth/magic-link", body, "")
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("rejects missing login_session", func(t *testing.T) {
		body := `{"email":"alice@example.com"}`
		status, _ := apiRequest(t, "POST", oauthURL+"/oauth/magic-link", body, "")
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("rejects malformed body", func(t *testing.T) {
		status, _ := apiRequest(t, "POST", oauthURL+"/oauth/magic-link", `{not-json`, "")
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("rejects unknown login_session", func(t *testing.T) {
		body := `{"email":"alice@example.com","login_session":"never-allocated-session-xyz"}`
		status, _ := apiRequest(t, "POST", oauthURL+"/oauth/magic-link", body, "")
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 (invalid session)", status)
		}
	})

	t.Run("valid session + unknown email returns 200 (anti-enumeration)", func(t *testing.T) {
		// The handler intentionally returns 200 with a generic "if an account
		// exists" message regardless of whether the email is registered,
		// preventing email enumeration. We exercise that branch by sending
		// a guaranteed-unknown email with a valid session.
		sess := freshLoginSession(t)
		body := fmt.Sprintf(`{"email":"nobody-%s@nowhere.invalid","login_session":%q}`,
			strings.ReplaceAll(sess[:8], "/", "-"), sess)
		status, respBody := apiRequest(t, "POST", oauthURL+"/oauth/magic-link", body, "")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (anti-enum); body = %v", status, respBody)
		}
		msg, _ := respBody["message"].(string)
		if msg == "" {
			t.Errorf("response missing message; body = %v", respBody)
		}
	})
}

// TestMagicLink_Verify covers GET /oauth/magic-link-verify. With no token
// the handler redirects to /login?error; the only happy paths require a
// real magic-link record (created by the real identity service).
func TestMagicLink_Verify(t *testing.T) {
	t.Run("missing token returns 4xx or redirect-with-error", func(t *testing.T) {
		// We have to disable CheckRedirect here because the handler
		// often returns a 302 to /login?error=... — the shared httpClient
		// already returns ErrUseLastResponse so we see the redirect.
		status, body := apiRequest(t, "GET", oauthURL+"/oauth/magic-link-verify", "", "")
		// Accept anything in [302, 499] — the handler may render a 400
		// JSON page OR redirect to /login with an error query.
		if status < 300 || status >= 500 {
			t.Errorf("status = %d, want 3xx redirect or 4xx; body = %v", status, body)
		}
	})

	t.Run("unknown token rejected", func(t *testing.T) {
		status, body := apiRequest(t, "GET",
			oauthURL+"/oauth/magic-link-verify?token=does-not-exist&login_session=sess",
			"", "")
		if status < 300 || status >= 500 {
			t.Errorf("status = %d, want 3xx/4xx; body = %v", status, body)
		}
	})
}

// TestQRLoginCreate covers POST /oauth/qr-login/create.
func TestQRLoginCreate(t *testing.T) {
	t.Run("rejects missing login_session", func(t *testing.T) {
		status, _ := apiRequest(t, "POST", oauthURL+"/oauth/qr-login/create", `{}`, "")
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("rejects malformed body", func(t *testing.T) {
		status, _ := apiRequest(t, "POST", oauthURL+"/oauth/qr-login/create", `{not-json`, "")
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("rejects login_session in invalid format (Redis-injection guard)", func(t *testing.T) {
		// The handler runs isValidSessionID before any Redis read to keep
		// attackers from injecting arbitrary characters into Redis keys.
		body := `{"login_session":"foo:bar baz/qux"}`
		status, respBody := apiRequest(t, "POST", oauthURL+"/oauth/qr-login/create", body, "")
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400; body = %v", status, respBody)
		}
	})

	t.Run("rejects unknown login_session", func(t *testing.T) {
		// Well-formed but not allocated.
		body := `{"login_session":"abcdefghijklmnopqrstuvwxyz012345"}`
		status, _ := apiRequest(t, "POST", oauthURL+"/oauth/qr-login/create", body, "")
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 (invalid session)", status)
		}
	})

	t.Run("valid session returns qr_content + session_token", func(t *testing.T) {
		// Restored after #125: isValidSessionID now accepts the
		// base64url login_session shape that /oauth/authorize produces.
		sess := freshLoginSession(t)
		body := fmt.Sprintf(`{"login_session":%q}`, sess)
		status, respBody := apiRequest(t, "POST", oauthURL+"/oauth/qr-login/create", body, "")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %v", status, respBody)
		}
		if respBody["session_token"] == nil || respBody["session_token"] == "" {
			t.Errorf("missing session_token; body = %v", respBody)
		}
		qr, _ := respBody["qr_content"].(string)
		if !strings.HasPrefix(qr, "openidx://qr-login?session=") {
			t.Errorf("qr_content = %q, want openidx://qr-login?session=...", qr)
		}
		if respBody["expires_at"] == nil {
			t.Errorf("missing expires_at; body = %v", respBody)
		}
	})
}

// TestQRLoginPoll covers GET /oauth/qr-login/poll.
func TestQRLoginPoll(t *testing.T) {
	t.Run("rejects missing query params", func(t *testing.T) {
		status, _ := apiRequest(t, "GET", oauthURL+"/oauth/qr-login/poll", "", "")
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("rejects only one of the two params", func(t *testing.T) {
		status, _ := apiRequest(t, "GET", oauthURL+"/oauth/qr-login/poll?session_token=abc", "", "")
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 (login_session also required)", status)
		}
	})

	t.Run("rejects bad session_token format (Redis-injection guard)", func(t *testing.T) {
		q := "session_token=" + url.QueryEscape("with spaces") +
			"&login_session=abcdefghijklmnopqrstuvwxyz012345"
		status, _ := apiRequest(t, "GET", oauthURL+"/oauth/qr-login/poll?"+q, "", "")
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("returns 404 when session_token unknown", func(t *testing.T) {
		// Restored after #125: a 32-char base64url-style token now
		// passes the validator and the handler reaches the QR-session
		// lookup, which 404s for an unknown token.
		q := "session_token=abcdefghijklmnopqrstuvwxyz012345" +
			"&login_session=abcdefghijklmnopqrstuvwxyz012345"
		status, _ := apiRequest(t, "GET", oauthURL+"/oauth/qr-login/poll?"+q, "", "")
		if status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})
}

// TestPasskeyBegin covers POST /oauth/passkey-begin. Reaching the success
// path requires a registered WebAuthn credential; we only exercise the
// validation gates here. The full WebAuthn dance is exercised by the
// existing user-facing tests in mfa_flow_test.go.
func TestPasskeyBegin(t *testing.T) {
	t.Run("rejects malformed body", func(t *testing.T) {
		status, _ := apiRequest(t, "POST", oauthURL+"/oauth/passkey-begin", `{not-json`, "")
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("missing email returns 4xx", func(t *testing.T) {
		status, body := apiRequest(t, "POST", oauthURL+"/oauth/passkey-begin", `{}`, "")
		if status < 400 || status >= 500 {
			t.Errorf("status = %d, want 4xx; body = %v", status, body)
		}
	})
}

