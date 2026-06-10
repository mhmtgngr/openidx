//go:build integration

package integration

import (
	"net/http"
	"testing"
)

// TestStepUpChallenge covers the /oauth/stepup-challenge endpoint. The handler
// requires a valid session in the JWT (extracted by the Auth middleware from
// the sid claim) — we use the admin token from getAdminToken which carries
// both user_id and session_id.
func TestStepUpChallenge(t *testing.T) {
	t.Run("rejects unauthenticated requests", func(t *testing.T) {
		status, body := apiRequest(t, "POST", oauthURL+"/oauth/stepup-challenge", `{"reason":"test"}`, "")
		// The Auth middleware will reject with 401 before the handler runs.
		// (The handler itself also returns 401 if user_id/session_id are
		// empty — defense in depth.)
		if status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401; body = %v", status, body)
		}
	})

	t.Run("happy path returns challenge_id + expires_at", func(t *testing.T) {
		tok := getAdminToken(t)
		status, body := apiRequest(t, "POST", oauthURL+"/oauth/stepup-challenge", `{"reason":"high-value-transfer"}`, tok)

		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %v", status, body)
		}
		// The handler must echo back enough for the client to display a
		// challenge UI: an ID, an expiry, and the methods the user has
		// available. We don't lock to a specific list (test runner may not
		// have MFA registered) but the field must exist.
		if _, ok := body["challenge_id"]; !ok {
			t.Errorf("response missing challenge_id; body = %v", body)
		}
		if _, ok := body["expires_at"]; !ok {
			t.Errorf("response missing expires_at; body = %v", body)
		}
		if _, ok := body["available_methods"]; !ok {
			t.Errorf("response missing available_methods; body = %v", body)
		}
	})

	t.Run("default reason when body is empty or malformed", func(t *testing.T) {
		// The handler tolerates a missing/malformed body and defaults the
		// reason to "manual"; the call should still succeed.
		tok := getAdminToken(t)
		status, body := apiRequest(t, "POST", oauthURL+"/oauth/stepup-challenge", "", tok)
		if status != http.StatusOK {
			t.Errorf("empty body: status = %d, want 200; body = %v", status, body)
		}
	})
}

// TestStepUpStatus covers GET /oauth/stepup-status/:id. Unknown IDs return
// 404; a freshly-created challenge can be fetched and its status read.
func TestStepUpStatus(t *testing.T) {
	t.Run("returns 404 for an unknown challenge id", func(t *testing.T) {
		tok := getAdminToken(t)
		// UUID-shaped but never inserted.
		status, _ := apiRequest(t, "GET",
			oauthURL+"/oauth/stepup-status/00000000-0000-0000-0000-000000000000",
			"", tok)
		if status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("round-trips a freshly created challenge", func(t *testing.T) {
		tok := getAdminToken(t)

		// Create a challenge to fetch.
		status, body := apiRequest(t, "POST", oauthURL+"/oauth/stepup-challenge", `{"reason":"round-trip-test"}`, tok)
		if status != http.StatusOK {
			t.Fatalf("create: status = %d, want 200; body = %v", status, body)
		}
		challengeID, _ := body["challenge_id"].(string)
		if challengeID == "" {
			t.Fatalf("create: challenge_id missing; body = %v", body)
		}

		// Fetch its status.
		status, body = apiRequest(t, "GET", oauthURL+"/oauth/stepup-status/"+challengeID, "", tok)
		if status != http.StatusOK {
			t.Fatalf("status: status = %d, want 200; body = %v", status, body)
		}
		// A fresh challenge is "pending".
		if got, _ := body["status"].(string); got != "pending" {
			t.Errorf("status field = %q, want pending; body = %v", got, body)
		}
	})

	t.Run("requires authentication", func(t *testing.T) {
		status, _ := apiRequest(t, "GET",
			oauthURL+"/oauth/stepup-status/00000000-0000-0000-0000-000000000000",
			"", "")
		if status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", status)
		}
	})
}

// TestStepUpVerify only exercises the validation/auth-gate paths. Reaching
// the success path requires a registered MFA method + a valid OTP, which is
// a much bigger setup; the happy path is exercised end-to-end by
// mfa_flow_test.go.
func TestStepUpVerify(t *testing.T) {
	t.Run("rejects unauthenticated requests", func(t *testing.T) {
		body := `{"challenge_id":"00000000-0000-0000-0000-000000000000","method":"totp","code":"000000"}`
		status, _ := apiRequest(t, "POST", oauthURL+"/oauth/stepup-verify", body, "")
		if status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", status)
		}
	})

	t.Run("rejects unknown challenge", func(t *testing.T) {
		tok := getAdminToken(t)
		body := `{"challenge_id":"00000000-0000-0000-0000-000000000000","method":"totp","code":"000000"}`
		status, respBody := apiRequest(t, "POST", oauthURL+"/oauth/stepup-verify", body, tok)
		// Could be 404 ("challenge not found") or 400 ("invalid request") —
		// both are acceptable; what matters is we don't silently accept.
		if status != http.StatusNotFound && status != http.StatusBadRequest {
			t.Errorf("status = %d, want 404 or 400; body = %v", status, respBody)
		}
	})

	t.Run("rejects malformed body", func(t *testing.T) {
		tok := getAdminToken(t)
		status, _ := apiRequest(t, "POST", oauthURL+"/oauth/stepup-verify", `{not-json`, tok)
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})
}
