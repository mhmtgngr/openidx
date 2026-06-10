//go:build integration

package integration

import (
	"net/http"
	"testing"
)

// All step-up endpoints require BOTH a user_id AND a session_id claim
// (sid) in the JWT.
//
// Before issue #124 was fixed, the admin OAuth access token didn't
// include sid, so these handlers all returned 401. The fix landed in
// the /oauth/token authorization-code handler: if the Redis bridge
// `authcode_session:<code>` is empty, the handler now falls back to
// the user's most-recently-started active session for that client.
// With the fix in place these tests exercise the real happy path.

// TestStepUpChallenge covers POST /oauth/stepup-challenge.
func TestStepUpChallenge(t *testing.T) {
	t.Run("rejects unauthenticated requests", func(t *testing.T) {
		status, body := apiRequest(t, "POST", oauthURL+"/oauth/stepup-challenge", `{"reason":"test"}`, "")
		if status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401; body = %v", status, body)
		}
	})

	t.Run("happy path returns challenge_id + expires_at + available_methods", func(t *testing.T) {
		tok := getAdminToken(t)
		status, body := apiRequest(t, "POST", oauthURL+"/oauth/stepup-challenge", `{"reason":"high-value-transfer"}`, tok)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %v", status, body)
		}
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

	t.Run("empty body falls back to default reason", func(t *testing.T) {
		tok := getAdminToken(t)
		status, body := apiRequest(t, "POST", oauthURL+"/oauth/stepup-challenge", "", tok)
		if status != http.StatusOK {
			t.Errorf("empty body: status = %d, want 200; body = %v", status, body)
		}
	})
}

// TestStepUpStatus covers GET /oauth/stepup-status/:id.
func TestStepUpStatus(t *testing.T) {
	t.Run("returns 404 for an unknown challenge id", func(t *testing.T) {
		tok := getAdminToken(t)
		status, _ := apiRequest(t, "GET",
			oauthURL+"/oauth/stepup-status/00000000-0000-0000-0000-000000000000",
			"", tok)
		if status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
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

	t.Run("round-trips a freshly created challenge", func(t *testing.T) {
		tok := getAdminToken(t)

		status, body := apiRequest(t, "POST", oauthURL+"/oauth/stepup-challenge", `{"reason":"round-trip-test"}`, tok)
		if status != http.StatusOK {
			t.Fatalf("create: status = %d, want 200; body = %v", status, body)
		}
		challengeID, _ := body["challenge_id"].(string)
		if challengeID == "" {
			t.Fatalf("create: challenge_id missing; body = %v", body)
		}

		status, body = apiRequest(t, "GET", oauthURL+"/oauth/stepup-status/"+challengeID, "", tok)
		if status != http.StatusOK {
			t.Fatalf("status: status = %d, want 200; body = %v", status, body)
		}
		// A fresh challenge has status == "pending".
		if got, _ := body["status"].(string); got != "pending" {
			t.Errorf("status field = %q, want pending; body = %v", got, body)
		}
	})
}

// TestStepUpVerify exercises only the validation-gate paths. Reaching
// the success path requires a registered MFA method + a valid OTP,
// which is exercised end-to-end by mfa_flow_test.go.
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
