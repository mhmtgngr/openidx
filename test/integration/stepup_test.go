//go:build integration

package integration

import (
	"net/http"
	"testing"
)

// All step-up endpoints require BOTH a user_id AND a session_id claim
// (sid) in the JWT. The admin token issued through the password-flow
// login path used by getAdminToken does not carry a sid claim — see the
// follow-up bug filed alongside this PR — so the only paths these tests
// exercise are the unauth / missing-session rejection gates.
//
// When the sid-claim bug is fixed, round-trip happy-path tests can be
// added: create with /stepup-challenge, fetch with /stepup-status,
// confirm status == "pending".

// TestStepUpChallenge_AuthGate verifies the 401 path on POST /oauth/stepup-challenge.
func TestStepUpChallenge_AuthGate(t *testing.T) {
	t.Run("rejects unauthenticated requests", func(t *testing.T) {
		status, body := apiRequest(t, "POST", oauthURL+"/oauth/stepup-challenge", `{"reason":"test"}`, "")
		if status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401; body = %v", status, body)
		}
	})

	t.Run("token-without-sid is rejected by the handler", func(t *testing.T) {
		// The admin token from getAdminToken is a valid OAuth access token
		// but carries no sid claim. The Auth middleware lets it through
		// (user_id is populated) but the stepup handler runs a defense-
		// in-depth check that requires session_id and rejects with 401.
		tok := getAdminToken(t)
		status, body := apiRequest(t, "POST", oauthURL+"/oauth/stepup-challenge", `{"reason":"test"}`, tok)
		if status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 (no sid claim); body = %v", status, body)
		}
		if msg, _ := body["error_description"].(string); msg == "" {
			t.Errorf("missing error_description in body = %v", body)
		}
	})
}

// TestStepUpStatus_AuthGate verifies the 401 path on GET /oauth/stepup-status/:id.
func TestStepUpStatus_AuthGate(t *testing.T) {
	status, _ := apiRequest(t, "GET",
		oauthURL+"/oauth/stepup-status/00000000-0000-0000-0000-000000000000",
		"", "")
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
}

// TestStepUpVerify_AuthGate verifies the 401 path on POST /oauth/stepup-verify.
func TestStepUpVerify_AuthGate(t *testing.T) {
	body := `{"challenge_id":"00000000-0000-0000-0000-000000000000","method":"totp","code":"000000"}`
	status, _ := apiRequest(t, "POST", oauthURL+"/oauth/stepup-verify", body, "")
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
}
