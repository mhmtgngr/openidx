package oauth

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/openidx/openidx/internal/common/middleware"
)

// LINKING A SOCIAL ACCOUNT NEEDS THE ACCOUNT HOLDER, NOT ONLY THEIR TOKEN.
//
// POST /oauth/social/link/:provider_id/start took a bearer token and nothing
// else, and the account it linked then signed in to this one. A token read out
// of the console's localStorage could attach the thief's own account and keep a
// way in after the token expired. An account with a password or a second
// factor now needs the password, or a current TOTP code, in the request body,
// as a change to its factors does; an account with neither has nothing to give.
func TestLinkingASocialAccountNeedsProof(t *testing.T) {
	x := newExternalHarness(t)
	start := func(user string, body map[string]string) (int, map[string]interface{}) {
		return x.post("/oauth/social/link/"+x.idp+"/start", x.accessToken(defaultOrg, user), body)
	}
	refused := func(t *testing.T, status int, out map[string]interface{}, code string, accepts ...string) {
		t.Helper()
		if status != http.StatusForbidden || out["error"] != code {
			t.Fatalf("status %d (%v), want 403 %s", status, out, code)
		}
		got, _ := out["accepts"].([]interface{})
		if len(got) != len(accepts) {
			t.Fatalf("accepts %v, want %v", got, accepts)
		}
		for i, a := range accepts {
			if got[i] != a {
				t.Fatalf("accepts %v, want %v", got, accepts)
			}
		}
	}

	t.Run("an account with a password", func(t *testing.T) {
		user := x.seedUser(middleware.DefaultOrgID, "link-pw")
		x.linkedUserPassword(user)
		status, out := start(user, nil)
		refused(t, status, out, "reauthentication_required", "current_password")
		status, out = start(user, map[string]string{"current_password": "not it"})
		refused(t, status, out, "reauthentication_failed", "current_password")
		status, out = start(user, map[string]string{"current_password": externalPassword})
		if status != http.StatusOK || out["authorization_url"] == nil {
			t.Fatalf("with the password: %d (%v), want the authorization URL", status, out)
		}

		// The link completes, and the account signs in through the provider.
		authURL, _ := url.Parse(out["authorization_url"].(string))
		sub := "linked-" + x.suffix
		email := x.scalar(`SELECT email FROM users WHERE id = $1::uuid`, user)
		w := x.get("/oauth/social/link/callback?" + url.Values{
			"code": {x.provider.code(sub, email)}, "state": {authURL.Query().Get("state")},
		}.Encode())
		if w.Code != http.StatusOK {
			t.Fatalf("link callback: %d %s", w.Code, w.Body.String())
		}
		if n := x.scalar(`SELECT COUNT(*)::text FROM social_account_links WHERE user_id = $1::uuid`, user); n != "1" {
			t.Fatalf("%s links after the callback, want 1", n)
		}
	})

	t.Run("an account whose factor is TOTP and that has no password", func(t *testing.T) {
		user := x.seedUser(middleware.DefaultOrgID, "link-totp")
		key, _ := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: "link-totp"})
		x.exec(`INSERT INTO mfa_totp (user_id, secret, enabled, enrolled_at, org_id)
			VALUES ($1::uuid, $2, true, NOW(), $3::uuid)`, user, key.Secret(), middleware.DefaultOrgID)
		status, out := start(user, nil)
		refused(t, status, out, "reauthentication_required", "totp_code")
		code, _ := totp.GenerateCode(key.Secret(), time.Now())
		if status, out := start(user, map[string]string{"totp_code": code}); status != http.StatusOK {
			t.Fatalf("with a current code: %d (%v), want 200", status, out)
		}
		if status, out := start(user, map[string]string{"totp_code": code}); status != http.StatusForbidden {
			t.Fatalf("the same code again: %d (%v), want 403", status, out)
		}
	})

	t.Run("an account with neither needs only the token", func(t *testing.T) {
		user := x.seedUser(middleware.DefaultOrgID, "link-bare")
		if status, out := start(user, nil); status != http.StatusOK || out["authorization_url"] == nil {
			t.Fatalf("status %d (%v), want the authorization URL", status, out)
		}
	})
}

func (x *externalHarness) linkedUserPassword(userID string) {
	x.t.Helper()
	hash := x.passwordHash()
	x.exec(`UPDATE users SET password_hash = $1 WHERE id = $2::uuid`, hash, userID)
}
