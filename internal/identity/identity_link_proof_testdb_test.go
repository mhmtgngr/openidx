package identity

import (
	"net/http"
	"testing"

	"github.com/openidx/openidx/internal/common/middleware"
)

// UNLINKING AN EXTERNAL ACCOUNT NEEDS THE ACCOUNT HOLDER, AND UNLINKS IT.
//
// DELETE /users/me/identity-links/:linkId took the token alone. It deleted the
// user_identity_links row the profile screen lists and left the
// social_account_links row the social sign-in finds the account by, so the
// account the user had removed kept signing them in. It now needs the password
// or a current TOTP code when the account has either, as linking does, and
// removes both rows.
func TestUnlinkingAnExternalAccountNeedsProofAndUnlinksIt(t *testing.T) {
	h := newSelfServiceHarness(t)
	idp := h.scalar(`INSERT INTO identity_providers (name, provider_type, issuer_url, client_id, client_secret, enabled, org_id)
		VALUES ('Fed', 'oidc', $1, 'c', 's', true, $2::uuid) RETURNING id::text`,
		"https://fed-"+h.suffix+".example.test", middleware.DefaultOrgID)
	link := func(user, sub string) string {
		h.exec(`INSERT INTO social_account_links (user_id, provider_id, external_id, org_id)
			VALUES ($1::uuid, $2::uuid, $3, $4::uuid)`, user, idp, sub, middleware.DefaultOrgID)
		return h.scalar(`INSERT INTO user_identity_links (user_id, provider_id, external_id, org_id)
			VALUES ($1::uuid, $2::uuid, $3, $4::uuid) RETURNING id::text`, user, idp, sub, middleware.DefaultOrgID)
	}
	links := func(user string) string {
		return h.scalar(`SELECT (SELECT COUNT(*) FROM social_account_links WHERE user_id = $1::uuid)::text || '/' ||
			(SELECT COUNT(*) FROM user_identity_links WHERE user_id = $1::uuid)::text`, user)
	}

	user := h.seedUser("unlink-pw")
	bearer := h.bearer(user)
	id := link(user, "sub-pw-"+h.suffix)
	path := "/api/v1/identity/users/me/identity-links/" + id
	for _, tc := range []struct {
		name string
		body map[string]string
		want string
	}{
		{"the token alone", nil, reauthRequired},
		{"a wrong password", map[string]string{"current_password": "nope"}, reauthFailed},
	} {
		status, out := h.do(http.MethodDelete, path, bearer, tc.body)
		if status != http.StatusForbidden || out["error"] != tc.want {
			t.Fatalf("%s: status %d (%v), want 403 %s", tc.name, status, out, tc.want)
		}
		if got := links(user); got != "1/1" {
			t.Fatalf("%s: refused, but the links are %s", tc.name, got)
		}
	}
	status, out := h.do(http.MethodDelete, path, bearer, map[string]string{"current_password": harnessPassword})
	if status != http.StatusOK {
		t.Fatalf("with the password: status %d (%v), want 200", status, out)
	}
	if got := links(user); got != "0/0" {
		t.Fatalf("after unlinking, social/identity links = %s, want 0/0: the social sign-in would still find the account", got)
	}

	// An account with no password and no factor has nothing to give.
	bare := h.seedUser("unlink-bare")
	h.exec(`UPDATE users SET password_hash = NULL WHERE id = $1::uuid`, bare)
	bareID := link(bare, "sub-bare-"+h.suffix)
	if status, out := h.do(http.MethodDelete, "/api/v1/identity/users/me/identity-links/"+bareID, h.bearer(bare), nil); status != http.StatusOK {
		t.Fatalf("an account with neither: status %d (%v), want 200", status, out)
	}
	if got := links(bare); got != "0/0" {
		t.Fatalf("links = %s, want 0/0", got)
	}
}
