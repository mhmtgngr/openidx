package oauth

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/revocation"
)

// A password reset writes the per-user revocation cutoff, which refuses every
// access token the user already holds. The cutoff was compared in whole
// seconds, so a token minted in the same second AFTER it was refused too: the
// integration suite sets each test user's password and signs in straight
// away, and its tokens came back "token has been revoked" at /oauth/userinfo.
//
// Tokens from the authorization-code grant carry when their code was issued
// (revocation.GrantedAtClaim). Tokens from the refresh grant now carry when
// the grant began, so a device that refreshes just after the reset gets a
// token userinfo accepts, and one that refreshed just before it, in the same
// second, keeps nothing the reset should have cut.
func TestARefreshInTheSameSecondAsAPasswordResetIsDatedToTheMicrosecond(t *testing.T) {
	f := newSessionEndFixture(t)
	api := f.identityAPI(t)

	admin := f.seedUser(t, "same-second-admin")
	f.grantAdmin(t, admin)
	adminSession, _ := f.newSession(t, admin)
	adminAccess := f.bearer(t, admin, adminSession)

	accessFrom := func(t *testing.T, device, what string) string {
		t.Helper()
		code, _, body := f.refresh(t, device)
		tok, _ := body["access_token"].(string)
		if code != http.StatusOK || tok == "" {
			t.Fatalf("%s: refresh: %d %v", what, code, body)
		}
		return tok
	}

	// One attempt. It returns false when the reset and the refresh after it
	// did not land in the same second, so the case under test was not
	// exercised.
	attempt := func(t *testing.T, n int) bool {
		user := f.seedUser(t, fmt.Sprintf("same-second-%d", n))
		f.setPassword(t, user, pwBefore)
		_, before := f.newSession(t, user)

		// Start at the top of a second, so what follows lands in it.
		time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 5*time.Millisecond)))
		beforeAccess := accessFrom(t, before, "a device refreshing just before the reset")

		code, body := f.send(t, api, http.MethodPost, "/api/v1/identity/users/"+user+"/set-password", adminAccess,
			map[string]string{"password": pwAfter})
		if code != http.StatusOK {
			t.Fatalf("set password: %d %v", code, body)
		}
		marker, err := f.mini.Get(revocation.UserTokensRevokedAtKey(user))
		if err != nil {
			t.Fatalf("the reset wrote no revocation marker: %v", err)
		}

		// Signed in again straight afterwards, on another device.
		_, after := f.newSession(t, user)
		afterAccess := accessFrom(t, after, "a device refreshing just after the reset")

		claims, err := f.svc.parseVerifiedClaims(afterAccess, false)
		if err != nil {
			t.Fatal(err)
		}
		cutoff, err := revocation.ParseMarker(marker)
		if err != nil {
			t.Fatal(err)
		}
		if !cutoff.Revokes(revocation.IssuedAt{Seconds: int64(claims["iat"].(float64))}) {
			return false // crossed into the next second; nothing was tested
		}
		if _, ok := claims[revocation.GrantedAtClaim]; !ok {
			t.Fatalf("an access token from the refresh grant carries no %s", revocation.GrantedAtClaim)
		}

		if !f.userinfoAccepts(t, afterAccess) {
			t.Error("a token refreshed after the reset, in the same second, was refused as revoked")
		}
		if f.userinfoAccepts(t, beforeAccess) {
			t.Error("a token refreshed before the reset, in the same second, survived it")
		}
		return true
	}

	for i := 0; i < 3; i++ {
		if attempt(t, i) || t.Failed() {
			return
		}
		t.Log("the refresh after the reset crossed a second boundary; trying again")
	}
	t.Fatal("could not fit a reset and a refresh into one second in three attempts")
}

// Not every per-user cutoff ends the refresh chains. Losing a role writes it
// to cut the access tokens that still carry the role and leaves the devices
// signed in, so their next refresh mints a token with the roles the user has
// now (revokeAfterRoleLoss). A refreshed token therefore dates from the
// refresh, not from when its refresh token was issued: dated from that, every
// device of a user who lost a role would be refused at userinfo until the
// marker expired a week later.
func TestARefreshAfterARoleLossIsNotRevokedByIt(t *testing.T) {
	f := newSessionEndFixture(t)
	user := f.seedUser(t, "role-loss")
	session, device := f.newSession(t, user)
	stale := f.bearer(t, user, session)

	// The cutoff revokeAfterRoleLoss writes: access tokens only.
	if err := revocation.RevokeUserTokens(context.Background(), f.svc.redis.RevocationDB(), user); err != nil {
		t.Fatalf("write the cutoff: %v", err)
	}

	code, _, body := f.refresh(t, device)
	tok, _ := body["access_token"].(string)
	if code != http.StatusOK || tok == "" {
		t.Fatalf("a role loss ends no refresh chain, but the refresh failed: %d %v", code, body)
	}
	if !f.userinfoAccepts(t, tok) {
		t.Error("the token a refresh minted after the role loss was refused as revoked")
	}
	if f.userinfoAccepts(t, stale) {
		t.Error("an access token issued before the role loss survived it")
	}
}
