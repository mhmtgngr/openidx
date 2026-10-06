package sso

import (
	"net/url"
	"testing"
)

// TestAFreshSignInAsksTheServerToAuthenticateAgain: with Fresh, the authorize
// URL carries prompt=login and max_age=0; without it, neither, so an ordinary
// sign-in may reuse the browser's session.
func TestAFreshSignInAsksTheServerToAuthenticateAgain(t *testing.T) {
	fresh, err := url.Parse(desktopAuthorizeURL("https://openidx.test/", "st", "ch", LoginOptions{Fresh: true}))
	if err != nil {
		t.Fatal(err)
	}
	q := fresh.Query()
	if q.Get("prompt") != "login" || q.Get("max_age") != "0" {
		t.Fatalf("fresh sign-in must send prompt=login&max_age=0, got %q", fresh.RawQuery)
	}
	if fresh.Path != "/oauth/authorize" || q.Get("client_id") != DesktopClientID ||
		q.Get("code_challenge") != "ch" || q.Get("code_challenge_method") != "S256" || q.Get("state") != "st" {
		t.Fatalf("the rest of the request is unchanged: %s", fresh)
	}

	plain, _ := url.Parse(desktopAuthorizeURL("https://openidx.test", "st", "ch", LoginOptions{}))
	if plain.Query().Has("prompt") || plain.Query().Has("max_age") {
		t.Fatalf("an ordinary sign-in may reuse the browser's session: %q", plain.RawQuery)
	}
}
