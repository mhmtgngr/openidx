package oauth

import (
	"net/url"
	"testing"
)

// TestLoginRedirectURL pins the one destination.
//
// This test used to have a second half asserting that "server" mode sent the
// browser back to the CLIENT's own redirect_uri with ?login_session= —
// including, deliberately, a custom-scheme one. That was the shape the
// server-rendered login existed to work around, and it is gone: a native
// client cannot host a page at openidx://oauth-callback, so sending it there
// was only ever survivable because the server rendered the form itself.
func TestLoginRedirectURL(t *testing.T) {
	got := loginRedirectURL("https://openidx.tdv.org/login", "sess-1")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("not a URL: %v", err)
	}
	if u.Host != "openidx.tdv.org" || u.Path != "/login" {
		t.Errorf("want the login page, got %q", got)
	}
	if u.Query().Get("login_session") != "sess-1" {
		t.Errorf("login_session missing from %q", got)
	}

	// A configured login URL that already carries query parameters keeps them.
	got = loginRedirectURL("https://console.example.com/login?theme=dark", "sess-1")
	u, err = url.Parse(got)
	if err != nil {
		t.Fatalf("not a URL: %v", err)
	}
	if u.Query().Get("theme") != "dark" || u.Query().Get("login_session") != "sess-1" {
		t.Errorf("existing query params must survive, got %q", got)
	}

	// A value that is not an absolute URL yields "", which the caller turns
	// into a 500 rather than a redirect to nowhere. A relative "/oauth/login"
	// is exactly what the v2 handler used to emit.
	for _, bad := range []string{"", "/oauth/login", "://nope"} {
		if got := loginRedirectURL(bad, "sess-1"); got != "" {
			t.Errorf("loginRedirectURL(%q) = %q, want \"\" — a login URL with no host is not usable", bad, got)
		}
	}
}

// TestServiceLoginURLDefaultsToIssuer pins the fallback and the override. The
// override is not cosmetic: the reference compose stack serves the issuer at
// oauth.localtest.me:8446 and the console at localhost:3000, so an
// issuer-derived login URL 404s every sign-in there.
func TestServiceLoginURLDefaultsToIssuer(t *testing.T) {
	s := &Service{issuer: "https://openidx.tdv.org/"}
	if got := s.loginURL(); got != "https://openidx.tdv.org/login" {
		t.Errorf("loginURL() = %q, want the issuer's /login", got)
	}
}
