package oauth

import (
	"net/url"
	"testing"
)

// TestLoginRedirectURL: in spa mode every client — public, confidential, native
// — goes to the IdP's own login page. That is what lets the server-rendered page
// be deleted: a native client whose redirect_uri is openidx://oauth-callback
// cannot host a login page, which is why the hosted page existed.
func TestLoginRedirectURL(t *testing.T) {
	const issuer = "https://openidx.tdv.org"

	got := loginRedirectURL(issuer, "openidx://oauth-callback", "sess-1", "spa")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("not a URL: %v", err)
	}
	if u.Host != "openidx.tdv.org" || u.Path != "/login" {
		t.Errorf("spa mode must target the issuer's login page, got %q", got)
	}
	if u.Query().Get("login_session") != "sess-1" {
		t.Errorf("login_session missing from %q", got)
	}

	// server mode keeps today's behaviour: back to the client's OWN redirect
	// URI, not the issuer's /login. Deliberately use a custom scheme here
	// (the native-client case) rather than an https://openidx.tdv.org/login
	// URL — the latter is indistinguishable from the spa target for this
	// issuer, so it can't actually catch a regression that wrongly routes
	// server mode to the issuer's login page.
	got = loginRedirectURL(issuer, "openidx://oauth-callback", "sess-1", "server")
	u, err = url.Parse(got)
	if err != nil {
		t.Fatalf("not a URL: %v", err)
	}
	if u.Scheme != "openidx" || u.Host != "oauth-callback" {
		t.Errorf("server mode must preserve the client's own redirect_uri (custom scheme), got %q", got)
	}
	if u.Query().Get("login_session") != "sess-1" {
		t.Errorf("login_session missing from %q", got)
	}

	// server mode must not clobber query parameters the client already put on
	// its redirect_uri.
	got = loginRedirectURL(issuer, "https://client.example.com/cb?foo=1", "sess-1", "server")
	u, err = url.Parse(got)
	if err != nil {
		t.Fatalf("not a URL: %v", err)
	}
	if u.Query().Get("foo") != "1" {
		t.Errorf("server mode must preserve existing client query params, got %q", got)
	}
	if u.Query().Get("login_session") != "sess-1" {
		t.Errorf("login_session missing from %q", got)
	}
}
