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

	// server mode keeps today's behaviour: back to the client's own page.
	got = loginRedirectURL(issuer, "https://openidx.tdv.org/login", "sess-1", "server")
	if u, _ = url.Parse(got); u.Query().Get("login_session") != "sess-1" || u.Path != "/login" {
		t.Errorf("server mode must preserve the client redirect, got %q", got)
	}
}
