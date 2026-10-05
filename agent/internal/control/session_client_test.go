package control

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/openidx/openidx/agent/internal/authstore"
	"github.com/openidx/openidx/agent/internal/sso"
)

// oauthCapture serves /oauth/token and /oauth/revoke and records the client_id
// each presented.
type oauthCapture struct {
	srv     *httptest.Server
	refresh url.Values
	revoke  url.Values
}

func newOAuthCapture(t *testing.T) *oauthCapture {
	t.Helper()
	c := &oauthCapture{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/oauth/token":
			c.refresh = r.Form
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"at-new","refresh_token":"rt-new","expires_in":3600}`))
		case "/oauth/revoke":
			c.revoke = r.Form
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func saveSession(t *testing.T, dir string, tok *sso.Tokens) {
	t.Helper()
	if err := authstore.Save(dir, tok); err != nil {
		t.Fatal(err)
	}
}

// TestADesktopSessionRefreshesAndRevokesAsTheDesktopClient: the engine behind
// the desktop GUI logs in as openidx-desktop, so its refresh and its sign-out
// must say so. They used to say openidx-mobile: the refresh was refused and
// the revocation revoked nothing while answering 200.
func TestADesktopSessionRefreshesAndRevokesAsTheDesktopClient(t *testing.T) {
	cap := newOAuthCapture(t)
	e := newTestEngine(t, &fakeBackend{})
	e.serverURL = cap.srv.URL
	saveSession(t, e.configDir, &sso.Tokens{
		AccessToken: "at-old", RefreshToken: "rt-old",
		ExpiresAt: time.Now().Add(-time.Minute).Unix(), // expired: refresh is due
		ClientID:  sso.DesktopClientID,
	})

	at, err := e.AccessToken()
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if at != "at-new" {
		t.Fatalf("AccessToken = %q, want the refreshed at-new", at)
	}
	if got := cap.refresh.Get("client_id"); got != sso.DesktopClientID {
		t.Fatalf("refresh presented client_id %q, want %s", got, sso.DesktopClientID)
	}
	stored, _ := authstore.Load(e.configDir)
	if stored == nil || stored.ClientID != sso.DesktopClientID {
		t.Fatalf("the refreshed session must keep its client: %+v", stored)
	}

	if err := e.Logout(); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if got := cap.revoke.Get("client_id"); got != sso.DesktopClientID {
		t.Fatalf("revocation presented client_id %q, want %s", got, sso.DesktopClientID)
	}
	if got := cap.revoke.Get("token"); got != "rt-new" {
		t.Fatalf("revoked token %q, want the current rt-new", got)
	}
}

// TestALegacySessionWithoutAClientIsStillMobile: a session stored by a build
// that did not record the client is a mobile one (the only kind the engine
// issued then), so nothing changes for phones already signed in.
func TestALegacySessionWithoutAClientIsStillMobile(t *testing.T) {
	cap := newOAuthCapture(t)
	e := newTestEngine(t, &fakeBackend{})
	e.serverURL = cap.srv.URL
	saveSession(t, e.configDir, &sso.Tokens{
		AccessToken: "at-old", RefreshToken: "rt-old",
		ExpiresAt: time.Now().Add(-time.Minute).Unix(),
	})

	if _, err := e.AccessToken(); err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if got := cap.refresh.Get("client_id"); got != sso.MobileClientID {
		t.Fatalf("refresh presented client_id %q, want %s", got, sso.MobileClientID)
	}
	if err := e.Logout(); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if got := cap.revoke.Get("client_id"); got != sso.MobileClientID {
		t.Fatalf("revocation presented client_id %q, want %s", got, sso.MobileClientID)
	}
}
