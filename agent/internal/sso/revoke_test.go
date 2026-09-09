package sso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
)

// Two things the client half of "revoking a device revokes its tokens" rests
// on, neither of which the type system can hold up:
//
//	1. the token exchange NAMES the device, or the server has nothing to bind;
//	2. signing out REACHES the server, or the refresh token it deleted locally
//	   stays valid for its full 30 days.
//
// Both are single form fields on requests nobody watches, which is exactly the
// shape of a control that quietly stops working.

// formCapture is a token/revocation endpoint that records what it was sent.
type formCapture struct {
	srv    *httptest.Server
	path   string
	form   url.Values
	status int
}

func newFormCapture(t *testing.T) *formCapture {
	t.Helper()
	c := &formCapture{status: http.StatusOK}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		c.path = r.URL.Path
		c.form = r.Form
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(c.status)
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt","expires_in":3600,"token_type":"Bearer"}`))
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func TestMobileExchangeNamesTheDevice(t *testing.T) {
	cap := newFormCapture(t)

	m, _, err := StartMobileLogin(cap.srv.URL)
	if err != nil {
		t.Fatalf("StartMobileLogin: %v", err)
	}
	m.BindDevice("agent-abc123")

	if _, err := m.Exchange(context.Background(), "code-1", m.State()); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got := cap.form.Get("agent_id"); got != "agent-abc123" {
		t.Errorf("agent_id = %q, want agent-abc123 — the server cannot bind what it is not told", got)
	}
}

func TestMobileExchangeOmitsAnUnknownDevice(t *testing.T) {
	cap := newFormCapture(t)

	m, _, err := StartMobileLogin(cap.srv.URL)
	if err != nil {
		t.Fatalf("StartMobileLogin: %v", err)
	}
	// Not enrolled yet: the app can sign in, it simply has no device to name.
	if _, err := m.Exchange(context.Background(), "code-1", m.State()); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if _, present := cap.form["agent_id"]; present {
		t.Errorf("agent_id sent as %q by an unenrolled client; an empty claim is worse than none",
			cap.form.Get("agent_id"))
	}
}

// TestPersistedLoginKeepsTheDeviceBinding is the Android cold-start case: the
// OS kills the app during the browser step, so the exchange runs in a process
// that only has what LoginStart wrote to disk. A binding that lived only in
// memory would be lost exactly on the platform this flow exists for.
func TestPersistedLoginKeepsTheDeviceBinding(t *testing.T) {
	cap := newFormCapture(t)

	m, _, err := StartMobileLogin(cap.srv.URL)
	if err != nil {
		t.Fatalf("StartMobileLogin: %v", err)
	}
	m.BindDevice("agent-coldstart")

	path := filepath.Join(t.TempDir(), "login_pending.json")
	if err := m.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := LoadMobileLogin(path)
	if err != nil {
		t.Fatalf("LoadMobileLogin: %v", err)
	}

	if _, err := loaded.Exchange(context.Background(), "code-1", loaded.State()); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got := cap.form.Get("agent_id"); got != "agent-coldstart" {
		t.Errorf("agent_id = %q after a cold start, want agent-coldstart", got)
	}
}

func TestDesktopExchangeNamesTheDevice(t *testing.T) {
	cap := newFormCapture(t)

	p, err := StartLogin(cap.srv.URL)
	if err != nil {
		t.Skipf("loopback %s unavailable: %v", LoopbackAddr, err)
	}
	defer p.srv.Close()
	p.BindDevice("agent-laptop")

	// Drive Wait's exchange directly through the captured callback channel.
	p.resCh <- callbackResult{code: "code-9"}
	if _, err := p.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if got := cap.form.Get("agent_id"); got != "agent-laptop" {
		t.Errorf("agent_id = %q, want agent-laptop", got)
	}
	if got := cap.form.Get("client_id"); got != DesktopClientID {
		t.Errorf("client_id = %q, want %s", got, DesktopClientID)
	}
}

func TestRevokePostsTheRefreshToken(t *testing.T) {
	cap := newFormCapture(t)

	if err := Revoke(context.Background(), cap.srv.URL, MobileClientID, "rt-123"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if cap.path != "/oauth/revoke" {
		t.Errorf("posted to %q, want /oauth/revoke", cap.path)
	}
	if got := cap.form.Get("token"); got != "rt-123" {
		t.Errorf("token = %q, want rt-123", got)
	}
	// The hint is what makes the server look in the refresh-token table rather
	// than treating the value as an access token (RFC 7009 §2.1).
	if got := cap.form.Get("token_type_hint"); got != "refresh_token" {
		t.Errorf("token_type_hint = %q, want refresh_token", got)
	}
	// /oauth/revoke authenticates its caller; a public client sends the id and
	// no secret.
	if got := cap.form.Get("client_id"); got != MobileClientID {
		t.Errorf("client_id = %q, want %s", got, MobileClientID)
	}
	if cap.form.Get("client_secret") != "" {
		t.Error("a public client must not send a client_secret")
	}
}

func TestRevokeReportsRefusal(t *testing.T) {
	cap := newFormCapture(t)
	cap.status = http.StatusUnauthorized

	if err := Revoke(context.Background(), cap.srv.URL, MobileClientID, "rt-123"); err == nil {
		t.Error("a refused revocation reported success; the caller would report a sign-out that did not happen")
	}
}

func TestRevokeWithNoTokenIsANoOp(t *testing.T) {
	cap := newFormCapture(t)

	if err := Revoke(context.Background(), cap.srv.URL, MobileClientID, ""); err != nil {
		t.Errorf("no refresh token to revoke should be a no-op, got %v", err)
	}
	if cap.path != "" {
		t.Errorf("posted to %q with nothing to revoke", cap.path)
	}
}
