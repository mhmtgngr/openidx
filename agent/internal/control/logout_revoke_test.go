package control

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/authstore"
	"github.com/openidx/openidx/agent/internal/sso"
)

// Signing out used to be authstore.Clear alone: the file went away and the
// refresh token in it stayed valid on the server for its full 30 days. The app
// showed "signed out" and the credential someone had already copied kept
// working — the exact case a user signs out on a shared or lost device for.
//
// The other half is the device binding: a session that never names its device
// cannot be revoked with that device, and the failure is silent on both sides.

// revokeCapture is an /oauth/revoke endpoint that records what it received.
type revokeCapture struct {
	srv    *httptest.Server
	hits   int
	form   url.Values
	status int
}

func newRevokeCapture(t *testing.T) *revokeCapture {
	t.Helper()
	c := &revokeCapture{status: http.StatusOK}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/revoke" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		c.hits++
		c.form = r.Form
		w.WriteHeader(c.status)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func TestLogoutRevokesOnTheServerThenClears(t *testing.T) {
	cap := newRevokeCapture(t)
	e := newTestEngine(t, &fakeBackend{})
	e.serverURL = cap.srv.URL

	if err := authstore.Save(e.configDir, &sso.Tokens{
		AccessToken:  "at",
		RefreshToken: "rt-to-kill",
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	if err := e.Logout(); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if cap.hits != 1 {
		t.Fatalf("/oauth/revoke called %d times, want 1 — the refresh token would stay valid for its full lifetime", cap.hits)
	}
	if got := cap.form.Get("token"); got != "rt-to-kill" {
		t.Errorf("revoked token = %q, want rt-to-kill", got)
	}
	tok, err := authstore.Load(e.configDir)
	if err != nil || tok != nil {
		t.Errorf("local session not cleared: tok=%+v err=%v", tok, err)
	}
}

// TestLogoutClearsEvenWhenRevocationFails: a user who signs out must not stay
// signed in locally because the network was down or the server refused.
func TestLogoutClearsEvenWhenRevocationFails(t *testing.T) {
	cap := newRevokeCapture(t)
	cap.status = http.StatusInternalServerError
	e := newTestEngine(t, &fakeBackend{})
	e.serverURL = cap.srv.URL

	if err := authstore.Save(e.configDir, &sso.Tokens{AccessToken: "at", RefreshToken: "rt"}); err != nil {
		t.Fatal(err)
	}
	if err := e.Logout(); err != nil {
		t.Fatalf("Logout must not fail on a refused revocation: %v", err)
	}
	if tok, _ := authstore.Load(e.configDir); tok != nil {
		t.Error("local session survived a failed revocation")
	}
}

// TestLogoutWithNoSessionDoesNotCallTheServer keeps sign-out on a signed-out
// engine silent rather than posting an empty token.
func TestLogoutWithNoSessionDoesNotCallTheServer(t *testing.T) {
	cap := newRevokeCapture(t)
	e := newTestEngine(t, &fakeBackend{})
	e.serverURL = cap.srv.URL

	if err := e.Logout(); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if cap.hits != 0 {
		t.Errorf("called /oauth/revoke %d times with no session", cap.hits)
	}
}

// writeAgentConfig persists the minimum agent config the engine reads to learn
// which device it is.
func writeAgentConfig(t *testing.T, dir, agentID string) {
	t.Helper()
	cfg := &agent.AgentConfig{ServerURL: "https://openidx.test", AgentID: agentID, DeviceID: "device-1"}
	if err := cfg.Save(dir); err != nil {
		t.Fatalf("save agent config: %v", err)
	}
}

func TestLoginNamesTheEnrolledDevice(t *testing.T) {
	be := &fakeBackend{loginTokens: &sso.Tokens{AccessToken: "at"}}
	e := newTestEngine(t, be)
	writeAgentConfig(t, e.configDir, "agent-enrolled-1")

	if _, err := e.Login(); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !be.loginCalled {
		t.Fatal("backend login not called")
	}
	if be.loginAgentID != "agent-enrolled-1" {
		t.Errorf("login carried agent id %q, want agent-enrolled-1 — an unnamed session cannot be revoked with its device",
			be.loginAgentID)
	}
}

func TestLoginOnAnUnenrolledMachineNamesNoDevice(t *testing.T) {
	be := &fakeBackend{loginTokens: &sso.Tokens{AccessToken: "at"}}
	e := newTestEngine(t, be)

	if _, err := e.Login(); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if be.loginAgentID != "" {
		t.Errorf("login carried agent id %q on a machine with no agent config", be.loginAgentID)
	}
}

// TestLoginStartPersistsTheDeviceBinding pins the mobile half: LoginStart must
// write the device into the pending-login file, or the Android cold start (the
// reason that file exists) completes the exchange without naming the device.
func TestLoginStartPersistsTheDeviceBinding(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})
	writeAgentConfig(t, e.configDir, "agent-mobile-9")

	if _, err := e.LoginStart(); err != nil {
		t.Fatalf("LoginStart: %v", err)
	}
	data, err := os.ReadFile(e.pendingLoginPath())
	if err != nil {
		t.Fatalf("read pending login: %v", err)
	}
	if !strings.Contains(string(data), "agent-mobile-9") {
		t.Errorf("pending login does not carry the device: %s", data)
	}
}
