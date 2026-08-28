package control

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/openidx/openidx/agent/internal/agent"
)

var errTest = errors.New("boom")

// writePendingPushConfig seeds the engine's config dir with an enrolled device
// that has a pending push-enroll ticket (the state Enroll leaves behind on the
// session path).
func writePendingPushConfig(t *testing.T, e *Engine, token, path string) {
	t.Helper()
	cfg := &agent.AgentConfig{
		ServerURL:       "https://openidx.test",
		AgentID:         "agent-1",
		DeviceID:        "device-1",
		PushEnrollToken: token,
		PushEnrollPath:  path,
	}
	if err := cfg.Save(e.configDir); err != nil {
		t.Fatalf("seed config: %v", err)
	}
}

func decodePushResult(t *testing.T, js string) pushRegisterResult {
	t.Helper()
	var r pushRegisterResult
	if err := json.Unmarshal([]byte(js), &r); err != nil {
		t.Fatalf("decode result %q: %v", js, err)
	}
	return r
}

func TestRegisterPushDevice_RedeemsAndClearsTicket(t *testing.T) {
	be := &fakeBackend{}
	e := newTestEngine(t, be)
	writePendingPushConfig(t, e, "ticket-abc", "/api/v1/identity/mfa/push/enroll/complete")

	out, err := e.RegisterPushDevice("fcm-token-xyz", "android")
	if err != nil {
		t.Fatalf("RegisterPushDevice: %v", err)
	}
	if r := decodePushResult(t, out); !r.Registered {
		t.Fatalf("expected registered=true, got %+v", r)
	}

	// Backend was called with the ticket + device token from config/args.
	if be.pushTicket != "ticket-abc" || be.pushDeviceToken != "fcm-token-xyz" || be.pushPlatform != "android" {
		t.Fatalf("backend got wrong args: %+v", be)
	}
	if be.pushServerURL != "https://openidx.test" {
		t.Fatalf("backend got wrong server: %q", be.pushServerURL)
	}

	// Ticket must be cleared (single-use) so a re-call is a clean no-op.
	cfg, err := agent.LoadConfig(e.configDir)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if cfg.PushEnrollToken != "" || cfg.PushEnrollPath != "" {
		t.Fatalf("ticket not cleared: token=%q path=%q", cfg.PushEnrollToken, cfg.PushEnrollPath)
	}

	out2, err := e.RegisterPushDevice("fcm-token-xyz", "android")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if r := decodePushResult(t, out2); r.Registered {
		t.Fatal("second call should report registered=false (nothing pending)")
	}
}

func TestRegisterPushDevice_NoPendingTicket(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})
	// Config with no push ticket.
	cfg := &agent.AgentConfig{ServerURL: "https://openidx.test", AgentID: "a", DeviceID: "d"}
	if err := cfg.Save(e.configDir); err != nil {
		t.Fatal(err)
	}
	out, err := e.RegisterPushDevice("fcm", "ios")
	if err != nil {
		t.Fatalf("RegisterPushDevice: %v", err)
	}
	if r := decodePushResult(t, out); r.Registered {
		t.Fatal("expected registered=false when no ticket pending")
	}
}

func TestRegisterPushDevice_EmptyTokenRejected(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})
	if _, err := e.RegisterPushDevice("  ", "android"); err == nil {
		t.Fatal("expected error for empty device token")
	}
}

func TestRegisterPushDevice_BackendFailureKeepsTicket(t *testing.T) {
	be := &fakeBackend{pushErr: errTest}
	e := newTestEngine(t, be)
	writePendingPushConfig(t, e, "ticket-keep", "/push/complete")

	if _, err := e.RegisterPushDevice("fcm", "android"); err == nil {
		t.Fatal("expected error when backend push fails")
	}
	// On failure the ticket is retained so the client can retry.
	cfg, _ := agent.LoadConfig(e.configDir)
	if cfg.PushEnrollToken != "ticket-keep" {
		t.Fatalf("ticket should be retained on failure, got %q", cfg.PushEnrollToken)
	}
}
