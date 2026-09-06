package access

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
)

// TestBuildSSHClientConfigPassword: a non-key secret becomes a password auth
// method under the resolved username.
func TestBuildSSHClientConfigPassword(t *testing.T) {
	cfg, err := buildSSHClientConfig("alice", "password", []byte("s3cret"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.User != "alice" {
		t.Errorf("user = %q, want alice", cfg.User)
	}
	if len(cfg.Auth) != 1 {
		t.Fatalf("expected exactly one auth method, got %d", len(cfg.Auth))
	}
	if cfg.HostKeyCallback == nil {
		t.Error("HostKeyCallback must be set")
	}
}

// TestBuildSSHClientConfigKey: an 'ssh_key' secret is parsed as a private key.
func TestBuildSSHClientConfigKey(t *testing.T) {
	// A throwaway ed25519 key in OpenSSH PEM form would be ideal, but generating
	// one here keeps the test hermetic: use a known-good test key.
	// Instead, assert that a bad key is rejected (the parse path is exercised).
	_, err := buildSSHClientConfig("root", "ssh_key", []byte("not-a-key"), "")
	if err == nil {
		t.Fatal("expected an error parsing an invalid private key")
	}
	if !strings.Contains(err.Error(), "private key") {
		t.Errorf("error = %q, want it to mention private key", err.Error())
	}
}

// TestBuildSSHClientConfigNoCredential: no credential is a hard error (the relay
// must never attempt an unauthenticated SSH connection).
func TestBuildSSHClientConfigNoCredential(t *testing.T) {
	if _, err := buildSSHClientConfig("root", "password", nil, ""); err == nil {
		t.Fatal("expected an error when no credential is provided")
	}
}

// TestSSHConfigIsInteractiveShellCapable is a lightweight guard that the config
// requests a real auth method (not an empty set that some servers accept).
func TestSSHConfigAuthNonEmpty(t *testing.T) {
	cfg, _ := buildSSHClientConfig("root", "password", []byte("x"), "")
	var _ ssh.AuthMethod = cfg.Auth[0] // compile-time: it's a real AuthMethod
	if cfg.Timeout == 0 {
		t.Error("dial timeout must be set so a dead target fails fast")
	}
}

func TestPromoteWebSocketBearer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	run := func(upgrade, existingAuth, proto string) (string, string) {
		r := httptest.NewRequest("GET", "/api/v1/access/pam/entries/x/ws", nil)
		if upgrade != "" {
			r.Header.Set("Upgrade", upgrade)
		}
		if existingAuth != "" {
			r.Header.Set("Authorization", existingAuth)
		}
		if proto != "" {
			r.Header.Set("Sec-WebSocket-Protocol", proto)
		}
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = r
		promoteWebSocketBearer(c)
		return c.Request.Header.Get("Authorization"), c.GetString("ws_bearer_subprotocol")
	}

	// WS upgrade + bearer.<jwt> subprotocol -> promoted to Authorization.
	if auth, sub := run("websocket", "", "bearer.abc123"); auth != "Bearer abc123" || sub != "bearer.abc123" {
		t.Errorf("ws bearer not promoted: auth=%q sub=%q", auth, sub)
	}
	// access_token_<jwt> form also promoted.
	if auth, _ := run("websocket", "", "access_token_zzz"); auth != "Bearer zzz" {
		t.Errorf("access_token form not promoted: auth=%q", auth)
	}
	// NON-websocket request must NOT be touched (no header injection off a plain GET).
	if auth, _ := run("", "", "bearer.abc123"); auth != "" {
		t.Errorf("non-ws request must not get an Authorization header, got %q", auth)
	}
	// Existing Authorization header is never overwritten.
	if auth, _ := run("websocket", "Bearer real", "bearer.fake"); auth != "Bearer real" {
		t.Errorf("existing auth must be preserved, got %q", auth)
	}
	// Unknown subprotocol is ignored.
	if auth, _ := run("websocket", "", "chat"); auth != "" {
		t.Errorf("unknown subprotocol must not promote, got %q", auth)
	}
}

// TestSSHHostKeyPinIsEnforcedWhenPresent is the fix for the one genuine finding
// in docs/evidence/codeql-triage.md — go/insecure-hostkeycallback at 8.2.
//
// The relay used ssh.InsecureIgnoreHostKey() unconditionally, under a comment
// saying per-entry pinning was a follow-up. So a PAM entry could carry a host
// key and nothing would look at it: the shape this whole programme exists to
// remove, and worse than no pin, because someone would believe in it.
//
// The assertions are behavioural: the callback is invoked with a key and has to
// accept the pinned one and reject any other.
func TestSSHHostKeyPinIsEnforcedWhenPresent(t *testing.T) {
	pinned, pinnedLine := testHostKey(t)
	other, _ := testHostKey(t)
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 7), Port: 22}

	cfg, err := buildSSHClientConfig("root", "password", []byte("x"), pinnedLine)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := cfg.HostKeyCallback("host:22", addr, pinned); err != nil {
		t.Errorf("the pinned host key was rejected: %v", err)
	}
	if err := cfg.HostKeyCallback("host:22", addr, other); err == nil {
		t.Error("a DIFFERENT host key was accepted while the entry pinned one — " +
			"the pin is displayed and not enforced, which is worse than no pin")
	}
}

// TestSSHHostKeyPinUnparsableIsRefused: a stored pin that cannot be parsed must
// fail the connection, never fall back to accepting anything. Falling back is
// how a pin silently stops being a pin.
func TestSSHHostKeyPinUnparsableIsRefused(t *testing.T) {
	_, err := buildSSHClientConfig("root", "password", []byte("x"), "ssh-ed25519 not-base64")
	if err == nil {
		t.Fatal("an unparsable pinned host key did not fail the connection")
	}
	if !strings.Contains(err.Error(), "host key") {
		t.Errorf("error = %q, want it to name the host key", err.Error())
	}
}

// TestSSHHostKeyAbsentKeepsConnecting: an entry with no pin behaves as before.
// Refusing here would break every existing entry, which is a product decision
// the operator makes with PAM_SSH_REQUIRE_HOST_KEY, not one this function takes.
func TestSSHHostKeyAbsentKeepsConnecting(t *testing.T) {
	cfg, err := buildSSHClientConfig("root", "password", []byte("x"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	any, _ := testHostKey(t)
	if err := cfg.HostKeyCallback("host:22", &net.TCPAddr{}, any); err != nil {
		t.Errorf("an unpinned entry refused a host key: %v", err)
	}
}

// TestPamEntrySSHHostKeyReadsSettings covers the plumbing: the pin lives in the
// entry's free-form settings bag, so it needs no migration.
func TestPamEntrySSHHostKeyReadsSettings(t *testing.T) {
	_, line := testHostKey(t)
	cases := []struct {
		name     string
		settings map[string]interface{}
		want     string
	}{
		{"nil settings", nil, ""},
		{"absent", map[string]interface{}{"other": 1}, ""},
		{"wrong type", map[string]interface{}{"ssh_host_key": 42}, ""},
		{"whitespace only", map[string]interface{}{"ssh_host_key": "   "}, ""},
		{"present", map[string]interface{}{"ssh_host_key": "  " + line + "  "}, line},
	}
	for _, tc := range cases {
		if got := pamEntrySSHHostKey(tc.settings); got != tc.want {
			t.Errorf("%s: pamEntrySSHHostKey() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// testHostKey returns a fresh ed25519 host key and its authorized_keys line.
func testHostKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}
	return sshPub, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}
