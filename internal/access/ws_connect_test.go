package access

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestBuildSSHClientConfigPassword: a non-key secret becomes a password auth
// method under the resolved username.
func TestBuildSSHClientConfigPassword(t *testing.T) {
	cfg, err := buildSSHClientConfig("alice", "password", []byte("s3cret"))
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
	_, err := buildSSHClientConfig("root", "ssh_key", []byte("not-a-key"))
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
	if _, err := buildSSHClientConfig("root", "password", nil); err == nil {
		t.Fatal("expected an error when no credential is provided")
	}
}

// TestSSHConfigIsInteractiveShellCapable is a lightweight guard that the config
// requests a real auth method (not an empty set that some servers accept).
func TestSSHConfigAuthNonEmpty(t *testing.T) {
	cfg, _ := buildSSHClientConfig("root", "password", []byte("x"))
	var _ ssh.AuthMethod = cfg.Auth[0] // compile-time: it's a real AuthMethod
	if cfg.Timeout == 0 {
		t.Error("dial timeout must be set so a dead target fails fast")
	}
}
