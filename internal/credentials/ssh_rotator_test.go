package credentials

import (
	"strings"
	"testing"
)

// TestSSHConfigFromMap_ValidDefaults checks that a fully-specified valid map
// parses correctly and that port/admin_auth defaults are applied when omitted.
func TestSSHConfigFromMap_ValidDefaults(t *testing.T) {
	cfg := map[string]any{
		"host":            "10.0.0.1",
		"username":        "alice",
		"admin_secret_id": "secret-uuid-1",
		"admin_username":  "ubuntu",
		"host_key":        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test",
	}
	conf, err := sshConfigFromMap(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.host != "10.0.0.1" {
		t.Errorf("host: got %q, want %q", conf.host, "10.0.0.1")
	}
	if conf.port != 22 {
		t.Errorf("port default: got %d, want 22", conf.port)
	}
	if conf.username != "alice" {
		t.Errorf("username: got %q", conf.username)
	}
	if conf.adminSecretID != "secret-uuid-1" {
		t.Errorf("adminSecretID: got %q", conf.adminSecretID)
	}
	if conf.adminUsername != "ubuntu" {
		t.Errorf("adminUsername: got %q", conf.adminUsername)
	}
	if conf.adminAuth != "password" {
		t.Errorf("adminAuth default: got %q, want %q", conf.adminAuth, "password")
	}
	if conf.hostKey == "" {
		t.Errorf("hostKey: should not be empty")
	}
}

// TestSSHConfigFromMap_ExplicitPort verifies that an explicit port overrides the default.
func TestSSHConfigFromMap_ExplicitPort(t *testing.T) {
	cfg := map[string]any{
		"host":            "192.168.1.1",
		"port":            float64(2222), // JSON numbers decode as float64
		"username":        "bob",
		"admin_secret_id": "s1",
		"admin_username":  "admin",
		"admin_auth":      "private_key",
		"host_key":        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test",
	}
	conf, err := sshConfigFromMap(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.port != 2222 {
		t.Errorf("port: got %d, want 2222", conf.port)
	}
	if conf.adminAuth != "private_key" {
		t.Errorf("adminAuth: got %q, want %q", conf.adminAuth, "private_key")
	}
}

// TestSSHConfigFromMap_MissingRequired verifies that each required field produces an error.
func TestSSHConfigFromMap_MissingRequired(t *testing.T) {
	base := map[string]any{
		"host":            "10.0.0.1",
		"username":        "alice",
		"admin_secret_id": "secret-uuid-1",
		"admin_username":  "ubuntu",
		"host_key":        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test",
	}
	required := []string{"host", "username", "admin_secret_id", "admin_username", "host_key"}
	for _, field := range required {
		t.Run("missing_"+field, func(t *testing.T) {
			// shallow copy
			m := make(map[string]any, len(base))
			for k, v := range base {
				m[k] = v
			}
			delete(m, field)
			_, err := sshConfigFromMap(m)
			if err == nil {
				t.Errorf("expected error when %q is missing, got nil", field)
			}
		})
	}
}

// TestChpasswdStdin verifies the stdin payload shape: "username:password".
func TestChpasswdStdin(t *testing.T) {
	result := chpasswdStdin("alice", []byte("s3cr3t!"))
	if !strings.HasPrefix(result, "alice:") {
		t.Errorf("expected prefix %q, got %q", "alice:", result)
	}
	if !strings.Contains(result, "s3cr3t!") {
		t.Errorf("expected new value in result, got %q", result)
	}
	// Must be exactly one colon separating user from value (no colon in username here).
	parts := strings.SplitN(result, ":", 2)
	if len(parts) != 2 {
		t.Errorf("expected exactly one colon, got %q", result)
	}
	if parts[0] != "alice" {
		t.Errorf("username part: got %q, want %q", parts[0], "alice")
	}
	if parts[1] != "s3cr3t!" {
		t.Errorf("value part: got %q, want %q", parts[1], "s3cr3t!")
	}
}

// TestChpasswdStdin_EmptyUsername verifies that an empty username produces ":val"
// (config validation prevents this in practice, but the helper is pure).
func TestChpasswdStdin_EmptyUsername(t *testing.T) {
	result := chpasswdStdin("", []byte("val"))
	if result != ":val" {
		t.Errorf("empty username: got %q, want %q", result, ":val")
	}
}

// TestChpasswdCommand_Root verifies that a root admin uses bare "chpasswd".
func TestChpasswdCommand_Root(t *testing.T) {
	if got := chpasswdCommand(true); got != "chpasswd" {
		t.Errorf("root: got %q, want %q", got, "chpasswd")
	}
}

// TestChpasswdCommand_NonRoot verifies that a non-root admin uses "sudo chpasswd".
func TestChpasswdCommand_NonRoot(t *testing.T) {
	if got := chpasswdCommand(false); got != "sudo chpasswd" {
		t.Errorf("non-root: got %q, want %q", got, "sudo chpasswd")
	}
}
