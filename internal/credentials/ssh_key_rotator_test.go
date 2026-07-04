package credentials

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeVaultUser is a stub vaultUser for tests that need to construct a rotator without a
// real vault. Use should never be reached in the validation test (the guard fires first).
type fakeVaultUser struct {
	value []byte
	err   error
	used  bool
}

func (f *fakeVaultUser) Use(_ context.Context, _ string) ([]byte, error) {
	f.used = true
	return f.value, f.err
}

// TestSSHKeyRotator_Generate verifies Generate produces a parseable ed25519 OpenSSH key.
func TestSSHKeyRotator_Generate(t *testing.T) {
	r := &sshKeyRotator{}
	pem, err := r.Generate(GenerationPolicy{})
	if err != nil {
		t.Fatalf("Generate: unexpected error: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if got := signer.PublicKey().Type(); got != "ssh-ed25519" {
		t.Errorf("public key type: got %q, want %q", got, "ssh-ed25519")
	}
}

// TestSSHKeyRotator_AuthorizedLine verifies the authorized_keys line is well-formed and tagged.
func TestSSHKeyRotator_AuthorizedLine(t *testing.T) {
	r := &sshKeyRotator{}
	gen, err := r.Generate(GenerationPolicy{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	line, err := r.authorizedLine(gen, "deploy")
	if err != nil {
		t.Fatalf("authorizedLine: %v", err)
	}
	if !strings.HasSuffix(line, " openidx-rotated:deploy") {
		t.Errorf("line suffix: got %q, want trailing %q", line, " openidx-rotated:deploy")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil {
		t.Errorf("ParseAuthorizedKey rejected line %q: %v", line, err)
	}
}

// TestSSHKeyRotator_ValidateUsername rejects an unsafe username directly.
func TestSSHKeyRotator_ValidateUsername(t *testing.T) {
	if err := validateUsername("deploy"); err != nil {
		t.Errorf("valid username rejected: %v", err)
	}
	if err := validateUsername("a; rm -rf /"); err == nil {
		t.Error("expected error for unsafe username, got nil")
	}
}

// TestSSHKeyRotator_ApplyRejectsUnsafeUsername verifies Apply fails on a bad username
// BEFORE resolving the admin secret or dialing.
func TestSSHKeyRotator_ApplyRejectsUnsafeUsername(t *testing.T) {
	fv := &fakeVaultUser{value: []byte("admin-secret")}
	r := &sshKeyRotator{vault: fv}
	gen, err := r.Generate(GenerationPolicy{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cfg := map[string]any{
		"host":            "10.0.0.1",
		"username":        "a; rm -rf /",
		"admin_secret_id": "s1",
		"admin_username":  "ubuntu",
		"host_key":        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test",
	}
	if err := r.Apply(context.Background(), cfg, gen); err == nil {
		t.Fatal("expected error for unsafe username, got nil")
	}
	if fv.used {
		t.Error("vault.Use was called before username validation")
	}
}

// TestAuthorizedKeysScript is a sanity check on the generated script content.
func TestAuthorizedKeysScript(t *testing.T) {
	s := authorizedKeysScript("deploy")
	if !strings.Contains(s, "openidx-rotated:$u") {
		t.Errorf("script missing openidx-rotated:$u tag matcher: %q", s)
	}
	if !strings.Contains(s, "u=deploy") {
		t.Errorf("script missing user assignment: %q", s)
	}
}
