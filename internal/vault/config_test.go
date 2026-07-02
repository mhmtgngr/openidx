package vault

import "testing"

func TestKeyringFromConfig_DefaultsToEncryptionKey(t *testing.T) {
	// 32-byte raw ENCRYPTION_KEY, no VAULT_* set → id 0 default.
	r, err := KeyringFromConfig(KeyConfig{EncryptionKey: string(make([]byte, 32))})
	if err != nil || r == nil || !r.Enabled() {
		t.Fatalf("expected default ring from ENCRYPTION_KEY: %v", err)
	}
}

func TestKeyringFromConfig_FailsClosed(t *testing.T) {
	if _, err := KeyringFromConfig(KeyConfig{}); err == nil {
		t.Fatal("expected fail-closed error when no KEK available")
	}
	// ENCRYPTION_KEY of wrong length is also fail-closed.
	if _, err := KeyringFromConfig(KeyConfig{EncryptionKey: "too-short"}); err == nil {
		t.Fatal("expected fail-closed on short ENCRYPTION_KEY")
	}
}
