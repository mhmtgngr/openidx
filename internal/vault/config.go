package vault

import "fmt"

// KeyConfig is the subset of app config the vault keyring needs. Kept local so
// internal/vault does not import internal/common/config.
type KeyConfig struct {
	KEK           string // VAULT_KEK (base64, 32 bytes)
	KEKs          string // VAULT_KEKS ("id:base64,...")
	ActiveKEKID   int    // VAULT_ACTIVE_KEK_ID
	EncryptionKey string // ENCRYPTION_KEY (raw 32-byte string) — fallback KEK id 0
}

// KeyringFromConfig builds the vault KEK ring. Precedence: explicit VAULT_*
// keys, else the raw ENCRYPTION_KEY as id 0. Fails closed when neither yields a
// usable 32-byte key — the vault never silently stores plaintext.
func KeyringFromConfig(cfg KeyConfig) (*keyring, error) {
	r, err := newKeyring(cfg.KEKs, cfg.ActiveKEKID, cfg.KEK)
	if err != nil {
		return nil, err
	}
	if r != nil {
		return r, nil
	}
	if len(cfg.EncryptionKey) != kekLen {
		return nil, fmt.Errorf("vault: no VAULT_KEK/VAULT_KEKS set and ENCRYPTION_KEY is not %d bytes; refusing to start (fail-closed)", kekLen)
	}
	return &keyring{keys: map[byte][]byte{0: []byte(cfg.EncryptionKey)}, activeID: 0}, nil
}
