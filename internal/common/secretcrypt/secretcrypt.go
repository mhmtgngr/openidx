// Package secretcrypt provides AES-256-GCM encryption-at-rest for individual
// secret DB columns (IdP client secrets, webhook signing secrets, Guacamole pool
// tokens, TOTP secrets, the Ziti admin password, the RS256 signing keys, …).
//
// # Versioning and rotation
//
// Stored values carry a version tag so reads can tell an encrypted value from a
// legacy plaintext one, AND which key sealed it:
//
//   - "encv1:<b64>"          — single-key, sealed under ENCRYPTION_KEY.
//   - "encv2:<kekID>:<b64>"  — keyring, sealed under the KEK with that id.
//   - (no tag)               — legacy plaintext, passed through unchanged.
//
// Single-key mode (New(key), no ENCRYPTION_KEYS set) is the original behavior:
// it seals encv1 and is byte-compatible with existing data. Keyring mode is
// OPT-IN via ENCRYPTION_KEYS ("id:base64,id:base64") + ENCRYPTION_ACTIVE_KEK_ID:
// new writes seal encv2 under the active KEK (id embedded), while encv1 values
// still decrypt via ENCRYPTION_KEY (kept as the legacy reader) and encv2 values
// decrypt via their embedded id. Rotate by adding a KEK and flipping the active
// id — old ciphertext stays readable as long as its KEK remains in the ring (no
// flag-day; mirrors internal/vault/crypto.go). This is the "encv2 keyring" the
// original single-key implementation left room for.
package secretcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	tagV1 = "encv1:"
	tagV2 = "encv2:"
	// tag is the original single-key prefix (== tagV1), kept for compatibility.
	tag = tagV1
)

// Cipher encrypts/decrypts secret column values with AES-256-GCM. A noop Cipher
// (NewNoop) is a passthrough for environments without a usable key, so secrets
// stay plaintext at rest rather than crashing the service.
type Cipher struct {
	// keys is the KEK ring (id -> 32-byte key) for encv2. Empty in single-key mode.
	keys map[int][]byte
	// activeID is the KEK new writes seal under; 0 means single-key (encv1) mode.
	activeID int
	// legacyKey reads encv1 values (and seals them in single-key mode); nil if none.
	legacyKey []byte
	noop      bool
}

// New returns a Cipher for the given 32-byte key. When ENCRYPTION_KEYS is set it
// returns a keyring Cipher (encv2, rotatable) using `key` as the encv1 legacy
// reader; otherwise a single-key Cipher (encv1) — byte-compatible with existing
// data. An unusable key is an error; callers decide fail-closed vs NewNoop.
func New(key string) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secretcrypt: key must be 32 bytes for AES-256, got %d", len(key))
	}
	if ks := strings.TrimSpace(os.Getenv("ENCRYPTION_KEYS")); ks != "" {
		return newKeyringFromEnv(ks, os.Getenv("ENCRYPTION_ACTIVE_KEK_ID"), []byte(key))
	}
	return &Cipher{activeID: 0, legacyKey: []byte(key)}, nil
}

// NewKeyring builds a keyring Cipher directly (used by tests and explicit
// callers). activeID must be present in keys; every key must be 32 bytes.
// legacyKey (optional, 32 bytes) decrypts pre-existing encv1 values.
func NewKeyring(keys map[int][]byte, activeID int, legacyKey []byte) (*Cipher, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("secretcrypt: keyring has no keys")
	}
	for id, k := range keys {
		if len(k) != 32 {
			return nil, fmt.Errorf("secretcrypt: KEK %d must be 32 bytes for AES-256, got %d", id, len(k))
		}
	}
	if _, ok := keys[activeID]; !ok {
		return nil, fmt.Errorf("secretcrypt: active KEK id %d not in keyring", activeID)
	}
	if legacyKey != nil && len(legacyKey) != 32 {
		return nil, fmt.Errorf("secretcrypt: legacy key must be 32 bytes, got %d", len(legacyKey))
	}
	cp := make(map[int][]byte, len(keys))
	for id, k := range keys {
		cp[id] = append([]byte(nil), k...)
	}
	return &Cipher{keys: cp, activeID: activeID, legacyKey: legacyKey}, nil
}

// newKeyringFromEnv parses ENCRYPTION_KEYS ("id:base64,id:base64") +
// ENCRYPTION_ACTIVE_KEK_ID into a keyring, with legacyKey reading encv1.
func newKeyringFromEnv(keysStr, activeStr string, legacyKey []byte) (*Cipher, error) {
	keys := map[int][]byte{}
	for _, part := range strings.Split(keysStr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idStr, b64, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("secretcrypt: ENCRYPTION_KEYS entry %q must be id:base64", part)
		}
		id, err := strconv.Atoi(strings.TrimSpace(idStr))
		if err != nil {
			return nil, fmt.Errorf("secretcrypt: bad KEK id %q: %w", idStr, err)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil {
			return nil, fmt.Errorf("secretcrypt: KEK %d base64: %w", id, err)
		}
		keys[id] = raw
	}
	activeID, err := strconv.Atoi(strings.TrimSpace(activeStr))
	if err != nil {
		return nil, fmt.Errorf("secretcrypt: ENCRYPTION_ACTIVE_KEK_ID invalid (%q): %w", activeStr, err)
	}
	if legacyKey != nil && len(legacyKey) != 32 {
		legacyKey = nil
	}
	return NewKeyring(keys, activeID, legacyKey)
}

// NewNoop returns a passthrough Cipher for environments without a usable key.
func NewNoop() *Cipher { return &Cipher{noop: true} }

// IsEncrypted reports whether stored was produced by Encrypt (encv1 or encv2).
func IsEncrypted(stored string) bool {
	return strings.HasPrefix(stored, tagV1) || strings.HasPrefix(stored, tagV2)
}

// Encrypt returns the tagged, base64-encoded AES-256-GCM ciphertext of plaintext.
// Keyring mode seals encv2 under the active KEK; single-key mode seals encv1. An
// empty plaintext returns "" unchanged.
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	if c.noop || plaintext == "" {
		return plaintext, nil
	}
	if c.activeID == 0 {
		return c.seal(c.legacyKey, plaintext, tagV1)
	}
	return c.seal(c.keys[c.activeID], plaintext, fmt.Sprintf("%s%d:", tagV2, c.activeID))
}

// Decrypt returns the plaintext of a value produced by Encrypt. encv2 uses the
// embedded KEK id, encv1 uses the legacy key, and an untagged (legacy plaintext)
// value passes through unchanged so reads work during rollout.
func (c *Cipher) Decrypt(stored string) (string, error) {
	if c.noop || stored == "" {
		return stored, nil
	}
	switch {
	case strings.HasPrefix(stored, tagV2):
		rest := stored[len(tagV2):]
		idStr, b64, ok := strings.Cut(rest, ":")
		if !ok {
			return "", fmt.Errorf("secretcrypt: malformed encv2 value")
		}
		id, err := strconv.Atoi(idStr)
		if err != nil {
			return "", fmt.Errorf("secretcrypt: bad encv2 KEK id %q: %w", idStr, err)
		}
		key, ok := c.keys[id]
		if !ok {
			return "", fmt.Errorf("secretcrypt: KEK id %d not in keyring (retired or never configured)", id)
		}
		return c.open(key, b64)
	case strings.HasPrefix(stored, tagV1):
		if c.legacyKey == nil {
			return "", fmt.Errorf("secretcrypt: encv1 value but no legacy key configured")
		}
		return c.open(c.legacyKey, stored[len(tagV1):])
	default:
		return stored, nil // legacy plaintext passthrough
	}
}

func (c *Cipher) seal(key []byte, plaintext, prefix string) (string, error) {
	gcm, err := gcmFor(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("secretcrypt: nonce: %w", err)
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefix + base64.StdEncoding.EncodeToString(ct), nil
}

func (c *Cipher) open(key []byte, b64 string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("secretcrypt: base64: %w", err)
	}
	gcm, err := gcmFor(key)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return "", fmt.Errorf("secretcrypt: ciphertext too short")
	}
	pt, err := gcm.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("secretcrypt: decrypt: %w", err)
	}
	return string(pt), nil
}

func gcmFor(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secretcrypt: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretcrypt: gcm: %w", err)
	}
	return gcm, nil
}
