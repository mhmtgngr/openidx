// Package secretcrypt provides AES-256-GCM encryption-at-rest for individual
// secret DB columns (IdP client secrets, webhook signing secrets, Guacamole pool
// tokens). It is keyed by the 32-byte ENCRYPTION_KEY every service already loads
// — the same key used for TOTP secrets and the Ziti admin password.
//
// Stored values carry a version tag ("encv1:") so reads can distinguish an
// encrypted value from a legacy plaintext one during rollout: Decrypt returns a
// tagged value's plaintext and passes an untagged (legacy) value through
// unchanged. Writes always Encrypt. The tag also leaves room for a future
// keyring-backed "encv2:" without a flag-day.
package secretcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// tag prefixes every ciphertext this package produces. A stored value with this
// prefix is encrypted; anything else is treated as legacy plaintext.
const tag = "encv1:"

// Cipher encrypts/decrypts secret column values with AES-256-GCM.
type Cipher struct {
	key []byte
}

// New returns a Cipher for the given key, which must be exactly 32 bytes
// (AES-256). Fail-closed: an unusable key is an error, never silent plaintext.
func New(key string) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secretcrypt: key must be 32 bytes for AES-256, got %d", len(key))
	}
	return &Cipher{key: []byte(key)}, nil
}

// IsEncrypted reports whether stored carries this package's version tag (i.e. was
// produced by Encrypt) rather than being a legacy plaintext value.
func IsEncrypted(stored string) bool {
	return strings.HasPrefix(stored, tag)
}

// Encrypt returns the tagged, base64-encoded AES-256-GCM ciphertext of plaintext
// (nonce prepended). An empty plaintext returns "" unchanged (nothing to protect).
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	gcm, err := c.gcm()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("secretcrypt: nonce: %w", err)
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return tag + base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt returns the plaintext of a value produced by Encrypt. A value WITHOUT
// the version tag is assumed to be legacy plaintext and returned unchanged — this
// is what lets reads work while rows are being migrated. An empty string returns
// "" unchanged.
func (c *Cipher) Decrypt(stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if !IsEncrypted(stored) {
		return stored, nil // legacy plaintext passthrough
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, tag))
	if err != nil {
		return "", fmt.Errorf("secretcrypt: base64: %w", err)
	}
	gcm, err := c.gcm()
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return "", fmt.Errorf("secretcrypt: ciphertext too short")
	}
	nonce, ct := data[:ns], data[ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("secretcrypt: decrypt: %w", err)
	}
	return string(pt), nil
}

func (c *Cipher) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("secretcrypt: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretcrypt: gcm: %w", err)
	}
	return gcm, nil
}
