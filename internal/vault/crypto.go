// Package vault provides an envelope-encrypted, tenant-isolated store for
// privileged credentials (the PAM credential vault). Each secret version is
// sealed with a per-version key derived via HKDF-SHA256 from a key-encryption
// key (KEK) held in an in-memory keyring, then AES-256-GCM encrypted. The KEK
// id is stored alongside the ciphertext so KEKs rotate without re-encrypting
// history: new versions seal under the active id, old versions keep theirs and
// decrypt as long as their KEK remains in the ring.
//
// This mirrors internal/access/recording_crypto.go; the only differences are
// the derivation context (secretID:version) and that the key id lives in its
// own DB column rather than framed into the blob.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const kekLen = 32 // AES-256

const (
	nonceLen = 12 // AES-GCM standard nonce
	tagLen   = 16 // AES-GCM tag
)

// keyring holds the KEKs: an active id used for new seals plus any retained
// ids kept so older versions still decrypt.
type keyring struct {
	keys     map[byte][]byte
	activeID byte
}

func (r *keyring) Enabled() bool { return r != nil && len(r.keys) > 0 }

func (r *keyring) masterFor(id byte) ([]byte, error) {
	k, ok := r.keys[id]
	if !ok {
		return nil, fmt.Errorf("vault KEK id %d not in keyring (retired or never configured)", id)
	}
	return k, nil
}

// deriveGCM derives the per-version AEAD from a KEK. The info string binds the
// key to (secretID, version) so a blob can never be replayed under a different
// secret or version.
func deriveGCM(master []byte, secretID string, version int) (cipher.AEAD, error) {
	if len(master) != kekLen {
		return nil, fmt.Errorf("vault KEK must be %d bytes, got %d", kekLen, len(master))
	}
	info := []byte("openidx-vault-v1:" + secretID + ":" + strconv.Itoa(version))
	kdf := hkdf.New(sha256.New, master, nil, info)
	derived := make([]byte, 32)
	if _, err := io.ReadFull(kdf, derived); err != nil {
		return nil, fmt.Errorf("hkdf read: %w", err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext under the active KEK. Returns the KEK id (to store in
// the key_id column) and blob = nonce(12) | ciphertext+tag.
func (r *keyring) Seal(secretID string, version int, plaintext []byte) (byte, []byte, error) {
	master, err := r.masterFor(r.activeID)
	if err != nil {
		return 0, nil, err
	}
	gcm, err := deriveGCM(master, secretID, version)
	if err != nil {
		return 0, nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0, nil, fmt.Errorf("nonce random: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	blob := make([]byte, nonceLen+len(ct))
	copy(blob, nonce)
	copy(blob[nonceLen:], ct)
	return r.activeID, blob, nil
}

// Open decrypts a blob produced by Seal under the KEK identified by keyID.
func (r *keyring) Open(keyID byte, secretID string, version int, blob []byte) ([]byte, error) {
	if len(blob) < nonceLen+tagLen {
		return nil, errors.New("vault ciphertext too short")
	}
	master, err := r.masterFor(keyID)
	if err != nil {
		return nil, err
	}
	gcm, err := deriveGCM(master, secretID, version)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, blob[:nonceLen], blob[nonceLen:], nil)
}

// newKeyring builds a ring from config. multiForm is comma-separated
// "id:base64key" entries (activeID selects the write key); otherwise singleKey
// (base64 of 32 bytes) loads as id 0 active. Returns (nil,nil) when neither is
// set so the caller can apply the ENCRYPTION_KEY default or fail closed.
func newKeyring(multiForm string, activeID int, singleKey string) (*keyring, error) {
	multiForm = strings.TrimSpace(multiForm)
	if multiForm == "" {
		if strings.TrimSpace(singleKey) == "" {
			return nil, nil
		}
		raw, err := decodeKEK(singleKey)
		if err != nil {
			return nil, fmt.Errorf("vault_kek: %w", err)
		}
		return &keyring{keys: map[byte][]byte{0: raw}, activeID: 0}, nil
	}
	ring := &keyring{keys: make(map[byte][]byte)}
	for _, entry := range strings.Split(multiForm, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		idStr, keyStr, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("vault_keks: entry %q is not id:base64key", entry)
		}
		id, err := strconv.Atoi(strings.TrimSpace(idStr))
		if err != nil || id < 0 || id > 255 {
			return nil, fmt.Errorf("vault_keks: id %q must be 0-255", idStr)
		}
		raw, err := decodeKEK(keyStr)
		if err != nil {
			return nil, fmt.Errorf("vault_keks: id %d: %w", id, err)
		}
		ring.keys[byte(id)] = raw
	}
	if len(ring.keys) == 0 {
		return nil, errors.New("vault_keks: no valid entries")
	}
	if activeID < 0 || activeID > 255 {
		return nil, fmt.Errorf("vault_active_kek_id %d must be 0-255", activeID)
	}
	if _, ok := ring.keys[byte(activeID)]; !ok {
		return nil, fmt.Errorf("vault_active_kek_id %d not present in vault_keks", activeID)
	}
	ring.activeID = byte(activeID)
	return ring, nil
}

func decodeKEK(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	if len(raw) != kekLen {
		return nil, fmt.Errorf("must decode to %d bytes, got %d", kekLen, len(raw))
	}
	return raw, nil
}
