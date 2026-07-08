package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"
)

func TestBackupEncryptRoundTrip(t *testing.T) {
	m := &Manager{}
	plaintext := []byte("sensitive backup archive bytes \x00\x01\x02")
	const pass = "correct horse battery staple"

	ct, err := m.encrypt(plaintext, pass)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.HasPrefix(ct, backupKeyMagic) {
		t.Errorf("ciphertext missing scrypt-format magic prefix")
	}
	if bytes.Contains(ct, plaintext) {
		t.Errorf("ciphertext contains the plaintext")
	}
	got, err := m.decrypt(ct, pass)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

// TestBackupDecryptLegacy proves that backups written before scrypt (raw sha256(passphrase) key,
// no magic/salt) still decrypt.
func TestBackupDecryptLegacy(t *testing.T) {
	m := &Manager{}
	plaintext := []byte("legacy backup contents")
	const pass = "legacy-passphrase"

	// Reproduce the old format: nonce || gcm.Seal, key = sha256(passphrase).
	key := sha256.Sum256([]byte(pass))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}
	legacy := gcm.Seal(nonce, nonce, plaintext, nil)
	if bytes.HasPrefix(legacy, backupKeyMagic) {
		t.Skip("legacy blob coincidentally matched magic (2^-64); skip")
	}

	got, err := m.decrypt(legacy, pass)
	if err != nil {
		t.Fatalf("legacy decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("legacy round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestBackupDecryptWrongPassphrase(t *testing.T) {
	m := &Manager{}
	ct, err := m.encrypt([]byte("secret"), "right")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := m.decrypt(ct, "wrong"); err == nil {
		t.Error("decrypt with wrong passphrase should fail")
	}
}
