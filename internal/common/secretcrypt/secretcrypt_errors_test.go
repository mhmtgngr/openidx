package secretcrypt

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestDecryptRejectsMalformedBase64 ensures a tagged value whose body is not valid
// base64 (e.g. a corrupted DB column) yields a clean error rather than a panic.
func TestDecryptRejectsMalformedBase64(t *testing.T) {
	c, _ := New(testKey)
	if _, err := c.Decrypt(tag + "not!!valid!!base64"); err == nil {
		t.Fatal("expected error for malformed base64 body")
	} else if !strings.Contains(err.Error(), "base64") {
		t.Fatalf("expected base64 error, got: %v", err)
	}
}

// TestDecryptRejectsShortCiphertext ensures a tagged value shorter than the GCM
// nonce is rejected (bounds check) instead of slicing out of range.
func TestDecryptRejectsShortCiphertext(t *testing.T) {
	c, _ := New(testKey)
	// A validly base64-encoded body of only a few bytes — far shorter than the
	// 12-byte GCM nonce the decoder expects to strip first.
	short := tag + base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03})
	if _, err := c.Decrypt(short); err == nil {
		t.Fatal("expected error for ciphertext shorter than the nonce")
	} else if !strings.Contains(err.Error(), "too short") {
		t.Fatalf("expected 'too short' error, got: %v", err)
	}
}

// TestIsEncrypted checks the tag discriminator both ways.
func TestIsEncrypted(t *testing.T) {
	c, _ := New(testKey)
	enc, err := c.Encrypt("secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !IsEncrypted(enc) {
		t.Errorf("Encrypt output should be reported as encrypted: %q", enc)
	}
	if IsEncrypted("plain-legacy-value") {
		t.Error("legacy plaintext should not be reported as encrypted")
	}
	if IsEncrypted("") {
		t.Error("empty string should not be reported as encrypted")
	}
}

// TestNoopDecryptLeavesTaggedValueUntouched documents that a noop cipher returns
// even a tagged value verbatim (it never had a key to decrypt with).
func TestNoopDecryptLeavesTaggedValueUntouched(t *testing.T) {
	n := NewNoop()
	in := tag + "anything"
	out, err := n.Decrypt(in)
	if err != nil {
		t.Fatalf("noop decrypt: %v", err)
	}
	if out != in {
		t.Errorf("noop Decrypt changed value: got %q want %q", out, in)
	}
}
