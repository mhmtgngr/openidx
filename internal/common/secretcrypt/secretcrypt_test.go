package secretcrypt

import (
	"strings"
	"testing"
)

const testKey = "0123456789abcdef0123456789abcdef" // 32 bytes

func TestNewRejectsBadKey(t *testing.T) {
	if _, err := New("short"); err == nil {
		t.Fatal("expected error for non-32-byte key")
	}
	if _, err := New(testKey); err != nil {
		t.Fatalf("unexpected error for 32-byte key: %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	c, _ := New(testKey)
	for _, pt := range []string{"s3cr3t", "a much longer client secret value with spaces & symbols !@#$%", "π-unicode-✓"} {
		enc, err := c.Encrypt(pt)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if !IsEncrypted(enc) {
			t.Fatalf("ciphertext missing version tag: %q", enc)
		}
		if strings.Contains(enc, pt) {
			t.Fatalf("ciphertext leaks plaintext: %q", enc)
		}
		got, err := c.Decrypt(enc)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if got != pt {
			t.Fatalf("roundtrip mismatch: got %q want %q", got, pt)
		}
	}
}

func TestEmptyIsNoop(t *testing.T) {
	c, _ := New(testKey)
	if enc, err := c.Encrypt(""); err != nil || enc != "" {
		t.Fatalf("Encrypt(\"\") = %q,%v; want \"\",nil", enc, err)
	}
	if dec, err := c.Decrypt(""); err != nil || dec != "" {
		t.Fatalf("Decrypt(\"\") = %q,%v; want \"\",nil", dec, err)
	}
}

func TestLegacyPlaintextPassthrough(t *testing.T) {
	c, _ := New(testKey)
	legacy := "plaintext-legacy-secret"
	if IsEncrypted(legacy) {
		t.Fatal("legacy value should not look encrypted")
	}
	got, err := c.Decrypt(legacy)
	if err != nil {
		t.Fatalf("legacy passthrough errored: %v", err)
	}
	if got != legacy {
		t.Fatalf("legacy passthrough changed value: got %q want %q", got, legacy)
	}
}

func TestNonDeterministic(t *testing.T) {
	c, _ := New(testKey)
	a, _ := c.Encrypt("same")
	b, _ := c.Encrypt("same")
	if a == b {
		t.Fatal("expected distinct ciphertexts (random nonce) for the same plaintext")
	}
}

func TestWrongKeyFails(t *testing.T) {
	c, _ := New(testKey)
	enc, _ := c.Encrypt("secret")
	other, _ := New("ffffffffffffffffffffffffffffffff")
	if _, err := other.Decrypt(enc); err == nil {
		t.Fatal("expected decrypt failure under a different key")
	}
}

func TestTamperFails(t *testing.T) {
	c, _ := New(testKey)
	enc, _ := c.Encrypt("secret")
	// Flip a byte in the base64 body (after the tag).
	body := []byte(strings.TrimPrefix(enc, tag))
	body[len(body)-2] ^= 0x01
	tampered := tag + string(body)
	if _, err := c.Decrypt(tampered); err == nil {
		t.Fatal("expected decrypt failure for tampered ciphertext")
	}
}
