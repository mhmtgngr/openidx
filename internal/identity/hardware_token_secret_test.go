package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/secretcrypt"
)

func testCipherService(t *testing.T) *Service {
	t.Helper()
	c, err := secretcrypt.New(strings.Repeat("k", 32)) // 32-byte AES-256 key
	if err != nil {
		t.Fatalf("secretcrypt.New: %v", err)
	}
	return &Service{idpCipher: c}
}

// TestEncryptDecryptSecret_RoundTrip verifies a hardware-token secret is encrypted at rest (AES-GCM,
// not the plaintext) and round-trips back to the original.
func TestEncryptDecryptSecret_RoundTrip(t *testing.T) {
	s := testCipherService(t)
	const secret = "JBSWY3DPEHPK3PXP" // sample base32 TOTP seed

	enc, err := s.encryptSecret(secret)
	if err != nil {
		t.Fatalf("encryptSecret: %v", err)
	}
	if !secretcrypt.IsEncrypted(enc) {
		t.Errorf("stored value is not encrypted (no encv1 prefix): %q", enc)
	}
	if strings.Contains(enc, secret) {
		t.Errorf("stored value contains the plaintext secret: %q", enc)
	}
	if got := s.decryptSecret(enc); got != secret {
		t.Errorf("decryptSecret round-trip = %q, want %q", got, secret)
	}
}

// TestDecryptSecret_LegacyFormat verifies the pre-encryption "<64-hex sha256>:<secret>" format is still
// readable (so existing rows keep working until they're re-written).
func TestDecryptSecret_LegacyFormat(t *testing.T) {
	s := testCipherService(t)
	const secret = "LEGACYSEED123456"
	h := sha256.Sum256([]byte(secret))
	legacy := hex.EncodeToString(h[:]) + ":" + secret

	if got := s.decryptSecret(legacy); got != secret {
		t.Errorf("legacy decryptSecret = %q, want %q", got, secret)
	}
	// A bare/plaintext value (no encv1 prefix, no 64-hex:prefix) is returned as-is.
	if got := s.decryptSecret("plainsecret"); got != "plainsecret" {
		t.Errorf("plaintext decryptSecret = %q, want %q", got, "plainsecret")
	}
	// A value with a colon but not a 64-hex prefix must NOT be treated as legacy.
	if got := s.decryptSecret("notahash:value"); got != "notahash:value" {
		t.Errorf("non-legacy colon value = %q, want unchanged", got)
	}
}
