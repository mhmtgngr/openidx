package secretcrypt

import (
	"encoding/base64"
	"strings"
	"testing"
)

func key32(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b + byte(i)
	}
	return k
}

func TestKeyringRoundTrip(t *testing.T) {
	c, err := NewKeyring(map[int][]byte{1: key32(1)}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := c.Encrypt("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct, "encv2:1:") {
		t.Fatalf("want encv2:1: prefix, got %q", ct[:12])
	}
	pt, err := c.Decrypt(ct)
	if err != nil || pt != "hunter2" {
		t.Fatalf("pt=%q err=%v", pt, err)
	}
}

// TestRotationKeepsOldReadable is the core guarantee: after adding a new KEK and
// flipping the active id, values sealed under the old KEK still decrypt, and new
// writes seal under the new one — no re-encryption flag-day.
func TestRotationKeepsOldReadable(t *testing.T) {
	k1, k2 := key32(1), key32(50)

	// v1 of the keyring: only KEK 1, active 1.
	old, _ := NewKeyring(map[int][]byte{1: k1}, 1, nil)
	sealedUnder1, _ := old.Encrypt("old-secret")
	if !strings.HasPrefix(sealedUnder1, "encv2:1:") {
		t.Fatalf("old value should be encv2:1, got %q", sealedUnder1)
	}

	// Rotate: add KEK 2, make it active. KEK 1 retained for reads.
	rotated, err := NewKeyring(map[int][]byte{1: k1, 2: k2}, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Old value still decrypts (via retained KEK 1).
	if pt, err := rotated.Decrypt(sealedUnder1); err != nil || pt != "old-secret" {
		t.Fatalf("rotated cipher must still read KEK-1 value: pt=%q err=%v", pt, err)
	}
	// New writes seal under the active KEK 2.
	sealedUnder2, _ := rotated.Encrypt("new-secret")
	if !strings.HasPrefix(sealedUnder2, "encv2:2:") {
		t.Fatalf("new value should be encv2:2, got %q", sealedUnder2)
	}
	if pt, _ := rotated.Decrypt(sealedUnder2); pt != "new-secret" {
		t.Fatalf("new value should round-trip, got %q", pt)
	}
}

// TestKeyringReadsEncv1ViaLegacy: a keyring configured with the old ENCRYPTION_KEY
// as its legacy reader can decrypt pre-existing encv1 data.
func TestKeyringReadsEncv1ViaLegacy(t *testing.T) {
	legacy := "0123456789abcdef0123456789abcdef" // 32 bytes
	single, _ := New(legacy)                     // no ENCRYPTION_KEYS -> single-key encv1
	encv1, _ := single.Encrypt("legacy-secret")
	if !strings.HasPrefix(encv1, "encv1:") {
		t.Fatalf("single-key should produce encv1, got %q", encv1)
	}

	ring, err := NewKeyring(map[int][]byte{1: key32(9)}, 1, []byte(legacy))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := ring.Decrypt(encv1); err != nil || pt != "legacy-secret" {
		t.Fatalf("keyring must read encv1 via legacy key: pt=%q err=%v", pt, err)
	}
}

func TestKeyringMissingKekIDErrors(t *testing.T) {
	sealed := "encv2:1:" + base64.StdEncoding.EncodeToString([]byte("whatever"))
	ring, _ := NewKeyring(map[int][]byte{2: key32(2)}, 2, nil) // no KEK 1
	if _, err := ring.Decrypt(sealed); err == nil {
		t.Fatal("decrypt with a missing KEK id must error")
	}
}

func TestNewKeyringValidation(t *testing.T) {
	if _, err := NewKeyring(map[int][]byte{1: key32(1)}, 2, nil); err == nil {
		t.Fatal("active id not in ring must error")
	}
	if _, err := NewKeyring(map[int][]byte{1: []byte("short")}, 1, nil); err == nil {
		t.Fatal("non-32-byte KEK must error")
	}
	if _, err := NewKeyring(map[int][]byte{}, 1, nil); err == nil {
		t.Fatal("empty ring must error")
	}
}

// TestNewFromEnvKeyring: New(key) enters keyring mode when ENCRYPTION_KEYS is set,
// seals encv2 under the active id, and still reads encv1 sealed by the key param.
func TestNewFromEnvKeyring(t *testing.T) {
	legacy := "0123456789abcdef0123456789abcdef"
	// Pre-existing encv1 written by the single-key cipher.
	single, _ := New(legacy)
	encv1, _ := single.Encrypt("pre-existing")

	k2 := base64.StdEncoding.EncodeToString(key32(77))
	t.Setenv("ENCRYPTION_KEYS", "2:"+k2)
	t.Setenv("ENCRYPTION_ACTIVE_KEK_ID", "2")

	c, err := New(legacy) // legacy passed as the encv1 reader
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := c.Encrypt("via-env")
	if !strings.HasPrefix(ct, "encv2:2:") {
		t.Fatalf("env keyring should seal encv2:2, got %q", ct)
	}
	if pt, _ := c.Decrypt(ct); pt != "via-env" {
		t.Fatalf("encv2 round-trip failed: %q", pt)
	}
	if pt, err := c.Decrypt(encv1); err != nil || pt != "pre-existing" {
		t.Fatalf("env keyring must read prior encv1: pt=%q err=%v", pt, err)
	}
}
