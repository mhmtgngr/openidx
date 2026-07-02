package vault

import (
	"bytes"
	"testing"
)

func testKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	r := &keyring{keys: map[byte][]byte{0: testKey(1)}, activeID: 0}
	pt := []byte("s3cr3t-p@ss")
	keyID, blob, err := r.Seal("secret-abc", 1, pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if keyID != 0 {
		t.Fatalf("keyID=%d want 0", keyID)
	}
	if bytes.Contains(blob, pt) {
		t.Fatal("plaintext leaked into ciphertext blob")
	}
	got, err := r.Open(keyID, "secret-abc", 1, blob)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("open=%q want %q", got, pt)
	}
}

func TestOpenWrongContextFails(t *testing.T) {
	r := &keyring{keys: map[byte][]byte{0: testKey(1)}, activeID: 0}
	_, blob, _ := r.Seal("secret-abc", 1, []byte("x"))
	if _, err := r.Open(0, "secret-abc", 2, blob); err == nil { // wrong version → wrong derived key
		t.Fatal("expected auth failure on version mismatch")
	}
	if _, err := r.Open(0, "other", 1, blob); err == nil {
		t.Fatal("expected auth failure on secretID mismatch")
	}
}

func TestKeyRotation(t *testing.T) {
	r := &keyring{keys: map[byte][]byte{0: testKey(1)}, activeID: 0}
	_, blobV1, _ := r.Seal("s", 1, []byte("v1val"))
	// Rotate: add key id 1, make it active.
	r.keys[1] = testKey(2)
	r.activeID = 1
	idV2, blobV2, _ := r.Seal("s", 2, []byte("v2val"))
	if idV2 != 1 {
		t.Fatalf("new version keyID=%d want 1", idV2)
	}
	// Old version still opens under retained key 0.
	if got, err := r.Open(0, "s", 1, blobV1); err != nil || string(got) != "v1val" {
		t.Fatalf("old version decrypt failed: %v %q", err, got)
	}
	if got, _ := r.Open(1, "s", 2, blobV2); string(got) != "v2val" {
		t.Fatal("new version decrypt failed")
	}
	// Retire key 0 → old version errors clearly.
	delete(r.keys, 0)
	if _, err := r.Open(0, "s", 1, blobV1); err == nil {
		t.Fatal("expected retired-key error")
	}
}

func TestNewKeyring(t *testing.T) {
	// single raw form (base64 of 32 bytes)
	single := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 zero bytes b64
	r, err := newKeyring("", 0, single)
	if err != nil || r == nil || !r.Enabled() {
		t.Fatalf("single keyring: %v", err)
	}
	// unset → nil ring, no error (caller applies ENCRYPTION_KEY default / fail-closed)
	r2, err := newKeyring("", 0, "")
	if err != nil || r2 != nil {
		t.Fatalf("empty keyring should be (nil,nil): %v", err)
	}
	// bad length
	if _, err := newKeyring("", 0, "QUJD"); err == nil {
		t.Fatal("expected bad-length error")
	}
	// multi form + active id not present
	if _, err := newKeyring("0:"+single, 5, ""); err == nil {
		t.Fatal("expected active-id-missing error")
	}
}
