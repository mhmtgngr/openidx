package secretfile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// aesKeystore is a real AEAD in the shape a platform keystore presents: seal
// and open, key held elsewhere. Here "elsewhere" is a field, which is exactly
// the property a device keystore has and this does not — the point of these
// tests is the file format and the self-test, not the key's custody.
type aesKeystore struct{ aead cipher.AEAD }

func newAESKeystore(t *testing.T) aesKeystore {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	return aesKeystore{aead: aead}
}

func (k aesKeystore) Wrap(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return k.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (k aesKeystore) Unwrap(sealed []byte) ([]byte, error) {
	n := k.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("short")
	}
	return k.aead.Open(nil, sealed[:n], sealed[n:], nil)
}

func use(t *testing.T, k Keystore) {
	t.Helper()
	if err := Use(k); err != nil {
		t.Fatalf("Use: %v", err)
	}
	t.Cleanup(Forget)
}

// TestSelfTestRejectsEachWayAKeystoreCanFailToSeal. Every entry compiles and
// runs; each would let an app sign in and store its refresh token in a form
// somebody else can read. The self-test is the only thing between them and the
// disk, so each way of failing gets its own case rather than one "bad keystore".
func TestSelfTestRejectsEachWayAKeystoreCanFailToSeal(t *testing.T) {
	for _, tc := range []struct {
		name string
		ks   Keystore
		want string // a distinctive fragment of the refusal
	}{
		{"returns the plaintext", identityKeystore{}, "plaintext unchanged"},
		{"wraps a header round the plaintext", headerKeystore{}, "CONTAINS the plaintext"},
		{"is deterministic", staticNonceKeystore{newAEAD()}, "deterministic"},
		{"cannot wrap", failingKeystore{}, "could not wrap"},
		{"returns nothing", emptyKeystore{}, "empty seal"},
		{"does not round-trip", lossyKeystore{}, "did not return the plaintext"},
		{"panics", panickingKeystore{}, "panicked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := SelfTest(tc.ks)
			if err == nil {
				t.Fatalf("SelfTest accepted a keystore that %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not name the property that failed:\n  got:  %v\n  want a mention of %q",
					err, tc.want)
			}
			if err := Use(tc.ks); err == nil {
				t.Fatal("Use registered a keystore that failed its self-test")
			}
			if Active() {
				t.Error("a keystore is registered after Use refused it")
			}
		})
	}
}

func TestSelfTestAcceptsARealAEAD(t *testing.T) {
	if err := SelfTest(newAESKeystore(t)); err != nil {
		t.Fatalf("SelfTest refused AES-256-GCM with a random nonce: %v", err)
	}
}

// TestARegisteredKeystoreSealsWhatWriteStores, including the case Write's own
// platform layer covers on Windows and nowhere else — off Windows this is the
// difference between a plaintext file and a sealed one.
func TestARegisteredKeystoreSealsWhatWriteStores(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(string, []byte) error
	}{
		{"Write", Write},
		{"WriteShared", WriteShared},
	} {
		t.Run(tc.name, func(t *testing.T) {
			use(t, newAESKeystore(t))

			path := filepath.Join(t.TempDir(), "secret.json")
			secret := []byte(`{"refresh_token":"the-thing-that-must-not-be-readable"}`)
			if err := tc.write(path, secret); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if bytes.Contains(raw, []byte("must-not-be-readable")) {
				t.Fatal("the secret is in the file in the clear")
			}
			if !bytes.HasPrefix(raw, keystoreMagic) {
				t.Fatalf("the file carries no keystore marker: %q", raw[:min(len(raw), 48)])
			}

			back, err := Read(path)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if !bytes.Equal(back, secret) {
				t.Fatalf("round-trip lost the secret: %q", back)
			}
		})
	}
}

// TestWriteSharedIsUnchangedWithoutAKeystore pins the desktop half. agent.json
// moved onto this package in the same change that added the seam, and on every
// desktop — where no keystore is registered — it has to be the file it always
// was, byte for byte, or the Windows service and the tray stop reading it.
func TestWriteSharedIsUnchangedWithoutAKeystore(t *testing.T) {
	if Active() {
		t.Fatal("a keystore is registered; this test is about the case where none is")
	}
	path := filepath.Join(t.TempDir(), "agent.json")
	data := []byte(`{"auth_token":"abc"}`)
	if err := WriteShared(path, data); err != nil {
		t.Fatalf("WriteShared: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(raw, data) {
		t.Fatalf("WriteShared changed the bytes with no keystore registered:\n  got  %q\n  want %q", raw, data)
	}
}

// TestASealedFileIsUnreadableWithNoKeystore: the config directory of a phone,
// copied somewhere else. It must fail by name, not return ciphertext for
// something upstream to parse into nonsense.
func TestASealedFileIsUnreadableWithNoKeystore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.json")
	func() {
		use(t, newAESKeystore(t))
		if err := Write(path, []byte("secret")); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}()
	Forget()

	if _, err := Read(path); !errors.Is(err, ErrNoKeystore) {
		t.Fatalf("reading a sealed file with no keystore gave %v, want ErrNoKeystore", err)
	}
}

// TestResealUpgradesAPlaintextFileAndLeavesASealedOneAlone.
func TestResealUpgradesAPlaintextFileAndLeavesASealedOneAlone(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.json")
	if err := os.WriteFile(plain, []byte("in-the-clear"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	use(t, newAESKeystore(t))

	if err := Reseal(plain, Write); err != nil {
		t.Fatalf("Reseal: %v", err)
	}
	raw, err := os.ReadFile(plain)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if bytes.Contains(raw, []byte("in-the-clear")) {
		t.Fatal("Reseal left the plaintext in the file")
	}
	sealed := append([]byte(nil), raw...)

	// A second pass must not seal the seal: that would still round-trip and
	// would grow the file on every launch.
	if err := Reseal(plain, Write); err != nil {
		t.Fatalf("second Reseal: %v", err)
	}
	again, err := os.ReadFile(plain)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(sealed, again) {
		t.Fatal("Reseal rewrote an already-sealed file")
	}

	// And an absent file is not an error: a first launch has neither.
	if err := Reseal(filepath.Join(dir, "not-there.json"), Write); err != nil {
		t.Fatalf("Reseal of a missing file: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func newAEAD() cipher.AEAD {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return aead
}

// --- keystores that are not ------------------------------------------------

type identityKeystore struct{}

func (identityKeystore) Wrap(p []byte) ([]byte, error)   { return p, nil }
func (identityKeystore) Unwrap(s []byte) ([]byte, error) { return s, nil }

type headerKeystore struct{}

func (headerKeystore) Wrap(p []byte) ([]byte, error) {
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	return append(append([]byte("HDR1"), nonce...), p...), nil
}

func (headerKeystore) Unwrap(s []byte) ([]byte, error) {
	if len(s) < 12 {
		return nil, errors.New("short")
	}
	return s[12:], nil
}

type staticNonceKeystore struct{ aead cipher.AEAD }

func (k staticNonceKeystore) Wrap(p []byte) ([]byte, error) {
	return k.aead.Seal(nil, make([]byte, k.aead.NonceSize()), p, nil), nil
}

func (k staticNonceKeystore) Unwrap(s []byte) ([]byte, error) {
	return k.aead.Open(nil, make([]byte, k.aead.NonceSize()), s, nil)
}

type failingKeystore struct{}

func (failingKeystore) Wrap([]byte) ([]byte, error) {
	return nil, errors.New("the key was invalidated")
}
func (failingKeystore) Unwrap([]byte) ([]byte, error) {
	return nil, errors.New("the key was invalidated")
}

type emptyKeystore struct{}

func (emptyKeystore) Wrap([]byte) ([]byte, error)   { return nil, nil }
func (emptyKeystore) Unwrap([]byte) ([]byte, error) { return nil, nil }

// lossyKeystore seals properly and opens to something else — the shape of a
// keystore whose alias was reused between builds.
type lossyKeystore struct{}

func (lossyKeystore) Wrap(p []byte) ([]byte, error) {
	out := make([]byte, len(p)+16)
	_, _ = rand.Read(out)
	return out, nil
}

func (lossyKeystore) Unwrap([]byte) ([]byte, error) { return []byte("something else"), nil }

type panickingKeystore struct{}

func (panickingKeystore) Wrap([]byte) ([]byte, error)   { panic("JNI: no such method") }
func (panickingKeystore) Unwrap([]byte) ([]byte, error) { panic("JNI: no such method") }
