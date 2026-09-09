package control

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/authstore"
	"github.com/openidx/openidx/agent/internal/secretfile"
	"github.com/openidx/openidx/agent/internal/sso"
)

// TestASessionSealedByAnotherKeyAsksForSignIn.
//
// The device keystore that seals the stored session can stop being able to open
// it: an OEM keystore reset, a key whose alias was regenerated, a config
// directory restored beside a Keychain that did not come with it. The bytes are
// still on disk and mean nothing.
//
// What must NOT happen is the app showing a decryption error, because there is
// nothing the user can do with one. A stored session that cannot be opened IS
// an absent session, and saying so sends them to the login screen, which is the
// action that fixes it — the next sign-in overwrites the file.
//
// This drives the real path (AccessToken) rather than the helper, because the
// two loaders that report this are the ones the app calls.
func TestASessionSealedByAnotherKeyAsksForSignIn(t *testing.T) {
	dir := t.TempDir()

	// Seal a session with one key...
	if err := secretfile.Use(testKeystore(t)); err != nil {
		t.Fatalf("Use: %v", err)
	}
	err := authstore.Save(dir, &sso.Tokens{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	secretfile.Forget()

	// ...and open the engine with another. Same file, different key.
	if err := secretfile.Use(testKeystore(t)); err != nil {
		t.Fatalf("Use: %v", err)
	}
	t.Cleanup(secretfile.Forget)

	e, err := NewEngine(dir, zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := e.SetServer("https://openidx.invalid"); err != nil {
		t.Fatalf("SetServer: %v", err)
	}

	if _, err := e.AccessToken(); !errors.Is(err, errNotAuthenticated) {
		t.Fatalf("AccessToken reported %v.\n\nA stored session that cannot be opened must read as "+
			"\"not authenticated\", so the app sends the user to sign in. Anything else is an "+
			"error they cannot act on, on a device whose session is gone.", err)
	}
}

// testKeystore returns a fresh AES-256-GCM keystore. Each call generates its own
// key, which is what makes the test above a test: the second one cannot open
// what the first sealed.
func testKeystore(t *testing.T) secretfile.Keystore {
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
	return gcmKeystore{aead}
}

type gcmKeystore struct{ aead cipher.AEAD }

func (k gcmKeystore) Wrap(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return k.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (k gcmKeystore) Unwrap(sealed []byte) ([]byte, error) {
	n := k.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("short")
	}
	return k.aead.Open(nil, sealed[:n], sealed[n:], nil)
}
