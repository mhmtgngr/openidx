package mobile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/authstore"
	"github.com/openidx/openidx/agent/internal/secretfile"
	"github.com/openidx/openidx/agent/internal/sso"
)

// A host keystore, in Go, that does what the Kotlin and Swift ones do: AES-256-GCM
// with a fresh nonce per seal, over the tagged string boundary. It stands in for
// the platform keystore in every test here; what it cannot stand in for is the
// property that makes those real — that the key is held by the OS and not by
// this process — which is why scripts/check-mobile-keystore.sh reads the host
// sources rather than trusting a test.
type aesHost struct{ aead cipher.AEAD }

func newAESHost(t *testing.T) aesHost {
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
	return aesHost{aead: aead}
}

func (h aesHost) Wrap(plaintextB64 string) string {
	pt, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return "error:not base64"
	}
	nonce := make([]byte, h.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "error:" + err.Error()
	}
	return "ok:" + base64.StdEncoding.EncodeToString(h.aead.Seal(nonce, nonce, pt, nil))
}

func (h aesHost) Unwrap(sealedB64 string) string {
	blob, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		return "error:not base64"
	}
	n := h.aead.NonceSize()
	if len(blob) < n {
		return "error:short"
	}
	pt, err := h.aead.Open(nil, blob[:n], blob[n:], nil)
	if err != nil {
		return "error:" + err.Error()
	}
	return "ok:" + base64.StdEncoding.EncodeToString(pt)
}

// resetEngine drops the singleton and any registered keystore so each test
// starts from the state a freshly launched app is in.
func resetEngine(t *testing.T) {
	t.Helper()
	mu.Lock()
	engine = nil
	mu.Unlock()
	secretfile.Forget()
	t.Cleanup(func() {
		mu.Lock()
		engine = nil
		mu.Unlock()
		secretfile.Forget()
	})
}

// TestStartRefusesToRunWithoutADeviceKeystore. The whole control is that there
// is no way to start the engine and write credentials in the clear, so the
// no-keystore case is a refusal and not a warning.
func TestStartRefusesToRunWithoutADeviceKeystore(t *testing.T) {
	resetEngine(t)

	err := Start(t.TempDir(), nil)
	if err == nil {
		t.Fatal("Start succeeded with no keystore. Everything the engine writes into the app " +
			"sandbox is a credential, and a phone leaves that storage decrypted from the first " +
			"unlock after boot onwards.")
	}
	if !strings.Contains(err.Error(), "keystore") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
	if secretfile.Active() {
		t.Error("a keystore is registered after a failed Start")
	}
}

// TestStartRefusesAKeystoreThatDoesNotSeal is the important one: each of these
// compiles, each of them runs, each of them lets the app sign in, and each
// leaves the 30-day refresh token recoverable from the file. A control whose
// implementation is supplied by the caller has to check the implementation.
func TestStartRefusesAKeystoreThatDoesNotSeal(t *testing.T) {
	for _, tc := range []struct {
		name string
		host Keystore
		// why names the property SelfTest catches it on, so a failure here
		// says which check stopped working rather than only that one did.
		why string
	}{
		{"a stub that returns its argument", identityHost{}, "the plaintext comes back unchanged"},
		{"a header wrapped round the plaintext", headerHost{}, "the seal contains the secret in full"},
		{"a fixed nonce", staticNonceHost{newAESHostRaw()}, "wrapping twice gives the same bytes"},
		{"a keystore that reports failure", erroringHost{}, "Wrap answers error:"},
		{"a reply in neither shape", garbageHost{}, "the reply is not ok:/error:"},
		{"an empty reply", emptyHost{}, "the reply is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetEngine(t)

			dir := t.TempDir()
			if err := Start(dir, tc.host); err == nil {
				t.Fatalf("Start accepted a keystore where %s", tc.why)
			}
			if secretfile.Active() {
				t.Error("the keystore was registered despite failing its self-test")
			}
			if entries, err := os.ReadDir(dir); err == nil && len(entries) != 0 {
				t.Errorf("a refused Start left %d file(s) in the config directory; nothing may be "+
					"written before the keystore has proved itself", len(entries))
			}
		})
	}
}

// TestTheStoredSessionIsSealedOnDisk drives the real path: Start with a working
// keystore, save a session the way the engine does, and read the raw bytes back.
// The refresh token must not be findable in them.
func TestTheStoredSessionIsSealedOnDisk(t *testing.T) {
	resetEngine(t)

	dir := t.TempDir()
	if err := Start(dir, newAESHost(t)); err != nil {
		t.Fatalf("Start: %v", err)
	}

	const refresh = "refresh-token-that-must-not-appear-in-the-file"
	if err := authstore.Save(dir, &sso.Tokens{AccessToken: "at", RefreshToken: refresh}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "user-tokens.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(raw), refresh) {
		t.Fatalf("the refresh token is in the file in the clear")
	}
	if !secretfile.IsProtected(raw) {
		t.Fatalf("the file carries no seal marker: %q", first64(raw))
	}

	back, err := authstore.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if back == nil || back.RefreshToken != refresh {
		t.Fatalf("the sealed session did not round-trip: %+v", back)
	}
}

// TestStartResealsWhatAnEarlierBuildLeftInTheClear. The upgrade case: the file
// holding the refresh token was written before this control existed. If Start
// only protected future writes, the credential it was added for would sit in
// the clear until something happened to rewrite it.
func TestStartResealsWhatAnEarlierBuildLeftInTheClear(t *testing.T) {
	resetEngine(t)
	dir := t.TempDir()

	// Exactly what the previous build wrote: plaintext JSON, 0600, no marker.
	const refresh = "pre-upgrade-refresh-token"
	if err := authstore.Save(dir, &sso.Tokens{AccessToken: "at", RefreshToken: refresh}); err != nil {
		t.Fatalf("pre-upgrade Save: %v", err)
	}
	cfg := &agent.AgentConfig{ServerURL: "https://example.invalid", AuthToken: "agent-auth-token"}
	if err := cfg.Save(dir); err != nil {
		t.Fatalf("pre-upgrade config Save: %v", err)
	}
	for _, name := range []string{"user-tokens.json", "agent.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if secretfile.IsProtected(raw) {
			t.Fatalf("%s is already sealed before the keystore was registered; this test would "+
				"then prove nothing about the upgrade path", name)
		}
	}

	if err := Start(dir, newAESHost(t)); err != nil {
		t.Fatalf("Start: %v", err)
	}

	for _, tc := range []struct{ file, secret string }{
		{"user-tokens.json", refresh},
		{"agent.json", "agent-auth-token"},
	} {
		raw, err := os.ReadFile(filepath.Join(dir, tc.file))
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		if strings.Contains(string(raw), tc.secret) {
			t.Errorf("%s still holds its credential in the clear after Start", tc.file)
		}
		if !secretfile.IsProtected(raw) {
			t.Errorf("%s was not re-sealed on Start", tc.file)
		}
	}

	// And it is still readable, which is the half a re-seal can quietly lose.
	back, err := authstore.Load(dir)
	if err != nil || back == nil || back.RefreshToken != refresh {
		t.Fatalf("the re-sealed session did not load back: %+v, %v", back, err)
	}
	loaded, err := agent.LoadConfig(dir)
	if err != nil || loaded.AuthToken != "agent-auth-token" {
		t.Fatalf("the re-sealed agent config did not load back: %+v, %v", loaded, err)
	}
}

// TestAMalformedReplyIsNeverEchoed. reply() reports the shape of a bad answer
// and not its content, because the likeliest thing a host returns when it has
// misread the contract is the plaintext — and the engine writes its errors to
// control.log, which is in the same sandbox as the credentials.
func TestAMalformedReplyIsNeverEchoed(t *testing.T) {
	const secret = "SECRET-PLAINTEXT-VALUE"
	_, err := reply(secret, "Wrap")
	if err == nil {
		t.Fatal("a reply in neither shape was accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the error echoes the host's reply, which may be the plaintext: %v", err)
	}
}

// TestWhitespaceInTheBase64IsTolerated: Android's Base64 line-wraps unless
// NO_WRAP is passed, and that mistake must surface as a working call rather
// than as "the device keystore is broken".
func TestWhitespaceInTheBase64IsTolerated(t *testing.T) {
	want := []byte("payload")
	wrapped := "ok:" + base64.StdEncoding.EncodeToString(want)[:4] + "\n" +
		base64.StdEncoding.EncodeToString(want)[4:]

	got, err := reply(wrapped, "Wrap")
	if err != nil {
		t.Fatalf("a line-wrapped base64 payload was rejected: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func first64(b []byte) string {
	if len(b) > 64 {
		return string(b[:64])
	}
	return string(b)
}

// --- hosts that look like keystores and are not -----------------------------

type identityHost struct{}

func (identityHost) Wrap(p string) string   { return "ok:" + p }
func (identityHost) Unwrap(s string) string { return "ok:" + s }

// headerHost is the one worth having a test for. It round-trips perfectly, it
// is non-deterministic, and it leaves the secret on disk in full.
type headerHost struct{}

func (headerHost) Wrap(p string) string {
	pt, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return "error:not base64"
	}
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	return "ok:" + base64.StdEncoding.EncodeToString(append(append([]byte("HDR1"), nonce...), pt...))
}

func (headerHost) Unwrap(s string) string {
	blob, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(blob) < 12 {
		return "error:short"
	}
	return "ok:" + base64.StdEncoding.EncodeToString(blob[12:])
}

// staticNonceHost is real AES-GCM with the nonce fixed — the mistake that turns
// an AEAD into a deterministic mapping.
type staticNonceHost struct{ aead cipher.AEAD }

func newAESHostRaw() cipher.AEAD {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return aead
}

func (h staticNonceHost) Wrap(p string) string {
	pt, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return "error:not base64"
	}
	nonce := make([]byte, h.aead.NonceSize()) // all zeroes, every time
	return "ok:" + base64.StdEncoding.EncodeToString(h.aead.Seal(nil, nonce, pt, nil))
}

func (h staticNonceHost) Unwrap(s string) string {
	blob, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "error:not base64"
	}
	pt, err := h.aead.Open(nil, make([]byte, h.aead.NonceSize()), blob, nil)
	if err != nil {
		return "error:" + err.Error()
	}
	return "ok:" + base64.StdEncoding.EncodeToString(pt)
}

type erroringHost struct{}

func (erroringHost) Wrap(string) string   { return "error:the keystore key was invalidated" }
func (erroringHost) Unwrap(string) string { return "error:the keystore key was invalidated" }

type garbageHost struct{}

func (garbageHost) Wrap(p string) string   { return p }
func (garbageHost) Unwrap(s string) string { return s }

type emptyHost struct{}

func (emptyHost) Wrap(string) string   { return "" }
func (emptyHost) Unwrap(string) string { return "" }
