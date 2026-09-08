package authstore

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/openidx/openidx/agent/internal/secretfile"
	"github.com/openidx/openidx/agent/internal/sso"
)

// This package had no tests. It stores the user's access token and the 30-day
// refresh token behind it, and the property that matters is not the round trip
// — it is that the round trip goes THROUGH secretfile, because that is what
// applies the protection the platform enforces. A future edit that reached for
// os.WriteFile again would keep every case below green except the last one.

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := &sso.Tokens{AccessToken: "at", RefreshToken: "rt", ExpiresAt: 1234567890}

	if err := Save(dir, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil || got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken || got.ExpiresAt != want.ExpiresAt {
		t.Errorf("loaded %+v, want %+v", got, want)
	}
}

// TestLoadWithNoSessionIsNotAnError keeps the contract every caller relies on:
// Status, AccessToken and Logout all treat (nil, nil) as "not signed in".
func TestLoadWithNoSessionIsNotAnError(t *testing.T) {
	got, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load on a fresh config dir: %v", err)
	}
	if got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

func TestClearRemovesTheSession(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, &sso.Tokens{AccessToken: "at"}); err != nil {
		t.Fatal(err)
	}
	if err := Clear(dir); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if got, err := Load(dir); err != nil || got != nil {
		t.Errorf("session survived Clear: %+v (err %v)", got, err)
	}
	// Signing out twice is not an error.
	if err := Clear(dir); err != nil {
		t.Errorf("second Clear: %v", err)
	}
}

// TestSaveGoesThroughSecretfile is the wiring case. On Windows that means the
// bytes are a DPAPI blob; everywhere else it means the file is 0600 even when
// an earlier version left it wider.
func TestSaveGoesThroughSecretfile(t *testing.T) {
	dir := t.TempDir()

	// A file left behind by an older agent, world-readable.
	if err := os.WriteFile(Path(dir), []byte(`{"access_token":"old"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Save(dir, &sso.Tokens{AccessToken: "new", RefreshToken: "rt"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, err := os.ReadFile(Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if !secretfile.IsProtected(raw) {
			t.Error("the token file is not encrypted at rest on Windows")
		}
		return
	}
	info, err := os.Stat(Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600 — Save did not go through secretfile", perm)
	}
}

// TestLegacyPlaintextSessionStillLoads: an agent upgraded from before the
// secret files were protected must not sign its user out.
func TestLegacyPlaintextSessionStillLoads(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(Path(dir)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(dir), []byte(`{"access_token":"legacy","refresh_token":"old-rt"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load of a pre-upgrade session: %v", err)
	}
	if got == nil || got.AccessToken != "legacy" {
		t.Errorf("got %+v, want the legacy session", got)
	}
}
