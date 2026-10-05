//go:build !windows

package updater

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// signedServer publishes artifact under a manifest pub signed, at /latest.json.
func signedServer(t *testing.T, pub *testPublisher, artifact []byte) string {
	t.Helper()
	srv := serveManifest(t, artifact, func(u string) string {
		b, err := json.Marshal(pub.signedManifest(t, "9.9.9", u, digestOf(artifact)))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	})
	return srv.URL + "/latest.json"
}

// TestTheInstallerRunsFromThePrivateDirectoryItWasVerifiedIn: the file handed
// to apply is the one whose digest was checked, under a directory only the
// owner can write, with a random name; there is no predictable path.
func TestTheInstallerRunsFromThePrivateDirectoryItWasVerifiedIn(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	artifact := []byte("installer bytes")
	pub := publisher(t)
	manifestURL := signedServer(t, pub, artifact)

	var applied string
	orig := applyFn
	applyFn = func(path string) error { applied = path; return nil }
	t.Cleanup(func() { applyFn = orig })

	ok, v, err := CheckAndApply(context.Background(), manifestURL, "1.0.0", pub.trust())
	if err != nil || !ok || v != "9.9.9" {
		t.Fatalf("CheckAndApply: ok=%v v=%q err=%v", ok, v, err)
	}
	wantDir := filepath.Join(os.TempDir(), "openidx-updates")
	if filepath.Dir(applied) != wantDir {
		t.Fatalf("applied from %s, want a file under %s", applied, wantDir)
	}
	if strings.Contains(filepath.Base(applied), "9.9.9") {
		t.Fatalf("the file name must not be predictable from the version: %s", filepath.Base(applied))
	}
	info, err := os.Stat(wantDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("the download directory is %04o, want 0700", info.Mode().Perm())
	}
	got, err := os.ReadFile(applied)
	if err != nil || string(got) != string(artifact) {
		t.Fatalf("the applied file is not the verified artifact: %q, %v", got, err)
	}
}

// TestAnArtifactChangedAfterDownloadIsNotInstalled: the second digest check
// catches a file rewritten between the download and the install.
func TestAnArtifactChangedAfterDownloadIsNotInstalled(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	artifact := []byte("installer bytes")
	pub := publisher(t)
	manifestURL := signedServer(t, pub, artifact)

	orig := applyFn
	applyFn = func(path string) error { t.Fatalf("apply must not run on a changed artifact (%s)", path); return nil }
	t.Cleanup(func() { applyFn = orig })
	origVerify := verifyHook
	verifyHook = func(path string) { _ = os.WriteFile(path, []byte("replaced"), 0o600) }
	t.Cleanup(func() { verifyHook = origVerify })

	_, _, err := CheckAndApply(context.Background(), manifestURL, "1.0.0", pub.trust())
	if err == nil || !strings.Contains(err.Error(), "changed between download and install") {
		t.Fatalf("want the re-check to refuse, got %v", err)
	}
}

// TestADownloadDirectoryWritableByOthersIsRefused: a pre-existing directory
// that others can write is made private again (owner) rather than refused;
// what is refused is one whose mode the chmod cannot fix, which on Unix does
// not arise for the owner. This pins the mode after privateDir.
func TestADownloadDirectoryWritableByOthersIsMadePrivate(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	dir := filepath.Join(os.TempDir(), "openidx-updates")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	got, err := privateDir()
	if err != nil {
		t.Fatalf("privateDir: %v", err)
	}
	info, _ := os.Stat(got)
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("mode %04o after privateDir, want 0700", info.Mode().Perm())
	}
}
