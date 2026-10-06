package secretfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// What can be proved on any platform: the round trip, the upgrade path, and the
// mode. What cannot be proved here is the Windows half — DPAPI and the file's
// DACL are Windows APIs, so those cases live in secretfile_windows_test.go and
// run only on a Windows runner. The build being green on Linux is not evidence
// about Windows, which is the whole reason the 0600 in the old code read as a
// control for as long as it did.

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-tokens.json")
	secret := []byte(`{"access_token":"at","refresh_token":"rt"}`)

	if err := Write(path, secret); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != string(secret) {
		t.Errorf("Read returned %q, want %q", got, secret)
	}
}

// TestWriteCreatesTheDirectory keeps the callers' old behaviour: authstore.Save
// used to MkdirAll itself, and a first sign-in on a fresh install must not fail
// because nothing had created the config directory yet.
func TestWriteCreatesTheDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deeper", "user-tokens.json")
	if err := Write(path, []byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not written: %v", err)
	}
}

// TestPlaintextFileStillReads is the upgrade path. An agent updated from a
// version before this package wrote a plain JSON file; refusing it would sign
// every Windows and Linux user out on upgrade, which is a worse failure than
// the one being fixed.
func TestPlaintextFileStillReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-tokens.json")
	legacy := []byte(`{"access_token":"old"}`)
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Read(path)
	if err != nil {
		t.Fatalf("Read of a pre-existing plaintext file: %v", err)
	}
	if string(got) != string(legacy) {
		t.Errorf("got %q, want %q", got, legacy)
	}
}

// TestRewriteRestoresTheMode: os.WriteFile applies its mode only when it
// CREATES the file. A token file that was once left world-readable would keep
// those bits through every later sign-in, so Write re-asserts them.
func TestRewriteRestoresTheMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not the control on Windows; see secretfile_windows_test.go")
	}
	path := filepath.Join(t.TempDir(), "user-tokens.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Write(path, []byte("new")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o after rewriting an 0644 file, want 600", perm)
	}
}

func TestRemoveIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gone.json")
	if err := Remove(path); err != nil {
		t.Errorf("removing a file that does not exist: %v", err)
	}
	if err := Write(path, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file still present: %v", err)
	}
}

// TestNoEncryptionOffWindows records the deliberate choice rather than leaving
// it to be discovered: on Linux and macOS the mode is the control, so the file
// is plain and carries no marker. A future change that starts encrypting there
// has to update this test, which is the point.
func TestNoEncryptionOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows encrypts; see secretfile_windows_test.go")
	}
	path := filepath.Join(t.TempDir(), "user-tokens.json")
	if err := Write(path, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if IsProtected(raw) {
		t.Error("the file carries the DPAPI marker on a platform with no DPAPI")
	}
	if string(raw) != `{"a":1}` {
		t.Errorf("stored %q, want the plain payload", raw)
	}
}

// TestWritePrivatePlainStoresTheBytesAsTheyAre: the desktop GUI parses
// control-endpoint.json itself and holds no key, so the file must be the
// plaintext, even with a keystore registered and even on Windows, where Write
// would seal it with DPAPI.
func TestWritePrivatePlainStoresTheBytesAsTheyAre(t *testing.T) {
	use(t, newAESKeystore(t))
	path := filepath.Join(t.TempDir(), "nested", "control-endpoint.json")
	data := []byte(`{"addr":"127.0.0.1:50000","token":"drives-the-engine"}`)

	if err := WritePrivatePlain(path, data); err != nil {
		t.Fatalf("WritePrivatePlain: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(data) {
		t.Errorf("stored %q, want the plain payload %q", raw, data)
	}
}

// TestWritePrivatePlainDoesNotReuseWhatIsAlreadyThere: a file left at the path
// keeps the permissions of whoever created it, and a symlink there would carry
// the bearer to wherever it points. Either way the secret must land in a new
// file that only its owner can read. The Windows form of this, the DACL, is in
// secretfile_windows_test.go.
func TestWritePrivatePlainDoesNotReuseWhatIsAlreadyThere(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits and symlinks are not the control on Windows; see secretfile_windows_test.go")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "control-endpoint.json")
	data := []byte(`{"token":"new"}`)

	t.Run("a world-readable file", func(t *testing.T) {
		if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := WritePrivatePlain(path, data); err != nil {
			t.Fatalf("WritePrivatePlain: %v", err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("perm = %o, want no access for group or others", perm)
		}
	})

	t.Run("a symlink", func(t *testing.T) {
		target := filepath.Join(dir, "elsewhere")
		if err := os.WriteFile(target, []byte("untouched"), 0o644); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(path)
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if err := WritePrivatePlain(path, data); err != nil {
			t.Fatalf("WritePrivatePlain: %v", err)
		}
		if got, _ := os.ReadFile(target); string(got) != "untouched" {
			t.Errorf("the write went through the symlink: target now holds %q", got)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			t.Errorf("path is %v, want a regular owner-only file", info.Mode())
		}
		if got, _ := os.ReadFile(path); string(got) != string(data) {
			t.Errorf("path holds %q, want %q", got, data)
		}
	})
}
