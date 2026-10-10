//go:build windows

package tunnel

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const defaultTimeout = 10e9 // 10 s

// TestTheHeldTunnelerCannotBeReplacedWhileHeld: while the supervisor holds
// the tunneler and wintun.dll, neither can be renamed, deleted or written, and
// the held binary still runs.
func TestTheHeldTunnelerCannotBeReplacedWhileHeld(t *testing.T) {
	t.Setenv(fakeEnv, "1")
	bin := installFake(t, t.TempDir())
	dll := filepath.Join(filepath.Dir(bin), wintunDLL)
	h, err := openBinary(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{bin, dll} {
		if err := os.Rename(p, p+".moved"); err == nil {
			t.Errorf("%s was renamed while held", p)
		}
		if err := os.Remove(p); err == nil {
			t.Errorf("%s was deleted while held", p)
		}
		if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
			f.Close()
			t.Errorf("%s was opened for writing while held", p)
		}
	}
	if v := queryVersion(context.Background(), h, defaultTimeout); v != fakeVersion {
		t.Fatalf("the held binary ran %q, want %q", v, fakeVersion)
	}
	h.close()
	if err := os.Rename(bin, bin+".moved"); err != nil {
		t.Fatalf("released binary still locked: %v", err)
	}
}

// The same file reached through another spelling (letter case here; the CI
// temp directory adds an 8.3 short name) is the held file, not a swap.
func TestTheHeldTunnelerIsMatchedByIdentityNotSpelling(t *testing.T) {
	bin := installFake(t, t.TempDir())
	for _, p := range []string{bin, strings.ToUpper(bin), strings.ToLower(bin)} {
		h, err := openBinary(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		h.close()
	}
}

// A different file at the checked path is refused.
func TestSameFileRefusesADifferentFile(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.exe")
	b := filepath.Join(dir, "b.exe")
	writeFile(t, a, "a")
	writeFile(t, b, "b")
	f, err := openLocked(a)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		t.Fatal(err)
	}
	if err := sameFile(info, b); !errors.Is(err, ErrUntrustedBinary) {
		t.Fatalf("a different file was taken for the held one: %v", err)
	}
	if err := sameFile(info, a); err != nil {
		t.Fatalf("the held file itself was refused: %v", err)
	}
}

func TestATunnelerWithoutWintunBesideItIsRefused(t *testing.T) {
	bin := installFake(t, t.TempDir())
	if err := os.Remove(filepath.Join(filepath.Dir(bin), wintunDLL)); err != nil {
		t.Fatal(err)
	}
	if _, err := openBinary(bin); !errors.Is(err, ErrUntrustedBinary) {
		t.Fatalf("a tunneler without wintun.dll beside it was opened: %v", err)
	}
}

// A file outside Program Files is refused by the production check.
func TestVerifyTrustedBinaryRefusesOutsideProgramFiles(t *testing.T) {
	bin := installFake(t, t.TempDir())
	if err := verifyTrustedBinary(bin, ""); !errors.Is(err, ErrUntrustedBinary) {
		t.Fatalf("a binary under the temp directory was accepted: %v", err)
	}
}
