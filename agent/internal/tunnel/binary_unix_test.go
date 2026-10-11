//go:build !windows

package tunnel

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const defaultTimeout = 10e9 // 10 s

// The file that runs is the file that was checked: swapping the path after
// the check does not change what the held binary executes (Linux executes
// through the descriptor), and the supervisor sees the swap.
func TestASwapAfterTheCheckDoesNotChangeWhatRuns(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only Linux executes through the descriptor")
	}
	t.Setenv(fakeEnv, "1")
	bin := installFake(t, t.TempDir())
	h, err := openBinary(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()

	if err := os.Rename(bin, bin+".orig"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho swapped\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if v := queryVersion(context.Background(), h, defaultTimeout); v != fakeVersion {
		t.Fatalf("after the swap the held binary ran %q, want the checked file's %q", v, fakeVersion)
	}
	if h.stillCurrent() {
		t.Fatal("the swap was not noticed")
	}
}

func TestOpenBinaryRefusesALinkAndAWritableFile(t *testing.T) {
	dir := t.TempDir()
	bin := installFake(t, dir)

	link := filepath.Join(dir, "link")
	if err := os.Symlink(bin, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openBinary(link); !errors.Is(err, ErrUntrustedBinary) {
		t.Fatalf("a symlink was opened (O_NOFOLLOW): %v", err)
	}

	if err := os.Chmod(bin, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := openBinary(bin); !errors.Is(err, ErrUntrustedBinary) {
		t.Fatalf("a group-writable binary was opened: %v", err)
	}
	if err := os.Chmod(bin, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openBinary(bin); !errors.Is(err, ErrUntrustedBinary) {
		t.Fatalf("a non-executable file was opened: %v", err)
	}
}
