//go:build !windows

package tunnel

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyTrustedBinaryRefusesWritableFilesAndParents(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "lib", "openidx-agent", BinaryName())
	mkExe(t, bin)
	for _, d := range []string{filepath.Join(root, "lib"), filepath.Dir(bin)} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyTrustedBinary(bin, root); err != nil {
		t.Fatalf("a 0755 binary in 0755 directories was refused: %v", err)
	}

	cases := []struct {
		name string
		path string
		mode os.FileMode
	}{
		{"group-writable binary", bin, 0o775},
		{"world-writable binary", bin, 0o757},
		{"group-writable install dir", filepath.Dir(bin), 0o775},
		{"world-writable grandparent", filepath.Join(root, "lib"), 0o777},
		{"world-writable top", root, 0o777},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.Chmod(c.path, c.mode); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(c.path, 0o755)
			if err := verifyTrustedBinary(bin, root); !errors.Is(err, ErrUntrustedBinary) {
				t.Fatalf("err = %v, want ErrUntrustedBinary", err)
			}
		})
	}

	// A symlink is judged by what it points at.
	planted := filepath.Join(root, "planted")
	if err := os.Mkdir(planted, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(planted, 0o777); err != nil {
		t.Fatal(err)
	}
	evil := filepath.Join(planted, BinaryName())
	mkExe(t, evil)
	link := filepath.Join(filepath.Dir(bin), "link")
	if err := os.Symlink(evil, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyTrustedBinary(link, root); !errors.Is(err, ErrUntrustedBinary) {
		t.Fatalf("a symlink into a world-writable directory was accepted: %v", err)
	}
}

// The production check walks to "/" and so refuses anything under the
// sticky, world-writable temporary directory, which is where an unprivileged
// user can put a file.
func TestVerifyTrustedBinaryWalksToTheRoot(t *testing.T) {
	bin := filepath.Join(t.TempDir(), BinaryName())
	mkExe(t, bin)
	if err := verifyTrustedBinary(bin, ""); !errors.Is(err, ErrUntrustedBinary) {
		t.Fatalf("a binary under %s was accepted: %v", os.TempDir(), err)
	}
}
