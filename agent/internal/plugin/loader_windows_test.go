//go:build windows

package plugin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

// Discover on Windows used to refuse everything, because the trust check was
// Unix mode bits and Windows discards them. It reads the DACL now
// (trust_windows.go, unit-tested in trust_windows_test.go); these two drive the
// whole loader through it, since the loader checks three paths — the root, the
// plugin's own directory, and the executable — and a check applied to only some
// of them is a check on none.
//
// windows-client-build.yml runs `go test ./...` for the whole agent module on a
// Windows runner, so these actually execute rather than being a description of
// what would happen.

// layout writes a minimal plugin under root and returns the plugin directory
// and the executable, so a test can re-permission any of the three paths.
func layout(t *testing.T, root string) (dir, exe string) {
	t.Helper()
	dir = filepath.Join(root, "hello")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	manifest, err := json.Marshal(map[string]any{
		"name":            "hello",
		"version":         "1.0.0",
		"platforms":       []string{"all"},
		"check_types":     []string{"hello_check"},
		"timeout_seconds": 5,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	exe = filepath.Join(dir, "hello.exe")
	if err := os.WriteFile(exe, []byte("MZ"), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}
	return dir, exe
}

func TestDiscoverLoadsAPluginFromAPrivilegedOnlyTree(t *testing.T) {
	root := t.TempDir()
	dir, exe := layout(t, root)
	for _, p := range []string{root, dir, exe} {
		setProtectedDACL(t, p, privileged(t)...)
	}

	plugins, err := NewLoader(root, zap.NewNop()).Discover()
	if err != nil {
		t.Fatalf("Discover refused a tree writable only by SYSTEM, Administrators and this "+
			"process: %v", err)
	}
	if len(plugins) != 1 {
		t.Fatalf("discovered %d plugins, want 1", len(plugins))
	}
}

// TestDiscoverRefusesWhicheverOfTheThreePathsIsWritable. One subtest per path,
// because "the executable is checked" and "the directory it sits in is checked"
// are different claims and only one of them stops a swap of the other.
func TestDiscoverRefusesWhicheverOfTheThreePathsIsWritable(t *testing.T) {
	users := sidOrSkip(t, windows.WinBuiltinUsersSid, "BUILTIN\\Users")

	for _, which := range []string{"the plugin root", "the plugin's directory", "the executable"} {
		t.Run(which, func(t *testing.T) {
			root := t.TempDir()
			dir, exe := layout(t, root)
			paths := map[string]string{
				"the plugin root":        root,
				"the plugin's directory": dir,
				"the executable":         exe,
			}
			for _, p := range []string{root, dir, exe} {
				g := privileged(t)
				if p == paths[which] {
					g = append(g, grant{users, windows.GENERIC_ALL})
				}
				setProtectedDACL(t, p, g...)
			}

			plugins, err := NewLoader(root, zap.NewNop()).Discover()
			if err == nil {
				t.Fatalf("Discover returned %d plugin(s) and no error with %s writable by "+
					"BUILTIN\\Users; the caller is the service running as SYSTEM", len(plugins), which)
			}
			if len(plugins) != 0 {
				t.Errorf("plugins returned alongside the refusal: %d", len(plugins))
			}
			if !strings.Contains(err.Error(), "Users") {
				t.Errorf("the refusal does not name who holds the right: %v", err)
			}
		})
	}
}

// TestDiscoverStillNoOpsOnAMissingDirectoryOnWindows: an unset or absent
// plugin_dir was never an error and must not become one — that path returns
// before the trust check, and this pins it.
func TestDiscoverStillNoOpsOnAMissingDirectoryOnWindows(t *testing.T) {
	plugins, err := NewLoader(filepath.Join(t.TempDir(), "does-not-exist"), zap.NewNop()).Discover()
	if err != nil {
		t.Errorf("a missing plugin directory is now an error on Windows: %v", err)
	}
	if len(plugins) != 0 {
		t.Errorf("discovered %d plugins in a directory that does not exist", len(plugins))
	}
}
