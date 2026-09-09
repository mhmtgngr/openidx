//go:build windows

package plugin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// On Windows, Discover refuses. That is a decision rather than an oversight —
// the trust check is Unix mode bits, Windows discards them, and the caller here
// is the service running as SYSTEM — so it needs a test that fails if someone
// quietly removes the refusal, and one that fails if the refusal swallows the
// pre-existing "an absent plugin_dir is not an error" contract.
//
// windows-client-build.yml runs `go test ./...` for the whole agent module on a
// Windows runner, so these actually execute rather than being a description of
// what would happen.

func TestDiscoverRefusesOnWindows(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "hello")
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
	if err := os.WriteFile(filepath.Join(dir, "hello.exe"), []byte("MZ"), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}

	plugins, err := NewLoader(root, zap.NewNop()).Discover()
	if err == nil {
		t.Fatalf("Discover returned %d plugin(s) and no error on Windows; the permission "+
			"check that would make executing them safe is not implemented here, and the "+
			"caller is the SYSTEM service", len(plugins))
	}
	if len(plugins) != 0 {
		t.Errorf("plugins returned alongside the refusal: %d", len(plugins))
	}
	// The message has to name the reason, or the next person reads it as a bug
	// and deletes the check.
	if !strings.Contains(err.Error(), "DACL") {
		t.Errorf("the refusal does not say what is missing: %v", err)
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
