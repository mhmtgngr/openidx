//go:build !windows

package plugin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// Discover() hands what it finds to exec.CommandContext, and both callers of
// LoadPlugins are daemons — `openidx-agent serve`, and on Windows the service,
// which runs as SYSTEM. Until now nothing asked who else could write the file
// about to be run.
//
// These cases are about refusal at each of the three places a swap happens: the
// plugin root, the plugin's own directory, and the executable. The negative
// matters too — a check that refuses a correctly-installed plugin is one that
// gets removed.

// writePlugin lays down a plugin the loader would otherwise accept: a directory
// with a manifest and a matching executable.
func writePlugin(t *testing.T, root, name string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	manifest := map[string]any{
		"name":            name,
		"version":         "1.0.0",
		"platforms":       []string{"all"},
		"check_types":     []string{name + "_check"},
		"timeout_seconds": 5,
	}
	b, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	exe := filepath.Join(dir, name)
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}
	return dir
}

func discover(t *testing.T, root string) ([]*PluginCheck, error) {
	t.Helper()
	return NewLoader(root, zap.NewNop()).Discover()
}

func TestDiscoverAcceptsACorrectlyInstalledPlugin(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	writePlugin(t, root, "hello")

	got, err := discover(t, root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("discovered %d plugins, want 1 — the check must not refuse a normal install", len(got))
	}
}

func TestDiscoverRefusesAWorldWritableRoot(t *testing.T) {
	root := t.TempDir()
	writePlugin(t, root, "hello")
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatalf("chmod root: %v", err)
	}

	got, err := discover(t, root)
	if err == nil {
		t.Fatalf("Discover accepted a world-writable plugin root and returned %d plugin(s); "+
			"anyone who can write that directory chooses what this daemon executes", len(got))
	}
	if !strings.Contains(err.Error(), "plugin directory rejected") {
		t.Errorf("error does not name the root as the problem: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("plugins were returned alongside the refusal: %d", len(got))
	}
}

func TestDiscoverSkipsAWorldWritablePluginDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	good := writePlugin(t, root, "good")
	bad := writePlugin(t, root, "bad")
	if err := os.Chmod(bad, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_ = good

	got, err := discover(t, root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	// One bad plugin must not cost the operator the good ones, and must not be
	// loaded either.
	if len(got) != 1 {
		t.Fatalf("discovered %d plugins, want only the well-permissioned one", len(got))
	}
	if !strings.HasPrefix(got[0].Name(), "good") {
		t.Errorf("the plugin that loaded is %q; the world-writable one was accepted", got[0].Name())
	}
}

func TestDiscoverSkipsAWorldWritableExecutable(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	dir := writePlugin(t, root, "hello")
	// A tight directory with a replaceable binary in it is the same hole one
	// level down: the attacker does not need to create a file, only to rewrite
	// one.
	if err := os.Chmod(filepath.Join(dir, "hello"), 0o777); err != nil {
		t.Fatalf("chmod exe: %v", err)
	}

	got, err := discover(t, root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("a world-writable executable was registered as a check: %d plugin(s)", len(got))
	}
}

func TestDiscoverRefusesAGroupWritablePath(t *testing.T) {
	// Group-writable is the one people argue about, and it is the same answer:
	// the group is not the operator, and membership changes without anyone
	// revisiting this directory.
	root := t.TempDir()
	writePlugin(t, root, "hello")
	if err := os.Chmod(root, 0o775); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	if _, err := discover(t, root); err == nil {
		t.Error("Discover accepted a group-writable plugin root")
	}
}

func TestTrustErrorNamesWhoCanWrite(t *testing.T) {
	// The message has to say what to fix. An octal mode alone makes the reader
	// decode it, and a control people cannot act on gets switched off.
	dir := t.TempDir()
	for _, tc := range []struct {
		mode os.FileMode
		want string
	}{
		{0o777, "the group and everyone"},
		{0o775, "the group"},
		{0o757, "everyone"},
	} {
		if err := os.Chmod(dir, tc.mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		err := requireTrustedPath(dir)
		if err == nil {
			t.Fatalf("mode %04o accepted", tc.mode)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("mode %04o: message %q does not name %q", tc.mode, err, tc.want)
		}
	}
}

func TestDiscoverStillNoOpsOnAMissingDirectory(t *testing.T) {
	// The pre-existing contract: an unset or absent plugin_dir is not an error.
	// The new check must not turn "no plugins" into a startup failure.
	got, err := discover(t, filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Errorf("a missing plugin directory is now an error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("discovered %d plugins in a directory that does not exist", len(got))
	}
}
