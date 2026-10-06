package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/openidx/openidx/agent/internal/plugin"
)

// TestPluginDigestPrintsExactlyWhatTheLoaderVerifies. A publisher signs this
// command's output with their own tooling, and the loader verifies against
// plugin.SigningInput. Any byte this command adds or changes, a trailing
// newline included, would make every signature made from it fail to verify.
//
// The cases run in this order on purpose: cobra keeps flag state on the
// package-level command between executions, so the case without --dir has to
// run before any case sets it.
func TestPluginDigestPrintsExactlyWhatTheLoaderVerifies(t *testing.T) {
	run := func(args ...string) (string, error) {
		var out, errOut bytes.Buffer
		rootCmd.SetArgs(args)
		rootCmd.SetOut(&out)
		rootCmd.SetErr(&errOut)
		defer func() {
			rootCmd.SetArgs(nil)
			rootCmd.SetOut(nil)
			rootCmd.SetErr(nil)
		}()
		err := rootCmd.Execute()
		return out.String(), err
	}

	if _, err := run("plugin", "digest"); err == nil || !strings.Contains(err.Error(), "dir") {
		t.Fatalf("plugin digest without --dir did not ask for it: %v", err)
	}

	if _, err := run("plugin", "digest", "--dir", t.TempDir()); err == nil {
		t.Fatal("plugin digest printed a signing input for a folder with no manifest.json")
	}

	dir := filepath.Join(t.TempDir(), "hello")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"name":"hello","version":"1.0.0","platforms":["all"],"check_types":["hello_check"]}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := "hello"
	if runtime.GOOS == "windows" {
		exe = "hello.exe"
	}
	if err := os.WriteFile(filepath.Join(dir, exe), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := run("plugin", "digest", "--dir", dir)
	if err != nil {
		t.Fatalf("plugin digest: %v", err)
	}
	want, err := plugin.SigningInput(dir)
	if err != nil {
		t.Fatalf("SigningInput: %v", err)
	}
	if got != string(want) {
		t.Fatalf("plugin digest printed\n%q\nbut the loader verifies\n%q", got, want)
	}
	if !strings.HasPrefix(got, "openidx-agent-plugin/v1\n") {
		t.Errorf("the output does not begin with the plugin signing domain: %q", got)
	}
}
