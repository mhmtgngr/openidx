package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPickUnixConfigDirReadsTheLegacyPathOnlyWhenItAloneIsEnrolled(t *testing.T) {
	root := t.TempDir()
	cur, old := filepath.Join(root, "var"), filepath.Join(root, "etc")
	_ = os.MkdirAll(cur, 0o700)
	_ = os.MkdirAll(old, 0o700)
	if got := pickUnixConfigDir(cur, old); got != cur {
		t.Fatalf("fresh install: got %s", got)
	}
	_ = os.WriteFile(filepath.Join(old, "agent.json"), []byte("{}"), 0o600)
	if got := pickUnixConfigDir(cur, old); got != old {
		t.Fatalf("legacy-only: got %s", got)
	}
	_ = os.WriteFile(filepath.Join(cur, "agent.json"), []byte("{}"), 0o600)
	if got := pickUnixConfigDir(cur, old); got != cur {
		t.Fatalf("migrated: got %s", got)
	}
}
