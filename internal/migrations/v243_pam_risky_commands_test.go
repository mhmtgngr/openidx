package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV243PamRiskyCommandsShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 243 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 243 is not registered")
	}
	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS risky_command_patterns TEXT[] NOT NULL DEFAULT '{}'",
		"ADD COLUMN IF NOT EXISTS commands_scanned_at TIMESTAMPTZ",
		"ADD COLUMN IF NOT EXISTS risky_command_count INTEGER",
		"idx_pam_entry_sessions_unscanned",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v243 up lacks %q", want)
		}
	}
	for _, want := range []string{"DROP COLUMN IF EXISTS risky_command_patterns", "DROP COLUMN IF EXISTS commands_scanned_at",
		"DROP COLUMN IF EXISTS risky_command_count", "DROP INDEX IF EXISTS idx_pam_entry_sessions_unscanned"} {
		if !strings.Contains(mig.DownSQL, want) {
			t.Errorf("v243 down lacks %q", want)
		}
	}
}
