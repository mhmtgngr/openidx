package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV241PamEntryRecordingSealShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 241 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 241 is not registered")
	}
	for _, col := range []string{"recording_sealed_at TIMESTAMPTZ", "recording_sha256 TEXT", "recording_key_id SMALLINT", "recording_purged_at TIMESTAMPTZ"} {
		if !strings.Contains(mig.UpSQL, "ALTER TABLE pam_entry_sessions ADD COLUMN IF NOT EXISTS "+col) {
			t.Errorf("v241 up does not add %s", col)
		}
		name := strings.Fields(col)[0]
		if !strings.Contains(mig.DownSQL, "DROP COLUMN IF EXISTS "+name) {
			t.Errorf("v241 down does not drop %s", name)
		}
	}
	if strings.Contains(mig.UpSQL, "UPDATE ") || strings.Contains(mig.UpSQL, "CREATE TABLE") {
		t.Error("v241 adds nullable columns and an index only")
	}
}
