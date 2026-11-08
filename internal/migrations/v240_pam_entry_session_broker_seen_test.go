package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV240PamEntrySessionBrokerSeenShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 240 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 240 is not registered")
	}
	if !strings.Contains(mig.UpSQL, "ALTER TABLE pam_entry_sessions ADD COLUMN IF NOT EXISTS broker_last_seen_at TIMESTAMPTZ") {
		t.Error("v240 up does not add broker_last_seen_at")
	}
	if strings.Contains(mig.UpSQL, "CREATE TABLE") || strings.Contains(mig.UpSQL, "UPDATE ") {
		t.Error("v240 adds one nullable column and rewrites nothing")
	}
	if !strings.Contains(mig.DownSQL, "DROP COLUMN IF EXISTS broker_last_seen_at") {
		t.Error("v240 down does not drop the column")
	}
}
