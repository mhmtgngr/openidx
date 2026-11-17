package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV259AgenticSettingsShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 259 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 259 is not registered")
	}
	for _, table := range []string{"org_agentic_settings", "agentic_actions"} {
		for _, want := range []string{
			"CREATE TABLE IF NOT EXISTS " + table,
			"ALTER TABLE " + table + " FORCE  ROW LEVEL SECURITY",
			"GRANT SELECT, INSERT, UPDATE, DELETE ON " + table + " TO openidx_app",
		} {
			if !strings.Contains(mig.UpSQL, want) {
				t.Errorf("v259 up lacks %q", want)
			}
		}
		if !strings.Contains(mig.DownSQL, "DROP TABLE IF EXISTS "+table) {
			t.Errorf("v259 down does not drop %s", table)
		}
	}
	if !strings.Contains(mig.UpSQL, "CHECK (mode IN ('off', 'observe', 'tier0', 'tier1'))") {
		t.Error("v259 does not pin the mode vocabulary")
	}
	if strings.Contains(mig.UpSQL, "DO $$") {
		t.Error("v259 must not use DO $$")
	}
}
