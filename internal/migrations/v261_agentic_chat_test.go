package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV261AgenticChatShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 261 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 261 is not registered")
	}
	for _, table := range []string{"agentic_sessions", "agentic_messages"} {
		for _, want := range []string{
			"CREATE TABLE IF NOT EXISTS " + table,
			"ALTER TABLE " + table + " FORCE  ROW LEVEL SECURITY",
			"GRANT SELECT, INSERT, UPDATE, DELETE ON " + table + " TO openidx_app",
		} {
			if !strings.Contains(mig.UpSQL, want) {
				t.Errorf("v261 up lacks %q", want)
			}
		}
		if !strings.Contains(mig.DownSQL, "DROP TABLE IF EXISTS "+table) {
			t.Errorf("v261 down does not drop %s", table)
		}
	}
	if !strings.Contains(mig.UpSQL, "GRANT USAGE, SELECT ON SEQUENCE agentic_messages_id_seq TO openidx_app") {
		t.Error("v261 does not grant the sequence the app inserts through")
	}
	if strings.Contains(mig.UpSQL, "DO $$") {
		t.Error("v261 must not use DO $$")
	}
}
