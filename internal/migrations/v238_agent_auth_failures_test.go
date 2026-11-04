package migrations

import (
	"strings"
	"testing"
)

// TestMigrationV238AgentAuthFailuresShape pins the static contract of v238:
// two columns on enrolled_agents (no new table, so no new policy), both added
// idempotently and both dropped by down.
func TestMigrationV238AgentAuthFailuresShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 238 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 238 is not registered")
	}
	if strings.Contains(mig.UpSQL, "CREATE TABLE") || strings.Contains(mig.UpSQL, "DO $$") {
		t.Error("v238 adds columns only, without a DO block")
	}
	for _, col := range []string{"auth_failed_at", "auth_fail_count"} {
		if !strings.Contains(mig.UpSQL, "ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS "+col) {
			t.Errorf("v238 up does not add enrolled_agents.%s", col)
		}
		if !strings.Contains(mig.DownSQL, "ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS "+col) {
			t.Errorf("v238 down does not drop enrolled_agents.%s", col)
		}
	}
}
