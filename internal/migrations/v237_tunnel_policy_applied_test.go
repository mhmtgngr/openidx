package migrations

import (
	"strings"
	"testing"
)

// TestMigrationV237TunnelPolicyAppliedShape pins the static contract of v237:
// two columns on enrolled_agents (no new table, so no new policy), both added
// idempotently and both dropped by down.
func TestMigrationV237TunnelPolicyAppliedShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 237 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 237 is not registered")
	}
	if strings.Contains(mig.UpSQL, "CREATE TABLE") || strings.Contains(mig.UpSQL, "DO $$") {
		t.Error("v237 adds columns only, without a DO block")
	}
	for _, col := range []string{"tunnel_policy_version", "tunnel_policy_applied_at"} {
		if !strings.Contains(mig.UpSQL, "ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS "+col) {
			t.Errorf("v237 up does not add enrolled_agents.%s", col)
		}
		if !strings.Contains(mig.DownSQL, "ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS "+col) {
			t.Errorf("v237 down does not drop enrolled_agents.%s", col)
		}
	}
}
