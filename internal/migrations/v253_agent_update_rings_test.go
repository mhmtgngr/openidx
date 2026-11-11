package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV253AgentUpdateRingsShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 253 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 253 is not registered")
	}
	for _, want := range []string{
		"enrolled_agents ADD COLUMN IF NOT EXISTS agent_version",
		"enrolled_agents ADD COLUMN IF NOT EXISTS update_state  JSONB",
		"update_channel IN ('stable', 'beta')",
		"update_rollout_percent BETWEEN 0 AND 100",
		"update_paused BOOLEAN NOT NULL DEFAULT false",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v253 up lacks %q", want)
		}
	}
	for _, want := range []string{"DROP COLUMN IF EXISTS agent_version", "DROP COLUMN IF EXISTS update_paused"} {
		if !strings.Contains(mig.DownSQL, want) {
			t.Errorf("v253 down lacks %q", want)
		}
	}
}
