package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV263AccessPlansShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 263 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 263 is not registered")
	}
	for _, want := range []string{
		"CHECK (kind IN ('rollout_pause', 'rollout_advance', 'access_open'))",
		"'superseded', 'undone'",
		"ADD COLUMN IF NOT EXISTS outcome JSONB",
		"ON agentic_proposals (org_id, kind, target_id) WHERE status = 'pending'",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v263 up lacks %q", want)
		}
	}
	if !strings.Contains(mig.DownSQL, "DELETE FROM agentic_proposals WHERE kind = 'access_open'") || strings.Contains(mig.UpSQL, "DO $$") {
		t.Error("v263 down does not remove what the old checks refuse, or up uses DO $$")
	}
}
