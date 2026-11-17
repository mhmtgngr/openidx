package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV262AgenticProposalsShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 262 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 262 is not registered")
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS agentic_proposals",
		"ALTER TABLE agentic_proposals FORCE  ROW LEVEL SECURITY",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON agentic_proposals TO openidx_app",
		"CREATE UNIQUE INDEX IF NOT EXISTS uq_agentic_proposals_pending ON agentic_proposals (org_id, kind) WHERE status = 'pending'",
		"CHECK (kind IN ('rollout_pause', 'rollout_advance'))",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v262 up lacks %q", want)
		}
	}
	if !strings.Contains(mig.DownSQL, "DROP TABLE IF EXISTS agentic_proposals") || strings.Contains(mig.UpSQL, "DO $$") {
		t.Error("v262 down does not drop its table, or up uses DO $$")
	}
}
