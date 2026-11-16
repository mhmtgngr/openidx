package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV257AgentDiagnosticsShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 257 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 257 is not registered")
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS agent_diagnostics",
		"org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE",
		"octet_length(bundle::text) <= 131072",
		"INTERVAL '30 days'",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON agent_diagnostics TO openidx_app",
		"pol_agent_diagnostics_org_scope",
		"FORCE  ROW LEVEL SECURITY",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v257 up lacks %q", want)
		}
	}
	if !strings.Contains(mig.DownSQL, "DROP TABLE IF EXISTS agent_diagnostics") {
		t.Error("v257 down does not drop the table")
	}
}
