package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV251OrgAgentSettingsShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 251 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 251 is not registered")
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS org_agent_settings",
		"org_id     UUID PRIMARY KEY",
		"claim_mode IN ('login', 'logged_on_user')",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON org_agent_settings TO openidx_app",
		"FORCE  ROW LEVEL SECURITY",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v251 up lacks %q", want)
		}
	}
	if !strings.Contains(mig.DownSQL, "DROP TABLE IF EXISTS org_agent_settings") {
		t.Error("v251 down does not drop the table")
	}
}
