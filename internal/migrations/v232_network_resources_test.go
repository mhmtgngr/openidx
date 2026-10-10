package migrations

import (
	"strings"
	"testing"
)

// TestMigrationV232NetworkResourcesShape pins the static contract of v232:
// both new tables are org-scoped under a FORCE'd belt whose policy names
// app.org_id and nothing else (migration 231 took the app.bypass_rls clause
// out of every policy; a new one must not bring it back), and down drops
// everything up added.
func TestMigrationV232NetworkResourcesShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 232 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 232 is not registered")
	}
	up := mig.UpSQL
	if strings.Contains(up, "bypass_rls") {
		t.Error("v232 policies mention app.bypass_rls; bypass is a role since v231")
	}
	for _, table := range []string{"network_targets", "org_network_policy"} {
		for _, want := range []string{
			"CREATE TABLE IF NOT EXISTS " + table,
			"ALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY",
			"ALTER TABLE " + table + " FORCE  ROW LEVEL SECURITY",
			"CREATE POLICY pol_" + table + "_org_scope ON " + table,
			"GRANT SELECT, INSERT, UPDATE, DELETE ON " + table + " TO openidx_app",
		} {
			if !strings.Contains(up, want) {
				t.Errorf("v232 up is missing %q", want)
			}
		}
		if !strings.Contains(mig.DownSQL, "DROP TABLE IF EXISTS "+table) {
			t.Errorf("v232 down does not drop %s", table)
		}
	}
	for _, col := range []string{"tunnel_status", "tunnel_last_seen"} {
		if !strings.Contains(up, "ADD COLUMN IF NOT EXISTS "+col) {
			t.Errorf("v232 up does not add enrolled_agents.%s", col)
		}
		if !strings.Contains(mig.DownSQL, "DROP COLUMN IF EXISTS "+col) {
			t.Errorf("v232 down does not drop enrolled_agents.%s", col)
		}
	}
}
