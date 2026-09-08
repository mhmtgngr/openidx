package migrations

import (
	"os"
	"strings"
	"testing"
)

// TestMigrationV176_dropsTheTwoUnwrittenTables pins what goes and, more
// usefully, that the rollback lands on the schema the chain describes rather
// than an approximation of it.
//
// Both tables were read on a user-facing surface and neither has ever held a
// row: api_usage_metrics backed four numbers on the Usage Analytics card, and
// risk_factors was the continuous-auth engine's detail table while the engine
// returned its factor list empty on every response.
func TestMigrationV176_dropsTheTwoUnwrittenTables(t *testing.T) {
	m := migrationByVersion(t, 176)
	if m.Name != "drop_unwritten_tables" {
		t.Errorf("v176 Name = %q, want drop_unwritten_tables", m.Name)
	}

	for _, table := range []string{"api_usage_metrics", "risk_factors"} {
		if !strings.Contains(m.UpSQL, "DROP TABLE IF EXISTS "+table) {
			t.Errorf("v176 UpSQL does not drop %s", table)
		}
		if !strings.Contains(m.DownSQL, "CREATE TABLE IF NOT EXISTS "+table) {
			t.Errorf("v176 DownSQL does not recreate %s", table)
		}
	}

	// risk_factors sat behind the v121 FORCE-RLS belt. A rollback that brings
	// the table back without its policy brings back a table any tenant can read
	// across, which is a worse schema than the one being restored.
	for _, frag := range []string{
		"CREATE POLICY pol_risk_factors_org_scope ON risk_factors",
		"ALTER TABLE risk_factors FORCE  ROW LEVEL SECURITY",
	} {
		if !strings.Contains(m.DownSQL, frag) {
			t.Errorf("v176 DownSQL missing: %q", frag)
		}
	}

	// No backfill and no data copy anywhere: there are no rows to move. If a
	// future edit adds one, the premise of the drop has changed.
	if strings.Contains(m.UpSQL, "INSERT INTO") {
		t.Error("v176 Up copies rows out of a table the census says has none")
	}
}

// The readers must go with the tables. A DROP whose reader survives is a
// migration that turns a silent zero into a 500 on the next release.
func TestV176ReadersAreGone(t *testing.T) {
	for _, tc := range []struct{ file, table, what string }{
		{"../admin/analytics_enhanced.go", "api_usage_metrics",
			"the Usage Analytics API card"},
		{"../admin/continuous_auth.go", "risk_factors",
			"the continuous-auth factor detail"},
	} {
		src, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		// The table name survives in prose explaining the removal, which is
		// wanted; what must not survive is a statement naming it.
		for _, stmt := range []string{"FROM " + tc.table, "INTO " + tc.table, "UPDATE " + tc.table} {
			if strings.Contains(string(src), stmt) {
				t.Errorf("%s: still issues %q; %s reads a table v176 drops",
					tc.file, stmt, tc.what)
			}
		}
	}
}

// The engine's factors must reach the history column v77 created for them. It
// wrote the literal "{}" there while holding the five factors it had just
// computed, so the stored history could not say why any session scored what it
// did.
func TestV176RiskHistoryStoresItsFactors(t *testing.T) {
	src, err := os.ReadFile("../admin/continuous_auth.go")
	if err != nil {
		t.Fatalf("read continuous_auth.go: %v", err)
	}
	body := string(src)
	if strings.Contains(body, `[]byte("{}"), previousRisk`) {
		t.Error("CalculateSessionRisk still stores an empty object for its factors")
	}
	if !strings.Contains(body, `"factors": risk.RiskFactors`) {
		t.Error("CalculateSessionRisk does not store the factors it measured")
	}
	// Both writers of session_risks.risk_factors must say which shape they
	// wrote, or a reader cannot tell a calculation from a score event.
	if strings.Count(body, `"source":`) < 2 {
		t.Error("the two writers of session_risks.risk_factors are not discriminated")
	}
}
