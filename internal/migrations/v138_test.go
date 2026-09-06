package migrations

import (
	"strings"
	"testing"
)

// TestMigrationV138_ispmAIOrgIsolation pins the contract of the ISPM + AI
// tenant-isolation migration the way TestMigrationV36/V69 pin theirs: every
// table it names must receive the full v69 sequence (org_id column, NOT NULL,
// a USING + WITH CHECK policy, ENABLE and FORCE RLS, a GRANT), the two
// install-wide unique keys must be re-scoped to the tenant, and no org_id may
// carry a DEFAULT (a rolled-back binary must fail loudly, not mis-tenant).
func TestMigrationV138_ispmAIOrgIsolation(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 138 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v138 not registered in allMigrations()")
	}
	if m.Name != "ispm_ai_org_isolation" {
		t.Errorf("v138 Name = %q, want ispm_ai_org_isolation", m.Name)
	}

	tables := []string{
		"ispm_rules", "ispm_findings", "ispm_scores",
		"ai_agents", "ai_agent_credentials", "ai_agent_permissions", "ai_agent_activity",
		"ai_recommendations", "recommendation_history",
	}
	for _, tbl := range tables {
		for _, frag := range []string{
			"ALTER TABLE " + tbl + " ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;",
			"ALTER TABLE " + tbl + " ALTER COLUMN org_id SET NOT NULL;",
			"CREATE POLICY pol_" + tbl + "_org_scope ON " + tbl,
			"ALTER TABLE " + tbl + " ENABLE ROW LEVEL SECURITY;",
			"ALTER TABLE " + tbl + " FORCE  ROW LEVEL SECURITY;",
		} {
			if !strings.Contains(m.UpSQL, frag) {
				t.Errorf("v138 UpSQL missing for %s: %q", tbl, frag)
			}
		}
		// The policy must scope writes too, not only reads.
		policy := "CREATE POLICY pol_" + tbl + "_org_scope"
		i := strings.Index(m.UpSQL, policy)
		if i >= 0 && !strings.Contains(m.UpSQL[i:i+400], "WITH CHECK") {
			t.Errorf("v138 policy for %s has no WITH CHECK clause", tbl)
		}
		if !strings.Contains(m.DownSQL, "DROP POLICY IF EXISTS pol_"+tbl+"_org_scope ON "+tbl) {
			t.Errorf("v138 DownSQL does not drop the policy on %s", tbl)
		}
		if !strings.Contains(m.DownSQL, "DROP COLUMN IF EXISTS org_id") || !strings.Contains(m.DownSQL, "ALTER TABLE "+tbl) {
			t.Errorf("v138 DownSQL does not drop org_id from %s", tbl)
		}
	}

	// Every backfill lands rows somewhere before SET NOT NULL: the oldest-org
	// fallback must appear once per table.
	if got := strings.Count(m.UpSQL, "SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL"); got != len(tables) {
		t.Errorf("v138 has %d oldest-org backfills, want one per table (%d)", got, len(tables))
	}
	// Children backfill from their parent first.
	for _, frag := range []string{
		"UPDATE ispm_findings f SET org_id = r.org_id FROM ispm_rules r WHERE f.rule_id = r.id",
		"UPDATE ai_agents a SET org_id = u.org_id FROM users u WHERE a.owner_id = u.id",
		"UPDATE ai_agent_credentials c SET org_id = a.org_id FROM ai_agents a WHERE c.agent_id = a.id",
		"UPDATE ai_agent_permissions p SET org_id = a.org_id FROM ai_agents a WHERE p.agent_id = a.id",
		"UPDATE ai_agent_activity x SET org_id = a.org_id FROM ai_agents a WHERE x.agent_id = a.id",
		"UPDATE recommendation_history h SET org_id = r.org_id FROM ai_recommendations r WHERE h.recommendation_id = r.id",
	} {
		if !strings.Contains(m.UpSQL, frag) {
			t.Errorf("v138 UpSQL missing parent backfill: %q", frag)
		}
	}

	// No DEFAULT on any org_id column (the v76 lesson).
	for _, line := range strings.Split(m.UpSQL, "\n") {
		if strings.Contains(line, "ADD COLUMN IF NOT EXISTS org_id") && strings.Contains(line, "DEFAULT") {
			t.Errorf("v138 adds org_id with a DEFAULT: %q", line)
		}
	}

	// Install-wide unique keys become per-tenant keys.
	for _, frag := range []string{
		"ALTER TABLE ispm_rules DROP CONSTRAINT IF EXISTS ispm_rules_check_type_key;",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_ispm_rules_org_check_type ON ispm_rules(org_id, check_type);",
		"ALTER TABLE ai_agents DROP CONSTRAINT IF EXISTS ai_agents_name_key;",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_agents_org_name ON ai_agents(org_id, name);",
		"DROP INDEX IF EXISTS idx_ispm_scores_date;",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_ispm_scores_org_date ON ispm_scores(org_id, snapshot_date);",
	} {
		if !strings.Contains(m.UpSQL, frag) {
			t.Errorf("v138 UpSQL missing unique-key re-scope: %q", frag)
		}
	}
	for _, frag := range []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_ispm_scores_date ON ispm_scores(snapshot_date);",
		"ALTER TABLE ai_agents ADD CONSTRAINT ai_agents_name_key UNIQUE (name);",
		"ALTER TABLE ispm_rules ADD CONSTRAINT ispm_rules_check_type_key UNIQUE (check_type);",
	} {
		if !strings.Contains(m.DownSQL, frag) {
			t.Errorf("v138 DownSQL does not restore the pre-v138 key: %q", frag)
		}
	}

	// The runtime role is granted every table in one plain statement.
	grant := "GRANT SELECT, INSERT, UPDATE, DELETE ON " + strings.Join(tables, ", ") + " TO openidx_app;"
	if !strings.Contains(m.UpSQL, grant) {
		t.Errorf("v138 UpSQL missing the openidx_app grant: %q", grant)
	}

	// splitSQL cannot run DO $$ blocks (the v56/v57 lesson).
	for _, sql := range []string{m.UpSQL, m.DownSQL} {
		if strings.Contains(sql, "DO $$") {
			t.Error("v138 uses a DO $$ block, which the runner's splitSQL cannot execute")
		}
	}
}
