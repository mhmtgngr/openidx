package migrations

import (
	"strings"
	"testing"
)

// TestMigrationV142_unifiedAuditOrgScope pins the unified-audit scope migration
// the way V69/V138/V141 pin theirs: column → backfill → NOT NULL → index →
// policy → ENABLE/FORCE, in that order, with a rollback that rolls back.
//
// The backfill order carries extra weight here. Three passes narrow from most
// to least specific, and each is guarded by `org_id IS NULL`, so a later pass
// can only claim rows an earlier one could not attribute. Reverse two of them
// and every Ziti sync row that happens to name a user gets the route's org
// instead of the user's — silently, on a table nobody reconciles by hand.
func TestMigrationV142_unifiedAuditOrgScope(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 142 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v142 not registered in allMigrations()")
	}
	if m.Name != "unified_audit_org_scope" {
		t.Errorf("v142 Name = %q, want unified_audit_org_scope", m.Name)
	}

	const tbl = "unified_audit_events"
	up, down := collapseSpaces(m.UpSQL), collapseSpaces(m.DownSQL)

	addCol := "ALTER TABLE " + tbl + " ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;"
	notNull := "ALTER TABLE " + tbl + " ALTER COLUMN org_id SET NOT NULL;"
	for _, frag := range []string{
		addCol,
		notNull,
		"CREATE INDEX IF NOT EXISTS idx_unified_audit_org ON " + tbl + "(org_id, created_at DESC);",
		"CREATE POLICY pol_" + tbl + "_org_scope ON " + tbl,
		"ALTER TABLE " + tbl + " ENABLE ROW LEVEL SECURITY;",
		"ALTER TABLE " + tbl + " FORCE ROW LEVEL SECURITY;",
	} {
		if !strings.Contains(up, frag) {
			t.Errorf("v142 UpSQL missing: %q", frag)
		}
	}

	// Reads and writes both. Without WITH CHECK a writer that names another
	// tenant still lands its row, which on an audit table is worse than a
	// cross-tenant read: it is a forged record.
	if i := strings.Index(up, "CREATE POLICY pol_"+tbl+"_org_scope"); i >= 0 {
		end := i + 500
		if end > len(up) {
			end = len(up)
		}
		if !strings.Contains(up[i:end], "WITH CHECK") {
			t.Error("v142 policy has no WITH CHECK clause")
		}
	}

	// The three backfill passes, in order, narrowing from most specific to
	// least. Each is guarded by org_id IS NULL so it only claims what the
	// previous pass left.
	byUser := "UPDATE " + tbl + " e SET org_id = u.org_id FROM users u WHERE e.user_id = u.id AND e.org_id IS NULL;"
	byRoute := "UPDATE " + tbl + " e SET org_id = r.org_id FROM proxy_routes r WHERE e.route_id = r.id AND e.org_id IS NULL;"
	fallback := "UPDATE " + tbl + " SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;"
	for _, frag := range []string{byUser, byRoute, fallback} {
		if !strings.Contains(up, frag) {
			t.Errorf("v142 UpSQL missing backfill pass: %q", frag)
		}
	}
	userAt, routeAt, fallbackAt := strings.Index(up, byUser), strings.Index(up, byRoute), strings.Index(up, fallback)
	if userAt >= 0 && routeAt >= 0 && fallbackAt >= 0 {
		if !(userAt < routeAt && routeAt < fallbackAt) {
			t.Errorf("v142 backfill runs user=%d route=%d fallback=%d; must narrow user < route < fallback",
				userAt, routeAt, fallbackAt)
		}
	}

	// Order is the contract: add the column, fill it, and only then pin it
	// NOT NULL. Any other order aborts on a populated table -- and this is the
	// busiest table in the product, so it is never empty on a real install.
	addAt, nnAt := strings.Index(up, addCol), strings.Index(up, notNull)
	switch {
	case addAt < 0 || nnAt < 0:
	case !(addAt < userAt && fallbackAt < nnAt):
		t.Errorf("v142 orders add=%d fill=%d..%d notnull=%d; must be add < fill < notnull",
			addAt, userAt, fallbackAt, nnAt)
	}

	for _, frag := range []string{
		"DROP POLICY IF EXISTS pol_" + tbl + "_org_scope ON " + tbl,
		"ALTER TABLE " + tbl + " NO FORCE ROW LEVEL SECURITY;",
		"ALTER TABLE " + tbl + " DROP COLUMN IF EXISTS org_id;",
	} {
		if !strings.Contains(down, frag) {
			t.Errorf("v142 DownSQL missing: %q", frag)
		}
	}

	if strings.Contains(m.UpSQL, "DO $$") || strings.Contains(m.DownSQL, "DO $$") {
		t.Error("v142 uses a DO $$ block; the migration runner's splitSQL cannot execute it")
	}
	if strings.Contains(m.UpSQL, "org_id SET DEFAULT") {
		t.Error("v142 sets a DEFAULT on org_id; a rolled-back binary would mis-tenant new rows")
	}
}
