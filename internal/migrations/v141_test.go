package migrations

import (
	"strings"
	"testing"
)

// v141Tables are the three audit tables that gain a tenant.
var v141Tables = []string{"admin_audit_log", "audit_archives", "audit_retention_policies"}

// TestMigrationV141_auditTenantScope pins the audit-scope migration the way
// TestMigrationV69/V138 pin theirs: the full column → backfill → NOT NULL →
// index → policy → ENABLE/FORCE sequence per table, in that order, with a
// rollback that actually rolls back.
func TestMigrationV141_auditTenantScope(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 141 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v141 not registered in allMigrations()")
	}
	if m.Name != "audit_tenant_scope" {
		t.Errorf("v141 Name = %q, want audit_tenant_scope", m.Name)
	}

	up, down := collapseSpaces(m.UpSQL), collapseSpaces(m.DownSQL)

	for _, tbl := range v141Tables {
		addCol := "ALTER TABLE " + tbl + " ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;"
		notNull := "ALTER TABLE " + tbl + " ALTER COLUMN org_id SET NOT NULL;"
		for _, frag := range []string{
			addCol,
			notNull,
			"CREATE POLICY pol_" + tbl + "_org_scope ON " + tbl,
			"ALTER TABLE " + tbl + " ENABLE ROW LEVEL SECURITY;",
			"ALTER TABLE " + tbl + " FORCE ROW LEVEL SECURITY;",
		} {
			if !strings.Contains(up, frag) {
				t.Errorf("v141 UpSQL missing for %s: %q", tbl, frag)
			}
		}

		// Reads and writes both, or a cross-tenant INSERT still lands.
		if i := strings.Index(up, "CREATE POLICY pol_"+tbl+"_org_scope"); i >= 0 {
			end := i + 500
			if end > len(up) {
				end = len(up)
			}
			if !strings.Contains(up[i:end], "WITH CHECK") {
				t.Errorf("v141 policy for %s has no WITH CHECK clause", tbl)
			}
		}

		// Order is the contract: adding the column, filling it, and only then
		// pinning it NOT NULL. Any other order aborts on a populated table.
		addAt, fillAt, nnAt := strings.Index(up, addCol), strings.Index(up, "UPDATE "+tbl+" "), strings.Index(up, notNull)
		if fillAt < 0 {
			// The FROM-users form: "UPDATE admin_audit_log a SET ..."
			fillAt = strings.Index(up, "UPDATE "+tbl+" a SET")
		}
		switch {
		case fillAt < 0:
			t.Errorf("v141 pins %s.org_id NOT NULL with no backfill", tbl)
		case addAt < 0 || nnAt < 0:
		case !(addAt < fillAt && fillAt < nnAt):
			t.Errorf("v141 orders %s as add=%d fill=%d notnull=%d; must be add < fill < notnull",
				tbl, addAt, fillAt, nnAt)
		}

		// Every table must reach the oldest-org fallback, or rows whose actor
		// was deleted keep a NULL org and SET NOT NULL aborts the migration.
		fallback := "UPDATE " + tbl + " SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;"
		if !strings.Contains(up, fallback) {
			t.Errorf("v141 has no oldest-org fallback for %s; a row with no actor would keep NULL and abort SET NOT NULL", tbl)
		}

		for _, frag := range []string{
			"DROP POLICY IF EXISTS pol_" + tbl + "_org_scope ON " + tbl,
			"ALTER TABLE " + tbl + " NO FORCE ROW LEVEL SECURITY;",
			"ALTER TABLE " + tbl + " DROP COLUMN IF EXISTS org_id;",
		} {
			if !strings.Contains(down, frag) {
				t.Errorf("v141 DownSQL missing for %s: %q", tbl, frag)
			}
		}
	}

	if strings.Contains(m.UpSQL, "DO $$") || strings.Contains(m.DownSQL, "DO $$") {
		t.Error("v141 uses a DO $$ block; the migration runner's splitSQL cannot execute it")
	}
	if strings.Contains(m.UpSQL, "org_id SET DEFAULT") {
		t.Error("v141 sets a DEFAULT on org_id; a rolled-back binary would mis-tenant new rows")
	}

	// The two tables that carry an actor derive the org from it rather than
	// sending every historical row to the oldest org.
	for _, pair := range [][2]string{
		{"admin_audit_log", "actor_id"},
		{"audit_archives", "created_by"},
	} {
		want := "UPDATE " + pair[0] + " a SET org_id = u.org_id FROM users u WHERE a." + pair[1] + " = u.id AND a.org_id IS NULL;"
		if !strings.Contains(up, want) {
			t.Errorf("v141 does not derive %s.org_id from %s: want %q", pair[0], pair[1], want)
		}
	}
}
