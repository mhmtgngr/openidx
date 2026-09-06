package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV148_tempAccessTenantScope(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 148 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v148 not registered in allMigrations()")
	}
	if m.Name != "temp_access_tenant_scope" {
		t.Errorf("v148 Name = %q, want temp_access_tenant_scope", m.Name)
	}

	up, down := collapseSpaces(m.UpSQL), collapseSpaces(m.DownSQL)

	// Both tables get the belt.
	for _, tbl := range []string{"temp_access_links", "temp_access_usage"} {
		for _, frag := range []string{
			"CREATE POLICY pol_" + tbl + "_org_scope ON " + tbl,
			"ALTER TABLE " + tbl + " ENABLE ROW LEVEL SECURITY;",
			"ALTER TABLE " + tbl + " FORCE ROW LEVEL SECURITY;",
		} {
			if !strings.Contains(up, frag) {
				t.Errorf("v148 UpSQL missing for %s: %q", tbl, frag)
			}
		}
		if i := strings.Index(up, "CREATE POLICY pol_"+tbl+"_org_scope"); i >= 0 {
			end := i + 500
			if end > len(up) {
				end = len(up)
			}
			if !strings.Contains(up[i:end], "WITH CHECK") {
				t.Errorf("v148 policy for %s has no WITH CHECK clause", tbl)
			}
		}
		for _, frag := range []string{
			"DROP POLICY IF EXISTS pol_" + tbl + "_org_scope ON " + tbl,
			"ALTER TABLE " + tbl + " NO FORCE ROW LEVEL SECURITY;",
		} {
			if !strings.Contains(down, frag) {
				t.Errorf("v148 DownSQL missing for %s: %q", tbl, frag)
			}
		}
	}

	// Only the usage table gains a column; its backfill runs before NOT NULL.
	addCol := "ALTER TABLE temp_access_usage ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;"
	notNull := "ALTER TABLE temp_access_usage ALTER COLUMN org_id SET NOT NULL;"
	fill := "UPDATE temp_access_usage u SET org_id = l.org_id FROM temp_access_links l"
	addAt, nnAt, fillAt := strings.Index(up, addCol), strings.Index(up, notNull), strings.Index(up, fill)
	switch {
	case addAt < 0:
		t.Errorf("v148 does not add temp_access_usage.org_id: want %q", addCol)
	case fillAt < 0:
		t.Errorf("v148 does not attribute usage rows through their link: want %q", fill)
	case nnAt < 0:
		t.Errorf("v148 leaves temp_access_usage.org_id nullable: want %q", notNull)
	case !(addAt < fillAt && fillAt < nnAt):
		t.Errorf("v148 orders temp_access_usage as add=%d fill=%d notnull=%d; must be add < fill < notnull",
			addAt, fillAt, nnAt)
	}
	if !strings.Contains(up, "UPDATE temp_access_usage SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;") {
		t.Error("v148 has no oldest-org fallback for temp_access_usage; one unattributed row aborts " +
			"SET NOT NULL for the whole install, and the fallback costs nothing")
	}

	// THE POINT OF THIS TEST.
	//
	// temp_access_links.org_id is v71's, not v148's. v148 only adds the belt to
	// that table. A down migration that dropped the column would silently undo
	// v71's IDOR fix — the handlers would still name org_id in their predicates
	// and every management query would error, or worse, someone would "fix" that
	// by removing the predicates. The rollback must leave the column alone.
	if strings.Contains(up, "ALTER TABLE temp_access_links ADD COLUMN") {
		t.Error("v148 adds a column to temp_access_links; v71 already added org_id there and " +
			"this migration's job on that table is the belt alone")
	}
	if strings.Contains(down, "ALTER TABLE temp_access_links DROP COLUMN") {
		t.Error("v148's rollback drops temp_access_links.org_id. That column belongs to v71, which " +
			"added it to close a cross-tenant IDOR; rolling back v148 must remove only v148's belt, " +
			"never v71's tenant column")
	}

	if strings.Contains(m.UpSQL, "DO $$") || strings.Contains(m.DownSQL, "DO $$") {
		t.Error("v148 uses a DO $$ block; the migration runner's splitSQL cannot execute it")
	}
	if strings.Contains(m.UpSQL, "org_id SET DEFAULT") {
		t.Error("v148 sets a DEFAULT on org_id; a rolled-back binary would mis-tenant new rows")
	}
}
