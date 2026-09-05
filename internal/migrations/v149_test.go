package migrations

import (
	"strings"
	"testing"
)

var v149Holds = []struct {
	table, parent string
}{
	{"recording_legal_holds", "remote_support_sessions"},
	{"guacamole_recording_legal_holds", "guacamole_sessions"},
}

func TestMigrationV149_legalHoldTenantScope(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 149 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v149 not registered in allMigrations()")
	}
	if m.Name != "legal_hold_tenant_scope" {
		t.Errorf("v149 Name = %q, want legal_hold_tenant_scope", m.Name)
	}

	up, down := collapseSpaces(m.UpSQL), collapseSpaces(m.DownSQL)

	for _, h := range v149Holds {
		tbl := h.table
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
				t.Errorf("v149 UpSQL missing for %s: %q", tbl, frag)
			}
		}

		if i := strings.Index(up, "CREATE POLICY pol_"+tbl+"_org_scope"); i >= 0 {
			end := i + 500
			if end > len(up) {
				end = len(up)
			}
			if !strings.Contains(up[i:end], "WITH CHECK") {
				t.Errorf("v149 policy for %s has no WITH CHECK clause", tbl)
			}
		}

		// A hold is attributed through the session it protects, not through a
		// user: neither table has a user column that determines the tenant.
		fill := "UPDATE " + tbl + " h SET org_id = s.org_id FROM " + h.parent + " s"
		addAt, nnAt, fillAt := strings.Index(up, addCol), strings.Index(up, notNull), strings.Index(up, fill)
		switch {
		case fillAt < 0:
			t.Errorf("v149 does not attribute %s through %s: want %q", tbl, h.parent, fill)
		case addAt < 0 || nnAt < 0:
		case !(addAt < fillAt && fillAt < nnAt):
			t.Errorf("v149 orders %s as add=%d fill=%d notnull=%d; must be add < fill < notnull",
				tbl, addAt, fillAt, nnAt)
		}

		fallback := "UPDATE " + tbl + " SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;"
		if !strings.Contains(up, fallback) {
			t.Errorf("v149 has no oldest-org fallback for %s. Both session tables allow a NULL "+
				"org_id on old rows — the retention sweeps COALESCE it — so this one is load-bearing, "+
				"not a formality: want %q", tbl, fallback)
		}

		for _, frag := range []string{
			"DROP POLICY IF EXISTS pol_" + tbl + "_org_scope ON " + tbl,
			"ALTER TABLE " + tbl + " NO FORCE ROW LEVEL SECURITY;",
			"ALTER TABLE " + tbl + " DROP COLUMN IF EXISTS org_id;",
		} {
			if !strings.Contains(down, frag) {
				t.Errorf("v149 DownSQL missing for %s: %q", tbl, frag)
			}
		}
	}

	// THE ACTIVE-HOLD UNIQUE INDEX STAYS AS IT IS — the fourth appearance of
	// the taxonomy v143/v144/v146 built, and the same answer v146 gave.
	//
	// Both migrations created a partial unique index over session_id WHERE
	// released_at IS NULL, so a session can carry at most one active hold.
	// session_id already DETERMINES org_id, so a per-org key accepts strictly
	// more rows, and the extra rows it accepts are two active holds on one
	// session — which is not a tenancy feature but a corrupt state: the release
	// endpoint would clear one and leave the recording still held, or the sweep
	// would see a hold nobody can find in the console.
	for _, h := range v149Holds {
		for _, forbidden := range []string{
			"DROP INDEX IF EXISTS uq_" + h.table + "_active",
			"(org_id, session_id) WHERE released_at IS NULL",
		} {
			if strings.Contains(up, forbidden) {
				t.Errorf("v149 re-scopes %s's active-hold unique index (%q). It must stay keyed on "+
					"session_id alone: session_id already determines org_id, so a per-org key would "+
					"permit two active holds on one session", h.table, forbidden)
			}
		}
	}

	if strings.Contains(m.UpSQL, "DO $$") || strings.Contains(m.DownSQL, "DO $$") {
		t.Error("v149 uses a DO $$ block; the migration runner's splitSQL cannot execute it")
	}
	if strings.Contains(m.UpSQL, "org_id SET DEFAULT") {
		t.Error("v149 sets a DEFAULT on org_id; a rolled-back binary would mis-tenant new rows")
	}
}
