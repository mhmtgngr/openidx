package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV150_remoteSupportSessionScope(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 150 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v150 not registered in allMigrations()")
	}
	if m.Name != "remote_support_session_scope" {
		t.Errorf("v150 Name = %q, want remote_support_session_scope", m.Name)
	}

	up, down := collapseSpaces(m.UpSQL), collapseSpaces(m.DownSQL)
	const tbl = "remote_support_sessions"

	for _, frag := range []string{
		"CREATE POLICY pol_" + tbl + "_org_scope ON " + tbl,
		"ALTER TABLE " + tbl + " ENABLE ROW LEVEL SECURITY;",
		"ALTER TABLE " + tbl + " FORCE ROW LEVEL SECURITY;",
	} {
		if !strings.Contains(up, frag) {
			t.Errorf("v150 UpSQL missing: %q", frag)
		}
	}
	if i := strings.Index(up, "CREATE POLICY pol_"+tbl+"_org_scope"); i >= 0 {
		end := i + 500
		if end > len(up) {
			end = len(up)
		}
		if !strings.Contains(up[i:end], "WITH CHECK") {
			t.Error("v150 policy has no WITH CHECK clause")
		}
	}

	// THE POINT OF THIS TEST.
	//
	// org_id is v92's column and it is NULLABLE. Belting a nullable tenant
	// column does not scope the NULL rows, it HIDES them — and for this table
	// that means the administrator who started a session cannot list it, end it
	// or revoke its recording while the session keeps running out of the
	// broker's memory. So the backfill and the NOT NULL must both land, and
	// both must land BEFORE the policy. A later edit that reorders them, or
	// drops the NOT NULL because "the column already existed", puts the hazard
	// straight back.
	notNull := "ALTER TABLE " + tbl + " ALTER COLUMN org_id SET NOT NULL;"
	fill := "UPDATE " + tbl + " s SET org_id = u.org_id FROM users u"
	policy := "CREATE POLICY pol_" + tbl + "_org_scope"
	fillAt, nnAt, polAt := strings.Index(up, fill), strings.Index(up, notNull), strings.Index(up, policy)
	switch {
	case fillAt < 0:
		t.Errorf("v150 does not attribute sessions through their admin: want %q", fill)
	case nnAt < 0:
		t.Errorf("v150 leaves %s.org_id nullable. The belt would hide those rows rather than "+
			"scope them: want %q", tbl, notNull)
	case polAt < 0:
	case !(fillAt < nnAt && nnAt < polAt):
		t.Errorf("v150 orders fill=%d notnull=%d policy=%d; the backfill and the NOT NULL must "+
			"both come BEFORE the policy, or the first belted read hides every unattributed session",
			fillAt, nnAt, polAt)
	}

	if !strings.Contains(up, "UPDATE "+tbl+" SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;") {
		t.Error("v150 has no oldest-org fallback; a session started before v92, or by an admin " +
			"since deleted, would abort SET NOT NULL for the whole install")
	}

	// The column belongs to v92. Rolling v150 back must lift the NOT NULL, not
	// drop the column — dropping it would take v92's tenant attribution with it
	// and leave every handler predicate referencing a column that is gone.
	if strings.Contains(down, "DROP COLUMN IF EXISTS org_id") {
		t.Error("v150's rollback drops remote_support_sessions.org_id. That column is v92's; " +
			"the rollback must only lift the NOT NULL this migration added")
	}
	if !strings.Contains(down, "ALTER TABLE "+tbl+" ALTER COLUMN org_id DROP NOT NULL;") {
		t.Error("v150's rollback leaves org_id NOT NULL, so a rolled-back binary that writes a " +
			"NULL-org session would fail the insert instead of degrading to v92's behaviour")
	}
	for _, frag := range []string{
		"DROP POLICY IF EXISTS pol_" + tbl + "_org_scope ON " + tbl,
		"ALTER TABLE " + tbl + " NO FORCE ROW LEVEL SECURITY;",
	} {
		if !strings.Contains(down, frag) {
			t.Errorf("v150 DownSQL missing: %q", frag)
		}
	}

	if strings.Contains(m.UpSQL, "DO $$") || strings.Contains(m.DownSQL, "DO $$") {
		t.Error("v150 uses a DO $$ block; the migration runner's splitSQL cannot execute it")
	}
	if strings.Contains(m.UpSQL, "org_id SET DEFAULT") {
		t.Error("v150 sets a DEFAULT on org_id; a rolled-back binary would mis-tenant new rows")
	}
}
