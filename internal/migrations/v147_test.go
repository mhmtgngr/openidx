package migrations

import (
	"strings"
	"testing"
)

var v147Tables = []string{
	"breach_incidents",
	"breach_alerts",
}

func TestMigrationV147_breachResponseTenantScope(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 147 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v147 not registered in allMigrations()")
	}
	if m.Name != "breach_response_tenant_scope" {
		t.Errorf("v147 Name = %q, want breach_response_tenant_scope", m.Name)
	}

	up, down := collapseSpaces(m.UpSQL), collapseSpaces(m.DownSQL)

	for _, tbl := range v147Tables {
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
				t.Errorf("v147 UpSQL missing for %s: %q", tbl, frag)
			}
		}

		if i := strings.Index(up, "CREATE POLICY pol_"+tbl+"_org_scope"); i >= 0 {
			end := i + 500
			if end > len(up) {
				end = len(up)
			}
			if !strings.Contains(up[i:end], "WITH CHECK") {
				t.Errorf("v147 policy for %s has no WITH CHECK clause", tbl)
			}
		}

		fillAt := strings.Index(up, "UPDATE "+tbl+" ")
		addAt, nnAt := strings.Index(up, addCol), strings.Index(up, notNull)
		switch {
		case fillAt < 0:
			t.Errorf("v147 pins %s.org_id NOT NULL with no backfill", tbl)
		case addAt < 0 || nnAt < 0:
		case !(addAt < fillAt && fillAt < nnAt):
			t.Errorf("v147 orders %s as add=%d fill=%d notnull=%d; must be add < fill < notnull",
				tbl, addAt, fillAt, nnAt)
		}

		fallback := "UPDATE " + tbl + " SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;"
		if !strings.Contains(up, fallback) {
			t.Errorf("v147 has no oldest-org fallback for %s; an incident whose affected users have "+
				"since been deleted attributes to nothing, and one unattributed row aborts SET NOT "+
				"NULL for the whole install: want %q", tbl, fallback)
		}

		for _, frag := range []string{
			"DROP POLICY IF EXISTS pol_" + tbl + "_org_scope ON " + tbl,
			"ALTER TABLE " + tbl + " NO FORCE ROW LEVEL SECURITY;",
			"ALTER TABLE " + tbl + " DROP COLUMN IF EXISTS org_id;",
		} {
			if !strings.Contains(down, frag) {
				t.Errorf("v147 DownSQL missing for %s: %q", tbl, frag)
			}
		}
	}

	// THE BACKFILL HAS AN ORDER DEPENDENCY, and getting it wrong is silent.
	//
	// Neither of these tables hangs off a user the way the last four batches'
	// did. An incident names its users in affected_user_ids, a TEXT[] of
	// users.id values, so the first element attributes the row. An alert has
	// its own user_id, but the better attribution is its incident's — an alert
	// whose user has been deleted still belongs to the tenant whose incident
	// raised it.
	//
	// Which means breach_alerts must be filled AFTER breach_incidents is
	// COMPLETE, fallback included. Fill it earlier and every alert whose
	// incident had not yet been attributed inherits NULL, falls through to its
	// own user_id, and — for an alert with no user, which is every alert raised
	// on an incident with an empty affected_user_ids — lands in the oldest
	// organization instead of the tenant that owns its incident. Nothing fails;
	// the rows are just filed under the wrong tenant, permanently, because the
	// down migration cannot reconstruct the attribution.
	incidentFallbackAt := strings.Index(up,
		"UPDATE breach_incidents SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;")
	alertFromIncidentAt := strings.Index(up, "UPDATE breach_alerts a SET org_id = i.org_id FROM breach_incidents i")
	switch {
	case incidentFallbackAt < 0:
		t.Error("v147 has no oldest-org fallback for breach_incidents")
	case alertFromIncidentAt < 0:
		t.Error("v147 does not attribute breach_alerts through their incident; an alert whose user " +
			"has been deleted would fall through to the oldest organization even though the incident " +
			"that raised it names its tenant")
	case alertFromIncidentAt < incidentFallbackAt:
		t.Errorf("v147 fills breach_alerts.org_id (at %d) before breach_incidents is complete (its "+
			"fallback is at %d). Every alert whose incident is still NULL at that point inherits "+
			"NULL and gets mis-filed, silently and irreversibly", alertFromIncidentAt, incidentFallbackAt)
	}

	// The incident backfill reads affected_user_ids[1], not a user_id column:
	// there is no user_id column on breach_incidents. A later batch copying the
	// v145/v146 join by rote has to fail here rather than produce an UpSQL that
	// errors on a table nobody in CI has rows in.
	if !strings.Contains(up, "i.affected_user_ids[1]") {
		t.Error("v147 does not attribute breach_incidents through affected_user_ids[1]; that array " +
			"is the only thing on the row naming a user, and there is no user_id column to join on")
	}

	if strings.Contains(m.UpSQL, "DO $$") || strings.Contains(m.DownSQL, "DO $$") {
		t.Error("v147 uses a DO $$ block; the migration runner's splitSQL cannot execute it")
	}
	if strings.Contains(m.UpSQL, "org_id SET DEFAULT") {
		t.Error("v147 sets a DEFAULT on org_id; a rolled-back binary would mis-tenant new rows")
	}
}
