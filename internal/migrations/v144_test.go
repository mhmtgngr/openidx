package migrations

import (
	"strings"
	"testing"
)

var v144Tables = []string{"saml_service_providers", "saml_sessions"}

func TestMigrationV144_samlTenantScope(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 144 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v144 not registered in allMigrations()")
	}
	if m.Name != "saml_tenant_scope" {
		t.Errorf("v144 Name = %q, want saml_tenant_scope", m.Name)
	}

	up, down := collapseSpaces(m.UpSQL), collapseSpaces(m.DownSQL)

	for _, tbl := range v144Tables {
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
				t.Errorf("v144 UpSQL missing for %s: %q", tbl, frag)
			}
		}

		if i := strings.Index(up, "CREATE POLICY pol_"+tbl+"_org_scope"); i >= 0 {
			end := i + 500
			if end > len(up) {
				end = len(up)
			}
			if !strings.Contains(up[i:end], "WITH CHECK") {
				t.Errorf("v144 policy for %s has no WITH CHECK clause", tbl)
			}
		}

		addAt, nnAt := strings.Index(up, addCol), strings.Index(up, notNull)
		fillAt := strings.Index(up, "UPDATE "+tbl+" ")
		switch {
		case fillAt < 0:
			t.Errorf("v144 pins %s.org_id NOT NULL with no backfill", tbl)
		case addAt < 0 || nnAt < 0:
		case !(addAt < fillAt && fillAt < nnAt):
			t.Errorf("v144 orders %s as add=%d fill=%d notnull=%d; must be add < fill < notnull",
				tbl, addAt, fillAt, nnAt)
		}

		for _, frag := range []string{
			"DROP POLICY IF EXISTS pol_" + tbl + "_org_scope ON " + tbl,
			"ALTER TABLE " + tbl + " NO FORCE ROW LEVEL SECURITY;",
			"ALTER TABLE " + tbl + " DROP COLUMN IF EXISTS org_id;",
		} {
			if !strings.Contains(down, frag) {
				t.Errorf("v144 DownSQL missing for %s: %q", tbl, frag)
			}
		}
	}

	// Sessions hang off a user; service providers hang off nothing, so they get
	// the oldest-org fallback and an operator re-files them.
	wantSess := "UPDATE saml_sessions s SET org_id = u.org_id FROM users u WHERE s.user_id = u.id AND s.org_id IS NULL;"
	if !strings.Contains(up, wantSess) {
		t.Errorf("v144 does not derive saml_sessions.org_id from its user: want %q", wantSess)
	}
	wantSP := "UPDATE saml_service_providers SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;"
	if !strings.Contains(up, wantSP) {
		t.Errorf("v144 has no oldest-org fallback for saml_service_providers, which has no owner column; "+
			"every existing row would keep NULL and abort SET NOT NULL: want %q", wantSP)
	}

	// THE POINT OF THIS TEST. v143 re-scoped social_providers.provider_key to
	// (org_id, provider_key) because an install-wide key let the first tenant to
	// register 'google' take the name from everybody else. Doing the same to
	// entity_id would break SAML: the id is a globally unique URI by
	// specification, and it is the key that resolves the tenant on an incoming
	// AuthnRequest -- make it per-org and that lookup becomes ambiguous.
	//
	// So this migration must NOT touch the constraint, and a later batch
	// applying the v143 pattern mechanically has to fail here first.
	for _, forbidden := range []string{
		"DROP CONSTRAINT IF EXISTS saml_service_providers_entity_id_key",
		"ON saml_service_providers(org_id, entity_id)",
	} {
		if strings.Contains(up, forbidden) {
			t.Errorf("v144 re-scopes entity_id (%q). It must stay UNIQUE install-wide: a SAML "+
				"entity id is a globally unique URI and is what resolves the tenant on an "+
				"incoming request, so a per-org key makes that lookup ambiguous", forbidden)
		}
	}

	if strings.Contains(m.UpSQL, "DO $$") || strings.Contains(m.DownSQL, "DO $$") {
		t.Error("v144 uses a DO $$ block; the migration runner's splitSQL cannot execute it")
	}
	if strings.Contains(m.UpSQL, "org_id SET DEFAULT") {
		t.Error("v144 sets a DEFAULT on org_id; a rolled-back binary would mis-tenant new rows")
	}
}
