package migrations

import (
	"strings"
	"testing"
)

var v145Tables = []string{
	"hardware_tokens",
	"hardware_token_events",
	"mfa_bypass_codes",
	"mfa_bypass_audit",
	"magic_links",
}

func TestMigrationV145_credentialTenantScope(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 145 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v145 not registered in allMigrations()")
	}
	if m.Name != "credential_tenant_scope" {
		t.Errorf("v145 Name = %q, want credential_tenant_scope", m.Name)
	}

	up, down := collapseSpaces(m.UpSQL), collapseSpaces(m.DownSQL)

	for _, tbl := range v145Tables {
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
				t.Errorf("v145 UpSQL missing for %s: %q", tbl, frag)
			}
		}

		if i := strings.Index(up, "CREATE POLICY pol_"+tbl+"_org_scope"); i >= 0 {
			end := i + 500
			if end > len(up) {
				end = len(up)
			}
			if !strings.Contains(up[i:end], "WITH CHECK") {
				t.Errorf("v145 policy for %s has no WITH CHECK clause", tbl)
			}
		}

		addAt, nnAt := strings.Index(up, addCol), strings.Index(up, notNull)
		fillAt := strings.Index(up, "UPDATE "+tbl+" ")
		switch {
		case fillAt < 0:
			t.Errorf("v145 pins %s.org_id NOT NULL with no backfill", tbl)
		case addAt < 0 || nnAt < 0:
		case !(addAt < fillAt && fillAt < nnAt):
			t.Errorf("v145 orders %s as add=%d fill=%d notnull=%d; must be add < fill < notnull",
				tbl, addAt, fillAt, nnAt)
		}

		for _, frag := range []string{
			"DROP POLICY IF EXISTS pol_" + tbl + "_org_scope ON " + tbl,
			"ALTER TABLE " + tbl + " NO FORCE ROW LEVEL SECURITY;",
			"ALTER TABLE " + tbl + " DROP COLUMN IF EXISTS org_id;",
		} {
			if !strings.Contains(down, frag) {
				t.Errorf("v145 DownSQL missing for %s: %q", tbl, frag)
			}
		}
	}

	// Every table gets the oldest-org fallback, because every one of them has a
	// nullable owner: mfa_bypass_codes.user_id and hardware_tokens.assigned_to
	// both are, and a single NULL left behind aborts SET NOT NULL and takes the
	// whole migration with it.
	for _, tbl := range v145Tables {
		want := "UPDATE " + tbl + " SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;"
		if !strings.Contains(up, want) {
			t.Errorf("v145 has no oldest-org fallback for %s, whose owner column is nullable; "+
				"one unattributed row would abort SET NOT NULL: want %q", tbl, want)
		}
	}

	// The two derived tables must be filled AFTER the table they derive from,
	// or they inherit a column that is still NULL and fall through to the
	// oldest org for rows whose parent knew the answer.
	for _, c := range []struct{ child, parent, derive string }{
		{"hardware_token_events", "hardware_tokens",
			"UPDATE hardware_token_events e SET org_id = t.org_id FROM hardware_tokens t WHERE e.token_id = t.id AND e.org_id IS NULL;"},
		{"mfa_bypass_audit", "mfa_bypass_codes",
			"UPDATE mfa_bypass_audit a SET org_id = c.org_id FROM mfa_bypass_codes c WHERE a.bypass_code_id = c.id AND a.org_id IS NULL;"},
	} {
		at := strings.Index(up, c.derive)
		if at < 0 {
			t.Errorf("v145 does not derive %s.org_id from %s: want %q", c.child, c.parent, c.derive)
			continue
		}
		parentNotNull := strings.Index(up, "ALTER TABLE "+c.parent+" ALTER COLUMN org_id SET NOT NULL;")
		if parentNotNull < 0 || parentNotNull > at {
			t.Errorf("v145 fills %s from %s at %d, before %s is complete at %d; "+
				"the parent column is still NULL there and every child row falls through to the oldest org",
				c.child, c.parent, at, c.parent, parentNotNull)
		}
	}

	// THE POINT OF THIS TEST, and the mirror image of v144's.
	//
	// v144 asserts that saml_service_providers.entity_id must NOT be re-scoped,
	// because the entity id is what resolves the tenant on an inbound request.
	// hardware_tokens.serial_number is the other case, and the two together are
	// the rule: an install-wide unique key is a bug unless the key is the thing
	// that resolves the tenant. A serial resolves nothing — verification finds
	// a token through assigned_to — so keeping it install-wide bought no
	// correctness and cost two real things: the first tenant to register a
	// serial vetoed every other tenant (v143's provider_key shape), and
	// "already exists" answered a question about hardware somebody else owns.
	//
	// So this migration MUST re-scope it, and a later batch that "restores" the
	// install-wide constraint by analogy with v144 has to fail here first.
	for _, required := range []string{
		"ALTER TABLE hardware_tokens DROP CONSTRAINT IF EXISTS hardware_tokens_serial_number_key;",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_hardware_tokens_org_serial ON hardware_tokens(org_id, serial_number);",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("v145 leaves serial_number UNIQUE install-wide (%q missing). A hardware serial "+
				"resolves no tenant, so unlike v144's entity_id the install-wide key only hands the "+
				"first registrant a veto and answers existence questions about another tenant's hardware",
				required)
		}
	}
	// The rollback has to put the constraint back, or a binary rolled back to
	// v144 runs against a schema that no longer enforces what it assumes.
	if !strings.Contains(down, "ALTER TABLE hardware_tokens ADD CONSTRAINT hardware_tokens_serial_number_key UNIQUE (serial_number);") {
		t.Error("v145 DownSQL does not restore serial_number's install-wide UNIQUE; " +
			"a rolled-back binary would run without the constraint it was written against")
	}

	if strings.Contains(m.UpSQL, "DO $$") || strings.Contains(m.DownSQL, "DO $$") {
		t.Error("v145 uses a DO $$ block; the migration runner's splitSQL cannot execute it")
	}
	if strings.Contains(m.UpSQL, "org_id SET DEFAULT") {
		t.Error("v145 sets a DEFAULT on org_id; a rolled-back binary would mis-tenant new rows")
	}
}
