package migrations

import (
	"strings"
	"testing"
)

// v143Tables are the five sign-in tables that gain a tenant.
var v143Tables = []string{
	"social_providers",
	"trusted_browsers",
	"passwordless_preferences",
	"user_risk_baselines",
	"phone_call_challenges",
}

// v143NullableOwner are the tables whose owning column is nullable, so the
// oldest-org fallback is not optional: without it a row with no owner keeps a
// NULL org and SET NOT NULL aborts the whole migration on a populated install.
var v143NullableOwner = []string{
	"social_providers",         // provider_id became nullable in v127
	"passwordless_preferences", // user_id is nullable
	"phone_call_challenges",    // user_id is nullable
}

func TestMigrationV143_signinTenantScope(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 143 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v143 not registered in allMigrations()")
	}
	if m.Name != "signin_tenant_scope" {
		t.Errorf("v143 Name = %q, want signin_tenant_scope", m.Name)
	}

	up, down := collapseSpaces(m.UpSQL), collapseSpaces(m.DownSQL)

	for _, tbl := range v143Tables {
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
				t.Errorf("v143 UpSQL missing for %s: %q", tbl, frag)
			}
		}

		// Reads and writes both, or a cross-tenant INSERT still lands.
		if i := strings.Index(up, "CREATE POLICY pol_"+tbl+"_org_scope"); i >= 0 {
			end := i + 500
			if end > len(up) {
				end = len(up)
			}
			if !strings.Contains(up[i:end], "WITH CHECK") {
				t.Errorf("v143 policy for %s has no WITH CHECK clause", tbl)
			}
		}

		// Order is the contract: add the column, fill it, and only then pin it
		// NOT NULL. Any other order aborts on a populated table.
		addAt, nnAt := strings.Index(up, addCol), strings.Index(up, notNull)
		fillAt := strings.Index(up, "UPDATE "+tbl+" ")
		switch {
		case fillAt < 0:
			t.Errorf("v143 pins %s.org_id NOT NULL with no backfill", tbl)
		case addAt < 0 || nnAt < 0:
		case !(addAt < fillAt && fillAt < nnAt):
			t.Errorf("v143 orders %s as add=%d fill=%d notnull=%d; must be add < fill < notnull",
				tbl, addAt, fillAt, nnAt)
		}

		for _, frag := range []string{
			"DROP POLICY IF EXISTS pol_" + tbl + "_org_scope ON " + tbl,
			"ALTER TABLE " + tbl + " NO FORCE ROW LEVEL SECURITY;",
			"ALTER TABLE " + tbl + " DROP COLUMN IF EXISTS org_id;",
		} {
			if !strings.Contains(down, frag) {
				t.Errorf("v143 DownSQL missing for %s: %q", tbl, frag)
			}
		}
	}

	// The four tables that hang off a user derive the org from it rather than
	// sending every row to the oldest org.
	for _, pair := range [][3]string{
		{"trusted_browsers", "t", "user_id"},
		{"passwordless_preferences", "p", "user_id"},
		{"user_risk_baselines", "b", "user_id"},
		{"phone_call_challenges", "c", "user_id"},
	} {
		want := "UPDATE " + pair[0] + " " + pair[1] + " SET org_id = u.org_id FROM users u WHERE " +
			pair[1] + "." + pair[2] + " = u.id AND " + pair[1] + ".org_id IS NULL;"
		if !strings.Contains(up, want) {
			t.Errorf("v143 does not derive %s.org_id from its user: want %q", pair[0], want)
		}
	}
	// social_providers hangs off the identity provider it decorates, not a user.
	wantSP := "UPDATE social_providers sp SET org_id = ip.org_id FROM identity_providers ip WHERE sp.provider_id = ip.id AND sp.org_id IS NULL;"
	if !strings.Contains(up, wantSP) {
		t.Errorf("v143 does not derive social_providers.org_id from its identity provider: want %q", wantSP)
	}

	// Every table whose owning column is nullable MUST reach the fallback, or
	// SET NOT NULL aborts on the first ownerless row.
	for _, tbl := range v143NullableOwner {
		fallback := "UPDATE " + tbl + " SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;"
		if !strings.Contains(up, fallback) {
			t.Errorf("v143 has no oldest-org fallback for %s, whose owner column is nullable; "+
				"an ownerless row would keep NULL and abort SET NOT NULL", tbl)
		}
	}

	// provider_key was UNIQUE across the whole install: the first tenant to
	// register 'google' took it from everybody else. Re-scoping it is the point,
	// and the rollback has to put the old constraint back or a rolled-back
	// binary runs against a schema it was not written for.
	for _, frag := range []string{
		"ALTER TABLE social_providers DROP CONSTRAINT IF EXISTS social_providers_provider_key_key;",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_social_providers_org_key ON social_providers(org_id, provider_key);",
	} {
		if !strings.Contains(up, frag) {
			t.Errorf("v143 UpSQL missing provider_key re-scope: %q", frag)
		}
	}
	if !strings.Contains(down, "ALTER TABLE social_providers ADD CONSTRAINT social_providers_provider_key_key UNIQUE (provider_key);") {
		t.Error("v143 DownSQL does not restore the install-wide provider_key uniqueness it dropped")
	}

	if strings.Contains(m.UpSQL, "DO $$") || strings.Contains(m.DownSQL, "DO $$") {
		t.Error("v143 uses a DO $$ block; the migration runner's splitSQL cannot execute it")
	}
	if strings.Contains(m.UpSQL, "org_id SET DEFAULT") {
		t.Error("v143 sets a DEFAULT on org_id; a rolled-back binary would mis-tenant new rows")
	}
}
