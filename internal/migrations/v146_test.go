package migrations

import (
	"strings"
	"testing"
)

var v146Tables = []string{
	"mfa_sms",
	"mfa_email_otp",
	"mfa_phone_call",
	"mfa_otp_challenges",
}

func TestMigrationV146_mfaFactorTenantScope(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 146 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v146 not registered in allMigrations()")
	}
	if m.Name != "mfa_factor_tenant_scope" {
		t.Errorf("v146 Name = %q, want mfa_factor_tenant_scope", m.Name)
	}

	up, down := collapseSpaces(m.UpSQL), collapseSpaces(m.DownSQL)

	for _, tbl := range v146Tables {
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
				t.Errorf("v146 UpSQL missing for %s: %q", tbl, frag)
			}
		}

		if i := strings.Index(up, "CREATE POLICY pol_"+tbl+"_org_scope"); i >= 0 {
			end := i + 500
			if end > len(up) {
				end = len(up)
			}
			if !strings.Contains(up[i:end], "WITH CHECK") {
				t.Errorf("v146 policy for %s has no WITH CHECK clause", tbl)
			}
		}

		// Every one of these tables hangs off a user, so the backfill derives
		// from users and never needs anything cleverer.
		derive := "UPDATE " + tbl + " "
		addAt, nnAt, fillAt := strings.Index(up, addCol), strings.Index(up, notNull), strings.Index(up, derive)
		switch {
		case fillAt < 0:
			t.Errorf("v146 pins %s.org_id NOT NULL with no backfill", tbl)
		case addAt < 0 || nnAt < 0:
		case !(addAt < fillAt && fillAt < nnAt):
			t.Errorf("v146 orders %s as add=%d fill=%d notnull=%d; must be add < fill < notnull",
				tbl, addAt, fillAt, nnAt)
		}

		fallback := "UPDATE " + tbl + " SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;"
		if !strings.Contains(up, fallback) {
			t.Errorf("v146 has no oldest-org fallback for %s; mfa_phone_call's user_id is nullable "+
				"and a single unattributed row aborts SET NOT NULL: want %q", tbl, fallback)
		}

		for _, frag := range []string{
			"DROP POLICY IF EXISTS pol_" + tbl + "_org_scope ON " + tbl,
			"ALTER TABLE " + tbl + " NO FORCE ROW LEVEL SECURITY;",
			"ALTER TABLE " + tbl + " DROP COLUMN IF EXISTS org_id;",
		} {
			if !strings.Contains(down, frag) {
				t.Errorf("v146 DownSQL missing for %s: %q", tbl, frag)
			}
		}
	}

	// THE POINT OF THIS TEST, and the third case in the taxonomy.
	//
	// v143 RE-SCOPED social_providers.provider_key, because an install-wide key
	// let the first tenant to register 'google' take the name from everybody
	// else. v144 KEPT saml_service_providers.entity_id, because that key is
	// what resolves the tenant on an inbound request. Here the answer is "keep"
	// again but for a third reason, and the reason matters more than the
	// verdict: user_id already DETERMINES org_id, so UNIQUE(user_id) and
	// UNIQUE(org_id, user_id) accept exactly the same rows — except that the
	// second also permits one user to hold two enrolments in two
	// organizations, which is not a tenancy feature but a corrupt row.
	//
	// Re-scoping a unique key is not a step in this programme's recipe. A later
	// batch applying v143's pattern by rote has to fail here first.
	for _, tbl := range []string{"mfa_sms", "mfa_email_otp", "mfa_phone_call"} {
		for _, forbidden := range []string{
			"DROP CONSTRAINT IF EXISTS " + tbl + "_user_id_key",
			"ON " + tbl + "(org_id, user_id)",
		} {
			if strings.Contains(up, forbidden) {
				t.Errorf("v146 re-scopes %s's UNIQUE(user_id) (%q). It must stay as it is: user_id "+
					"already determines org_id, so a per-org key accepts strictly more rows and the "+
					"extra rows it accepts are one user enrolled in two organizations", tbl, forbidden)
			}
		}
	}

	if strings.Contains(m.UpSQL, "DO $$") || strings.Contains(m.DownSQL, "DO $$") {
		t.Error("v146 uses a DO $$ block; the migration runner's splitSQL cannot execute it")
	}
	if strings.Contains(m.UpSQL, "org_id SET DEFAULT") {
		t.Error("v146 sets a DEFAULT on org_id; a rolled-back binary would mis-tenant new rows")
	}
}
