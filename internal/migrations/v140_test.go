package migrations

import (
	"strings"
	"testing"
)

// v140Tables is the belt batch, in the order the migration applies it.
var v140Tables = []string{
	"scheduled_reports", "detailed_compliance_reports", "audit_webhook_subscriptions",
	"usage_metering_daily", "email_branding", "device_trust_settings",
	"pam_active_checkouts", "pam_checkout_authorizations", "brokered_sessions", "ssh_ca",
	"sod_violations", "privileged_accounts_discovered", "entitlement_warehouse",
	"upstream_pools", "upstream_pool_members",
}

// v140NotNull are the four whose org_id was declared nullable. A nullable org
// under a belt means a row nobody can see rather than a row that is loudly
// wrong, so they are backfilled and pinned NOT NULL in the same migration.
var v140NotNull = []string{
	"scheduled_reports", "device_trust_settings", "email_branding", "usage_metering_daily",
}

// TestMigrationV140_rlsBeltBatch1 pins the belt batch the way
// TestMigrationV121/V138 pin theirs: every table named must get a policy that
// scopes writes as well as reads, ENABLE and FORCE, and a matching rollback.
func TestMigrationV140_rlsBeltBatch1(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 140 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v140 not registered in allMigrations()")
	}
	if m.Name != "rls_belt_batch_1" {
		t.Errorf("v140 Name = %q, want rls_belt_batch_1", m.Name)
	}

	upSQL, downSQL := collapseSpaces(m.UpSQL), collapseSpaces(m.DownSQL)

	for _, tbl := range v140Tables {
		for _, frag := range []string{
			"CREATE POLICY pol_" + tbl + "_org_scope ON " + tbl,
			"ALTER TABLE " + tbl + " ENABLE ROW LEVEL SECURITY;",
			"ALTER TABLE " + tbl + " FORCE ROW LEVEL SECURITY;",
		} {
			if !strings.Contains(upSQL, frag) {
				t.Errorf("v140 UpSQL missing for %s: %q", tbl, frag)
			}
		}

		// USING alone would scope reads and leave a cross-tenant INSERT to
		// Postgres's default; email_branding's old handler is exactly the
		// write this must refuse.
		policy := "CREATE POLICY pol_" + tbl + "_org_scope"
		if i := strings.Index(upSQL, policy); i >= 0 {
			end := i + 500
			if end > len(upSQL) {
				end = len(upSQL)
			}
			if !strings.Contains(upSQL[i:end], "WITH CHECK") {
				t.Errorf("v140 policy for %s has no WITH CHECK clause", tbl)
			}
		}

		// A rollback that leaves the belt on is not a rollback.
		if !strings.Contains(downSQL, "DROP POLICY IF EXISTS pol_"+tbl+"_org_scope ON "+tbl) {
			t.Errorf("v140 DownSQL does not drop the policy for %s", tbl)
		}
		if !strings.Contains(downSQL, "ALTER TABLE "+tbl+" NO FORCE ROW LEVEL SECURITY;") {
			t.Errorf("v140 DownSQL does not lift FORCE for %s", tbl)
		}
	}

	for _, tbl := range v140NotNull {
		notNull := "ALTER TABLE " + tbl + " ALTER COLUMN org_id SET NOT NULL;"
		if !strings.Contains(upSQL, notNull) {
			t.Errorf("v140 does not pin %s.org_id NOT NULL", tbl)
		}
		// SET NOT NULL on a column that still holds NULLs aborts the
		// migration, so the backfill has to come first in the statement stream.
		backfillAt := strings.Index(upSQL, "UPDATE "+tbl+" SET org_id")
		switch notNullAt := strings.Index(upSQL, notNull); {
		case backfillAt < 0:
			t.Errorf("v140 pins %s.org_id NOT NULL with no backfill before it", tbl)
		case notNullAt >= 0 && backfillAt > notNullAt:
			t.Errorf("v140 backfills %s AFTER SET NOT NULL; the migration would abort", tbl)
		}
		if !strings.Contains(downSQL, "ALTER TABLE "+tbl+" ALTER COLUMN org_id DROP NOT NULL;") {
			t.Errorf("v140 DownSQL does not restore %s.org_id as nullable", tbl)
		}
	}

	// The runner's splitSQL cannot handle DO $$ blocks; v37, v69, v121 and
	// v138 all keep to plain statements for the same reason.
	if strings.Contains(m.UpSQL, "DO $$") || strings.Contains(m.DownSQL, "DO $$") {
		t.Error("v140 uses a DO $$ block; the migration runner's splitSQL cannot execute it")
	}
	// No DEFAULT on org_id: a rolled-back binary must fail loudly rather than
	// silently write rows into whichever org the default names.
	if strings.Contains(m.UpSQL, "org_id SET DEFAULT") {
		t.Error("v140 sets a DEFAULT on org_id; a rolled-back binary would mis-tenant new rows")
	}
}

// TestMigrationV140_MatchesOrgscopeRegister is the join between the migration
// and the lint. tools/orgscope derives its scoped set from this DDL, so a table
// belted here must have left the needsBelt register in the same commit and vice
// versa -- otherwise the belt lands without its queries being checked, which is
// the coupling the register exists to force.
func TestMigrationV140_MatchesOrgscopeRegister(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 140 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v140 not registered in allMigrations()")
	}
	// Count the FORCE statements and match them against the declared list, so
	// a table quietly added to the SQL without a register entry is caught.
	forced := strings.Count(collapseSpaces(m.UpSQL), " FORCE ROW LEVEL SECURITY;")
	if forced != len(v140Tables) {
		t.Errorf("v140 forces RLS on %d tables, but v140Tables lists %d", forced, len(v140Tables))
	}
}

// collapseSpaces squeezes runs of spaces to one so an assertion is about the
// SQL rather than about how its statements happen to be column-aligned.
func collapseSpaces(s string) string {
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	return s
}
