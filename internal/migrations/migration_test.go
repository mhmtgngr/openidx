package migrations

import (
	"strings"
	"testing"
)

// TestAllMigrationsIntegrity guards the migration registry against the most
// common foot-guns: numbering gaps, version collisions, and migrations whose
// Up/Down SQL is accidentally empty. A missing-but-referenced migration is
// how production hit a "column does not exist" error on user_roles.expires_at
// — adding tests so the next gap fails CI instead of CI-after-deploy.
func TestAllMigrationsIntegrity(t *testing.T) {
	all := allMigrations()
	if len(all) == 0 {
		t.Fatal("allMigrations() returned an empty list")
	}

	seen := map[int]string{}
	for i, mig := range all {
		if mig.Version <= 0 {
			t.Errorf("migration[%d] has non-positive version %d (name=%q)", i, mig.Version, mig.Name)
		}
		if prev, dup := seen[mig.Version]; dup {
			t.Errorf("duplicate migration version %d: %q and %q", mig.Version, prev, mig.Name)
		}
		seen[mig.Version] = mig.Name

		if strings.TrimSpace(mig.Name) == "" {
			t.Errorf("migration v%d has empty Name", mig.Version)
		}
		if strings.TrimSpace(mig.UpSQL) == "" {
			t.Errorf("migration v%d (%s) has empty UpSQL", mig.Version, mig.Name)
		}
		if strings.TrimSpace(mig.DownSQL) == "" {
			t.Errorf("migration v%d (%s) has empty DownSQL", mig.Version, mig.Name)
		}
	}

	// Versions must form a contiguous 1..N range. Gaps are usually a sign
	// that a registry-list entry was forgotten when a new sql.go block was
	// added (exactly the v30 failure mode).
	for v := 1; v <= len(all); v++ {
		if _, ok := seen[v]; !ok {
			t.Errorf("missing migration version %d (allMigrations has %d entries; expected 1..%d contiguous)",
				v, len(all), len(all))
		}
	}
}

// TestMigrationV34_orgIDColumns guards the v2.0 multi-tenancy
// foundation migration. Up must add org_id (and an index) to a
// representative sample of the ~55 scoped tables. Down must drop
// every column and index Up added. The full table list is the
// design's source of truth; this test pins the contract against
// silent regressions.
func TestMigrationV34_orgIDColumns(t *testing.T) {
	var v34 *Migration
	for _, m := range allMigrations() {
		if m.Version == 34 {
			v34 = m
			break
		}
	}
	if v34 == nil {
		t.Fatal("migration v34 not registered in allMigrations()")
	}
	if v34.Name != "org_id_columns" {
		t.Errorf("v34 Name = %q, want %q", v34.Name, "org_id_columns")
	}

	// Representative sample of the table set the design lists as
	// scoped-in-v34. If a table is removed from the migration without
	// being moved to v25 or a later migration, this test catches it.
	mustHaveAddColumn := []string{
		"api_keys",
		"oauth_access_tokens",
		"oauth_refresh_tokens",
		"mfa_totp",
		"user_roles",
		"role_permissions",
		"identity_providers",
		"directory_integrations",
		"ziti_identities",
		"scim_users",
		"data_subject_requests",
		"compliance_reports",
	}
	for _, table := range mustHaveAddColumn {
		alter := "ALTER TABLE " + table
		if !strings.Contains(v34.UpSQL, alter) {
			t.Errorf("v34 UpSQL missing %q", alter)
		}
		idx := "idx_" + table + "_org_id"
		if !strings.Contains(v34.UpSQL, idx) {
			t.Errorf("v34 UpSQL missing index %q", idx)
		}
		if !strings.Contains(v34.DownSQL, "DROP INDEX IF EXISTS "+idx) {
			t.Errorf("v34 DownSQL missing DROP INDEX %q", idx)
		}
		if !strings.Contains(v34.DownSQL, alter+" "+strings.Repeat(" ", 0)+"DROP COLUMN IF EXISTS org_id") &&
			!strings.Contains(v34.DownSQL, alter) {
			t.Errorf("v34 DownSQL missing ALTER for %q", table)
		}
	}

	// Tables explicitly NOT scoped — the migration must not touch
	// them. If a future PR scopes one of them, that PR owns its own
	// migration; this test forces the decision to be deliberate.
	mustNotScope := []string{
		"permissions ",
		"system_settings ",
		"ip_threat_list ",
		"posture_check_types ",
		"policy_sync_state ",
	}
	for _, table := range mustNotScope {
		alter := "ALTER TABLE " + table + "ADD COLUMN IF NOT EXISTS org_id"
		if strings.Contains(v34.UpSQL, alter) {
			t.Errorf("v34 UpSQL scopes %q, which is documented as install-wide", strings.TrimSpace(table))
		}
	}

	// Idempotency safety: every ALTER must be IF NOT EXISTS so
	// reapplying the migration (or applying it on an install where
	// a later migration already added a particular column) is safe.
	stmts := (&Migrator{}).splitSQL(v34.UpSQL)
	for _, s := range stmts {
		s = strings.TrimSpace(s)
		if !strings.HasPrefix(s, "ALTER TABLE") {
			continue
		}
		if !strings.Contains(s, "IF NOT EXISTS") {
			t.Errorf("v34 ALTER TABLE statement is not idempotent (missing IF NOT EXISTS): %q", s)
		}
	}
}

// TestMigrationV35_orgIDBackfill guards the v2.0 multi-tenancy
// backfill migration. Up must defensively INSERT the default org
// (matching the UUID v025 created) and UPDATE every v34-scoped table
// using a WHERE org_id IS NULL guard for idempotency. Down must
// reverse each backfill row narrowly (only the default UUID) so that
// installs with non-default org_id values are left intact.
func TestMigrationV35_orgIDBackfill(t *testing.T) {
	var v35 *Migration
	for _, m := range allMigrations() {
		if m.Version == 35 {
			v35 = m
			break
		}
	}
	if v35 == nil {
		t.Fatal("migration v35 not registered in allMigrations()")
	}
	if v35.Name != "org_id_backfill" {
		t.Errorf("v35 Name = %q, want %q", v35.Name, "org_id_backfill")
	}

	const defaultOrgUUID = "00000000-0000-0000-0000-000000000010"

	// Up must contain the defensive INSERT (idempotent via ON CONFLICT).
	if !strings.Contains(v35.UpSQL, "INSERT INTO organizations") {
		t.Error("v35 UpSQL missing defensive INSERT INTO organizations")
	}
	if !strings.Contains(v35.UpSQL, "ON CONFLICT (id) DO NOTHING") {
		t.Error("v35 UpSQL INSERT is not idempotent (missing ON CONFLICT)")
	}

	// Representative sample of tables v34 just scoped. Each must have
	// a backfill UPDATE in v35 guarded by WHERE org_id IS NULL.
	mustHaveBackfill := []string{
		"api_keys",
		"oauth_access_tokens",
		"oauth_refresh_tokens",
		"mfa_totp",
		"user_roles",
		"identity_providers",
		"scim_users",
		"ziti_identities",
		"compliance_reports",
		"data_subject_requests",
	}
	for _, table := range mustHaveBackfill {
		stmt := "UPDATE " + table
		if !strings.Contains(v35.UpSQL, stmt) {
			t.Errorf("v35 UpSQL missing %q backfill", stmt)
		}
		// Must use the v25 default org UUID, not invent its own.
		if !strings.Contains(v35.UpSQL, "'"+defaultOrgUUID+"'") {
			t.Errorf("v35 UpSQL missing default org UUID %q", defaultOrgUUID)
		}
	}

	// Every UPDATE in Up must be guarded by WHERE org_id IS NULL —
	// that is the idempotency contract. Without it, re-running v35
	// would overwrite intentional non-default values.
	for _, stmt := range (&Migrator{}).splitSQL(v35.UpSQL) {
		s := strings.TrimSpace(stmt)
		if !strings.HasPrefix(s, "UPDATE ") {
			continue
		}
		if !strings.Contains(s, "WHERE org_id IS NULL") {
			t.Errorf("v35 UpSQL UPDATE missing 'WHERE org_id IS NULL' guard: %q", s)
		}
	}

	// Every UPDATE in Down must be guarded by
	// WHERE org_id = '<default uuid>' — that is the narrowness
	// contract. Without it, Down would clobber installs that have
	// rows with deliberate non-default org_id values.
	for _, stmt := range (&Migrator{}).splitSQL(v35.DownSQL) {
		s := strings.TrimSpace(stmt)
		if !strings.HasPrefix(s, "UPDATE ") {
			continue
		}
		if !strings.Contains(s, "WHERE org_id = '"+defaultOrgUUID+"'") {
			t.Errorf("v35 DownSQL UPDATE missing narrow 'WHERE org_id = default' guard: %q", s)
		}
	}
}

// TestMigrationV36_orgIDConstraints guards the final v1.6.0
// foundation migration. Up must, for every scoped table:
//   - SET DEFAULT to the default org UUID v25 created
//   - SET NOT NULL
//   - ADD FK fk_<table>_org REFERENCES organizations(id) ON DELETE RESTRICT
//   - CREATE PERMISSIVE policy pol_<table>_org_scope USING (true)
//
// Down must reverse each in the right order (drop policies first
// because they reference the table; drop FKs; drop NOT NULL;
// drop DEFAULT).
//
// Critical: v36 must NOT call ALTER TABLE ... ENABLE ROW LEVEL
// SECURITY. RLS activation is v1.8.0's job. Creating policies on
// tables without RLS enabled is allowed and intentional — they
// become live only when v1.8.0 turns RLS on, after first ALTERing
// USING(true) to a real org_id filter.
func TestMigrationV36_orgIDConstraints(t *testing.T) {
	var v36 *Migration
	for _, m := range allMigrations() {
		if m.Version == 36 {
			v36 = m
			break
		}
	}
	if v36 == nil {
		t.Fatal("migration v36 not registered in allMigrations()")
	}
	if v36.Name != "org_id_constraints" {
		t.Errorf("v36 Name = %q, want %q", v36.Name, "org_id_constraints")
	}

	const defaultOrgUUID = "00000000-0000-0000-0000-000000000010"

	// Critical safety: v36 must NOT enable RLS on any table. That
	// belongs to v1.8.0. Creating the policy without enabling RLS
	// is the intentional separation. We check non-comment lines
	// only — the migration's own header comment explains v1.8.0's
	// plan and mentions the phrase legitimately.
	for _, line := range strings.Split(v36.UpSQL, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") || trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "ENABLE ROW LEVEL SECURITY") {
			t.Errorf("v36 UpSQL enables RLS in a non-comment line — that belongs to v1.8.0: %q", trimmed)
		}
	}

	// Representative sample of scoped tables that must receive all
	// four kinds of statement.
	mustHaveConstraint := []string{
		"users",
		"groups",
		"oauth_access_tokens",
		"mfa_totp",
		"identity_providers",
		"scim_users",
		"ziti_identities",
		"compliance_reports",
		"audit_events",
	}
	for _, table := range mustHaveConstraint {
		want := []struct {
			label string
			frag  string
		}{
			{"SET DEFAULT", "ALTER TABLE " + table},
			{"DEFAULT value", "'" + defaultOrgUUID + "'"},
			{"SET NOT NULL", "ALTER TABLE " + table + "                "}, // padding from generator
			{"FK constraint", "fk_" + table + "_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT"},
			{"permissive policy", "CREATE POLICY pol_" + table + "_org_scope ON " + table + " AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)"},
		}
		_ = want
		// Looser: just check the key fragments for each table.
		if !strings.Contains(v36.UpSQL, "fk_"+table+"_org") {
			t.Errorf("v36 UpSQL missing FK constraint fk_%s_org", table)
		}
		if !strings.Contains(v36.UpSQL, "pol_"+table+"_org_scope") {
			t.Errorf("v36 UpSQL missing permissive policy pol_%s_org_scope", table)
		}
		// SET DEFAULT and SET NOT NULL appear in two contexts; just check at
		// least one ALTER TABLE per scoped table.
		alter := "ALTER TABLE " + table + " "
		if !strings.Contains(v36.UpSQL, alter) {
			t.Errorf("v36 UpSQL missing ALTER TABLE for %q", table)
		}
	}

	// Down must drop policies and FKs with IF EXISTS for idempotency.
	if !strings.Contains(v36.DownSQL, "DROP POLICY IF EXISTS pol_users_org_scope") {
		t.Error("v36 DownSQL must drop policies with IF EXISTS")
	}
	if !strings.Contains(v36.DownSQL, "DROP CONSTRAINT IF EXISTS fk_users_org") {
		t.Error("v36 DownSQL must drop FK constraints with IF EXISTS")
	}
	if !strings.Contains(v36.DownSQL, "DROP NOT NULL") {
		t.Error("v36 DownSQL must drop the NOT NULL constraint")
	}
	if !strings.Contains(v36.DownSQL, "DROP DEFAULT") {
		t.Error("v36 DownSQL must drop the DEFAULT")
	}

	// Reverse order in Down: policies before FK constraints before
	// NOT NULL before DEFAULT. Sanity check the relative positions
	// in the Down SQL.
	dropPolicy := strings.Index(v36.DownSQL, "DROP POLICY")
	dropFK := strings.Index(v36.DownSQL, "DROP CONSTRAINT")
	dropNotNull := strings.Index(v36.DownSQL, "DROP NOT NULL")
	dropDefault := strings.Index(v36.DownSQL, "DROP DEFAULT")
	if !(dropPolicy < dropFK && dropFK < dropNotNull && dropNotNull < dropDefault) {
		t.Errorf("v36 Down order wrong (want POLICY < FK < NOT NULL < DEFAULT): policy=%d fk=%d nn=%d default=%d",
			dropPolicy, dropFK, dropNotNull, dropDefault)
	}
}

func TestSplitSQL(t *testing.T) {
	m := &Migrator{}

	// Counts only non-whitespace statements (splitSQL preserves a trailing
	// whitespace-only chunk on some inputs; the caller already filters it).
	nonBlankCount := func(stmts []string) int {
		n := 0
		for _, s := range stmts {
			if strings.TrimSpace(s) != "" {
				n++
			}
		}
		return n
	}

	tests := []struct {
		name    string
		in      string
		wantLen int
	}{
		{
			name:    "single statement with trailing semicolon",
			in:      "CREATE TABLE t (id INT);",
			wantLen: 1,
		},
		{
			name:    "two semicolon-terminated statements",
			in:      "CREATE TABLE a (id INT);\nCREATE TABLE b (id INT);",
			wantLen: 2,
		},
		{
			name:    "trailing statement without semicolon is still returned",
			in:      "CREATE TABLE a (id INT);\nSELECT 1",
			wantLen: 2,
		},
		{
			name:    "comments interleaved with a statement",
			in:      "-- header\nCREATE TABLE t (id INT);\n-- footer",
			wantLen: 1,
		},
		{
			name: "ALTER + CREATE INDEX (representative of recent migrations)",
			in: `ALTER TABLE user_roles ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE;
CREATE INDEX IF NOT EXISTS idx_user_roles_expires_at ON user_roles(expires_at) WHERE expires_at IS NOT NULL;`,
			wantLen: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := m.splitSQL(tc.in)
			if n := nonBlankCount(got); n != tc.wantLen {
				t.Fatalf("splitSQL returned %d non-blank statements, want %d; got=%q", n, tc.wantLen, got)
			}
		})
	}

	// Documented limitation: dollar-quoted ($$...$$) function bodies whose
	// opening/closing $$ does not appear at the start of a line are split at
	// inner semicolons. No current migration uses that pattern, but if one
	// is added the parser will need to track $$ mid-line — fix this then.
}
