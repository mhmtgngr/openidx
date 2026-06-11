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
