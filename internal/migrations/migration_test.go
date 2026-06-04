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
