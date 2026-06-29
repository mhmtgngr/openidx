package migrations

import (
	"strings"
	"testing"
)

// TestV53RoleMigrationSplitsCleanly guards against the splitSQL dollar-quote bug:
// the DO $$ … $$ blocks in v53 must survive as single statements, not be shredded
// at their inner semicolons (which made the migration fail to apply).
func TestV53RoleMigrationSplitsCleanly(t *testing.T) {
	m := &Migrator{}
	for name, sql := range map[string]string{"up": rlsAppRoleUp, "down": rlsAppRoleDown} {
		stmts := m.splitSQL(sql)
		var doStmt string
		for _, s := range stmts {
			ts := strings.TrimSpace(s)
			if ts == "END IF;" || ts == "$$;" || strings.HasPrefix(ts, "END IF") || ts == "BEGIN" {
				t.Fatalf("%s: DO block was shredded — stray fragment %q", name, ts)
			}
			if strings.Contains(s, "openidx_app") &&
				(strings.Contains(s, "CREATE ROLE") || strings.Contains(s, "DROP ROLE")) {
				doStmt = s
			}
		}
		if doStmt == "" {
			t.Fatalf("%s: no intact DO statement containing the role CREATE/DROP found", name)
		}
		if !strings.Contains(doStmt, "$$") || !strings.Contains(doStmt, "END") {
			t.Fatalf("%s: DO block not intact in one statement: %q", name, doStmt)
		}
	}
}
