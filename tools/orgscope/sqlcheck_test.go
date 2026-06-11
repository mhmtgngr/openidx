package main

import (
	"strings"
	"testing"
)

func TestStartsWithSQLKeyword(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"SELECT * FROM users", true},
		{"select * from users", true},
		{"  SELECT id FROM users", true},
		{"\n\tSELECT id FROM users", true},
		{"UPDATE users SET x=1", true},
		{"DELETE FROM users", true},
		{"INSERT INTO users VALUES (1)", true},
		{"WITH cte AS (SELECT 1) SELECT * FROM cte", true},

		// Not SQL — typical false-positive sources:
		{"client_id", false},              // gin's c.Query("client_id")
		{"redirect_uri", false},           // ditto
		{"foo", false},                    // anything else
		{"", false},                       // empty
		{"   ", false},                    // whitespace-only
		{"selectall", false},              // not followed by space/newline/tab
		{"-- SELECT * FROM users", false}, // comment line, not a statement
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got := startsWithSQLKeyword(tc.in)
			if got != tc.want {
				t.Fatalf("startsWithSQLKeyword(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestExtractTables(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want []string
	}{
		{
			name: "SELECT FROM",
			sql:  "SELECT * FROM users WHERE id = $1",
			want: []string{"users"},
		},
		{
			name: "SELECT with JOIN",
			sql:  "SELECT * FROM users u JOIN roles r ON u.role_id = r.id",
			want: []string{"users", "roles"},
		},
		{
			name: "UPDATE",
			sql:  "UPDATE users SET org_id = $1 WHERE id = $2",
			want: []string{"users"},
		},
		{
			name: "DELETE FROM",
			sql:  "DELETE FROM sessions WHERE expires_at < NOW()",
			want: []string{"sessions"},
		},
		{
			name: "INSERT INTO",
			sql:  "INSERT INTO audit_events (id, action) VALUES ($1, $2)",
			want: []string{"audit_events"},
		},
		{
			name: "schema-qualified",
			sql:  "SELECT * FROM public.users",
			want: []string{"users"},
		},
		{
			name: "case insensitive",
			sql:  "select * from Users",
			want: []string{"users"},
		},
		{
			name: "multiple JOINs",
			sql:  "SELECT * FROM users JOIN groups JOIN roles",
			want: []string{"users", "groups", "roles"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractTables(tc.sql)
			if !equalStrings(got, tc.want) {
				t.Fatalf("extractTables(%q) = %v, want %v", tc.sql, got, tc.want)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestAnalyzeSQL_scopedTable_noOrgID_flagged(t *testing.T) {
	sql := "SELECT id, email FROM users WHERE email = $1"
	findings := analyzeSQL(sql)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Table != "users" {
		t.Errorf("Table = %q, want users", findings[0].Table)
	}
}

func TestAnalyzeSQL_scopedTable_withOrgID_notFlagged(t *testing.T) {
	sql := "SELECT id, email FROM users WHERE org_id = $1 AND email = $2"
	if findings := analyzeSQL(sql); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestAnalyzeSQL_unscopedTable_notFlagged(t *testing.T) {
	// permissions is documented as install-wide (global catalog).
	sql := "SELECT * FROM permissions WHERE id = $1"
	if findings := analyzeSQL(sql); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestAnalyzeSQL_organizationsTable_notFlagged(t *testing.T) {
	// organizations is the tenant table itself; queries against it
	// inherently scope by ID/slug, not org_id.
	sql := "SELECT id, name FROM organizations WHERE slug = $1"
	if findings := analyzeSQL(sql); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestAnalyzeSQL_systemSettings_notFlagged(t *testing.T) {
	sql := "SELECT key, value FROM system_settings"
	if findings := analyzeSQL(sql); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

func TestAnalyzeSQL_INSERT_withoutOrgIDColumn_flagged(t *testing.T) {
	sql := "INSERT INTO audit_events (id, action, actor_id) VALUES ($1, $2, $3)"
	findings := analyzeSQL(sql)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Table != "audit_events" {
		t.Errorf("Table = %q, want audit_events", findings[0].Table)
	}
}

func TestAnalyzeSQL_INSERT_withOrgIDColumn_notFlagged(t *testing.T) {
	sql := "INSERT INTO audit_events (id, org_id, action) VALUES ($1, $2, $3)"
	if findings := analyzeSQL(sql); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestAnalyzeSQL_JOIN_oneFiltered_oneNot(t *testing.T) {
	// Heuristic limit: the tool sees org_id anywhere and treats every
	// scoped table as ok. Documented false negative; v1.7.0 will
	// tighten if needed.
	sql := "SELECT u.id FROM users u JOIN audit_events a ON a.actor_id = u.id WHERE u.org_id = $1"
	if findings := analyzeSQL(sql); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 (documented heuristic): %+v", len(findings), findings)
	}
}

func TestAnalyzeSQL_uniqueByTable(t *testing.T) {
	// Querying the same scoped table twice without org_id should
	// produce one finding, not two — we dedupe by table within a
	// statement.
	sql := "DELETE FROM mfa_totp WHERE user_id IN (SELECT user_id FROM mfa_totp WHERE created_at < $1)"
	findings := analyzeSQL(sql)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (dedupe by table): %+v", len(findings), findings)
	}
}

func TestFindingString_truncatesLongSQL(t *testing.T) {
	long := strings.Repeat("SELECT col_xyz, ", 30) + "FROM users"
	f := Finding{Table: "users", Reason: "no org_id in SQL", SQL: long}
	s := f.String()
	if !strings.Contains(s, "scoped table \"users\"") {
		t.Errorf("missing table name in: %s", s)
	}
	if !strings.Contains(s, "...") {
		t.Errorf("long SQL not truncated in: %s", s)
	}
}

func TestFindingString_collapsesWhitespace(t *testing.T) {
	multiline := "SELECT\n\tid\nFROM\n\tusers"
	f := Finding{Table: "users", Reason: "no org_id in SQL", SQL: multiline}
	s := f.String()
	if strings.Contains(s, "\n") || strings.Contains(s, "\t") {
		t.Errorf("preview should collapse whitespace; got: %q", s)
	}
}
