package main

import (
	"fmt"
	"go/token"
	"regexp"
	"strings"
)

// Finding is one detected unscoped query.
type Finding struct {
	Pos    token.Position
	Table  string // the scoped table referenced
	Reason string // human-readable why
	SQL    string // the offending SQL string (truncated when printed)
}

func (f Finding) String() string {
	preview := f.SQL
	if len(preview) > 90 {
		preview = preview[:90] + "..."
	}
	preview = strings.ReplaceAll(preview, "\n", " ")
	preview = strings.ReplaceAll(preview, "\t", " ")
	for strings.Contains(preview, "  ") {
		preview = strings.ReplaceAll(preview, "  ", " ")
	}
	return fmt.Sprintf("%s: scoped table %q used without org_id (%s): %s",
		f.Pos.String(), f.Table, f.Reason, preview)
}

// SQL keyword + identifier patterns. Identifiers are PostgreSQL-style:
// up to 63 chars, snake_case. Schema-qualified names like "schema.users"
// are matched against the last segment.
var (
	fromRE     = regexp.MustCompile(`(?i)\b(?:FROM|JOIN)\s+(?:[a-z_][a-z0-9_]*\.)?([a-z_][a-z0-9_]*)`)
	updateRE   = regexp.MustCompile(`(?i)\bUPDATE\s+(?:[a-z_][a-z0-9_]*\.)?([a-z_][a-z0-9_]*)`)
	deleteRE   = regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+(?:[a-z_][a-z0-9_]*\.)?([a-z_][a-z0-9_]*)`)
	insertRE   = regexp.MustCompile(`(?i)\bINSERT\s+INTO\s+(?:[a-z_][a-z0-9_]*\.)?([a-z_][a-z0-9_]*)`)
	orgIDInSQL = regexp.MustCompile(`(?i)\borg_id\b`)
)

// startsWithSQLKeyword reports whether s begins with a top-level SQL
// keyword we care about. Used to filter out string literals that
// happen to be method arguments but aren't SQL (gin's c.Query("foo"),
// for instance, calls Query with "foo" — not SQL).
func startsWithSQLKeyword(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	upper := strings.ToUpper(s)
	for _, k := range []string{"SELECT ", "SELECT\n", "SELECT\t",
		"UPDATE ", "UPDATE\n", "UPDATE\t",
		"DELETE ", "DELETE\n", "DELETE\t",
		"INSERT ", "INSERT\n", "INSERT\t",
		"WITH ", "WITH\n", "WITH\t"} {
		if strings.HasPrefix(upper, k) {
			return true
		}
	}
	return false
}

// analyzeSQL inspects sql and returns one Finding per distinct
// scoped table referenced without an org_id mention. Returns nil if
// the SQL is fully scoped or references no scoped tables.
//
// Heuristic, not parser: we look for FROM/UPDATE/DELETE FROM/INSERT
// INTO patterns and check if "org_id" appears anywhere in the SQL.
// False negatives are possible (e.g., joining a scoped table to a
// non-scoped one with the org filter on the wrong side). False
// positives are also possible (e.g., a subquery that filters by
// org_id then the outer query joins another scoped table without).
// For v1.6.0 this is informational; v1.7.0 will tighten by promoting
// the tool to a CI gate after each service migration.
func analyzeSQL(sql string) []Finding {
	hasOrgID := orgIDInSQL.MatchString(sql)

	seen := map[string]bool{}
	var findings []Finding
	for _, t := range extractTables(sql) {
		if seen[t] {
			continue
		}
		seen[t] = true
		if !scopedTables[t] {
			continue
		}
		if hasOrgID {
			continue
		}
		findings = append(findings, Finding{
			Table:  t,
			Reason: "no org_id in SQL",
			SQL:    sql,
		})
	}
	return findings
}

func extractTables(sql string) []string {
	// DELETE FROM matches both deleteRE and fromRE, so naive append
	// double-counts. Dedupe while preserving first-seen order so the
	// output is stable across runs (helps test assertions).
	var out []string
	seen := map[string]bool{}
	for _, re := range []*regexp.Regexp{fromRE, updateRE, deleteRE, insertRE} {
		for _, m := range re.FindAllStringSubmatch(sql, -1) {
			if len(m) >= 2 {
				t := strings.ToLower(m[1])
				if seen[t] {
					continue
				}
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}
