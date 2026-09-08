package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isStatement decides what the database is asked about. Getting it wrong in one
// direction floods the run with noise; in the other it quietly stops checking,
// which is the failure that matters -- a guard that has silently narrowed to
// nothing reports "0 findings" and reads exactly like success.
func TestIsStatementSeparatesQueriesFromEverythingElse(t *testing.T) {
	cases := []struct {
		name string
		s    string
		want bool
	}{
		{"a plain select", "SELECT id FROM users WHERE org_id = $1", true},
		{"leading whitespace and newlines", "\n\t\tSELECT id\n\t\tFROM users\n", true},
		{"a two-word probe", "SELECT 1", true},
		{"an insert", "INSERT INTO users (id) VALUES ($1)", true},
		{"an update", "UPDATE users SET name = $1 WHERE id = $2", true},
		{"a delete", "DELETE FROM sessions WHERE id = $1", true},
		{"a CTE", "WITH recent AS (SELECT 1) SELECT * FROM recent", true},
		{"a leading SQL comment", "-- Migration 026\nSELECT 1", true},

		{"prose that opens with a keyword", "select the tenant before writing", false},
		{"more prose", "update the client and retry later", false},
		{"a column list, not a statement", "id, name, created_at", false},
		{"DDL is the schema, not a query about it", "CREATE TABLE t (id UUID)", false},
		{"an ALTER", "ALTER TABLE t ADD COLUMN x INT", false},
		{"a fmt template is not a statement", "SELECT %s FROM users", false},
		{"a wrapped error string", "update oauth client: %w", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		if got := isStatement(tc.s); got != tc.want {
			t.Errorf("isStatement(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

// The skip list is the tool's honesty about its own reach. Each entry must name
// a limit of PREPARE, never a class of defect somebody found inconvenient.
func TestOnlyPrepareLimitationsAreSkipped(t *testing.T) {
	skipped := []string{"42601", "42P18"}
	for _, code := range skipped {
		reason, ok := skipReason(code, "", "SELECT 1", false)
		if !ok {
			t.Errorf("SQLSTATE %s should be skipped", code)
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("SQLSTATE %s is skipped with no reason", code)
		}
	}

	// 42P08 used to sit in that list and does not belong there. "inconsistent
	// types deduced for parameter" is not a limit of PREPARE: pgx sends
	// parameters UNTYPED, so the deduction this tool sees is the one the
	// runtime performs, and a statement that cannot deduce one type for a
	// parameter fails when it is executed. Skipping it hid a live failure --
	// an INSERT ... SELECT reusing one parameter for notifications.type and
	// notification_preferences.event_type passed this sweep and raised 42P08 on
	// its first execution against a real database.
	if reason, ok := skipReason("42P08", "inconsistent types deduced for parameter $5", "INSERT INTO t SELECT $1", false); ok {
		t.Errorf("42P08 is skipped as %q; it is a statement that fails at runtime", reason)
	}

	// 42P01 is skippable in exactly one shape and a finding in every other:
	// "missing FROM-clause entry" on a literal that has no FROM clause is a
	// SELECT list somebody uses as a search string, not a statement. A missing
	// TABLE always comes from a statement that HAS the FROM clause naming it.
	if _, ok := skipReason("42P01", `missing FROM-clause entry for table "e"`,
		"SELECT e.id, e.source, r.name as route_name", false); !ok {
		t.Error("a SELECT list with no FROM clause is not a statement and must be skipped")
	}
	if reason, ok := skipReason("42P01", `missing FROM-clause entry for table "x"`,
		"SELECT a FROM t WHERE x.id = 1", false); ok {
		t.Errorf("a statement WITH a FROM clause was skipped as %q", reason)
	}
	if reason, ok := skipReason("42P01", `relation "gone" does not exist`,
		"SELECT a FROM gone", false); ok {
		t.Errorf("a missing table was skipped as %q -- that is the class this tool exists for", reason)
	}

	// The defect classes this tool exists to find must never be skippable.
	for _, code := range []string{
		"42703", // column does not exist
		"42P01", // relation does not exist
		"42883", // function/operator does not exist
		"42804", // datatype mismatch
		"42803", // grouping error
		"22P02", // invalid text representation (malformed array, bad uuid literal)
	} {
		if reason, ok := skipReason(code, `relation "t" does not exist`, "SELECT a FROM t", false); ok {
			t.Errorf("SQLSTATE %s must be a finding, not skipped as %q", code, reason)
		}
	}
}

// The fingerprint has to survive a query moving down its file and NOT survive
// the query being edited, because an edited query is one nobody has re-checked.
func TestFingerprintTracksTheQueryNotTheLine(t *testing.T) {
	base := finding{File: "internal/x/y.go", Line: 10, SQL: "SELECT a FROM t WHERE id = $1"}
	moved := finding{File: "internal/x/y.go", Line: 900, SQL: "\n\tSELECT a\n\tFROM t\n\tWHERE id = $1\n"}
	edited := finding{File: "internal/x/y.go", Line: 10, SQL: "SELECT a, b FROM t WHERE id = $1"}
	elsewhere := finding{File: "internal/z/y.go", Line: 10, SQL: "SELECT a FROM t WHERE id = $1"}

	if base.fingerprint() != moved.fingerprint() {
		t.Error("moving a query changed its fingerprint; every register entry would go stale on a reformat")
	}
	if base.fingerprint() == edited.fingerprint() {
		t.Error("editing a query kept its fingerprint; a rewritten query would inherit an old verdict")
	}
	if base.fingerprint() == elsewhere.fingerprint() {
		t.Error("the same SQL in a different file shares a fingerprint")
	}
}

// Every register entry must say what the query does wrong and what the user
// sees. An entry that says nothing is a suppression with extra steps.
func TestEveryRegisterEntryCarriesAVerdict(t *testing.T) {
	if len(knownBroken) == 0 {
		return // the list is meant to reach zero
	}
	for key, verdict := range knownBroken {
		if !strings.Contains(key, "#") {
			t.Errorf("register key %q is not file#fingerprint", key)
		}
		if len(strings.TrimSpace(verdict)) < 40 {
			t.Errorf("register entry %s has no real verdict: %q", key, verdict)
		}
	}
}

// The sweep must actually see the repository. A collector that walks nothing
// prepares nothing and reports a clean run.
func TestCollectFindsTheRepositorysSQL(t *testing.T) {
	root := repoRoot(t)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}

	stmts, err := collect(defaultRoots)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(stmts) < 500 {
		t.Fatalf("collected only %d SQL literals; the sweep is not reaching the tree", len(stmts))
	}
	for _, s := range stmts {
		if strings.Contains(s.File, "/migrations/") {
			t.Errorf("%s: migrations are the schema, not statements to prepare", s.File)
			break
		}
		if strings.HasSuffix(s.File, "_test.go") {
			t.Errorf("%s: test files are not product SQL", s.File)
			break
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the module root")
	return ""
}

// A grouping error is skippable only on a literal the code appends clauses to.
// internal/governance builds its access-review list that way: the aggregate is
// in the literal and the GROUP BY arrives three statements later, so preparing
// the first half alone reports a grouping error for a query that groups
// correctly at runtime. The same error on a COMPLETE statement is a real defect
// -- it fails the same way against the database.
func TestGroupingErrorsAreSkippedOnlyOnAssembledQueries(t *testing.T) {
	const detail = `column "ar.id" must appear in the GROUP BY clause`
	const sql = "SELECT ar.id, COUNT(ri.id) FROM access_reviews ar LEFT JOIN review_items ri ON ar.id = ri.review_id"

	if _, ok := skipReason("42803", detail, sql, true); !ok {
		t.Error("a grouping error on a literal the code appends to must be skipped")
	}
	if reason, ok := skipReason("42803", detail, sql, false); ok {
		t.Errorf("a grouping error on a complete statement was skipped as %q", reason)
	}
	// And a missing column stays a finding even on a fragment: no suffix
	// supplies a column the table does not have.
	if reason, ok := skipReason("42703", `column "gone" does not exist`, sql, true); ok {
		t.Errorf("a missing column on a fragment was skipped as %q", reason)
	}
}

// The fragment flag has to come from the code, not from a guess: a literal is
// assembled when the file appends to the variable holding it.
func TestContinuedVariablesAreDetected(t *testing.T) {
	src := `package p

func f(status string) {
	baseQuery := ` + "`SELECT a, COUNT(b) FROM t`" + `
	if status != "" {
		baseQuery += " AND status = $1"
	}
	baseQuery += ` + "`GROUP BY a`" + `
	whole := ` + "`SELECT c FROM u`" + `
	_, _ = baseQuery, whole
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	continued := continuedVars(f)
	if !continued["baseQuery"] {
		t.Error("baseQuery is appended to and was not recognised")
	}
	if continued["whole"] {
		t.Error("whole is never appended to and was marked assembled")
	}
}
