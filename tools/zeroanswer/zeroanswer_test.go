package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The rule, in both directions, on source this test writes.
//
// A guard that only ever runs against the real tree cannot show what it does
// NOT fire on, and that is the half that decides whether anyone leaves it
// turned on. Every case below names the reading it protects.
func TestWhatCountsAsAZeroAnswer(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool // is it a finding
		why  string
	}{
		{
			name: "a discarded aggregate error",
			src:  "func f() { s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE org_id = $1`, o).Scan(&n) }",
			want: true,
			why:  "the count is left at zero and printed as a measurement",
		},
		{
			name: "the same aggregate with the error checked",
			src:  "func f() error { return s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n) }",
			want: false,
			why:  "a checked error is the fix, and the guard must not fire on it",
		},
		{
			name: "assigned to the blank identifier",
			src:  "func f() { _ = s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n) }",
			want: true,
			why:  "`_ =` is discarding it with extra steps",
		},
		{
			name: "an if-statement that checks it",
			src:  "func f() { if err := s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil { return } }",
			want: false,
			why:  "checked",
		},
		{
			name: "a row lookup, not an aggregate",
			src:  "func f() { s.db.Pool.QueryRow(ctx, `SELECT org_id FROM vault_secrets WHERE id = $1`, id).Scan(&org) }",
			want: false,
			why:  "no rows is a legitimate answer here, so the zero value can be the right reading",
		},
		{
			name: "COALESCE around COUNT",
			src:  "func f() { s.db.Pool.QueryRow(ctx, `SELECT COALESCE(COUNT(*), 0) FROM users`).Scan(&n) }",
			want: true,
			why:  "still exactly one row",
		},
		{
			name: "COUNT DISTINCT",
			src:  "func f() { s.db.Pool.QueryRow(ctx, `SELECT COUNT(DISTINCT user_id) FROM mfa_totp`).Scan(&n) }",
			want: true,
			why:  "still exactly one row",
		},
		{
			name: "SELECT EXISTS",
			src:  "func f() { s.db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, id).Scan(&ok) }",
			want: true,
			why:  "EXISTS returns one row, so a failure reads as false rather than as a failure",
		},
		{
			name: "AVG",
			src:  "func f() { s.db.Pool.QueryRow(ctx, `SELECT AVG(risk_score) FROM login_history`).Scan(&avg) }",
			want: true,
			why:  "an average of nothing is not the same as an average nobody took",
		},
		{
			name: "MAX",
			src:  "func f() { s.db.Pool.QueryRow(ctx, `SELECT MAX(timestamp) FROM audit_events`).Scan(&t) }",
			want: true,
			why:  "the zero time reads as 1970, which a report prints as a date",
		},
		{
			name: "SQL built at run time",
			src:  "func f() { s.db.Pool.QueryRow(ctx, buildCountQuery(filters), args...).Scan(&n) }",
			want: false,
			why:  "the statement's shape is not knowable here, and guessing would make the check unsound",
		},
		{
			name: "a Query, not a QueryRow",
			src:  "func f() { rows, _ := s.db.Pool.Query(ctx, `SELECT COUNT(*) FROM users`) ; _ = rows }",
			want: false,
			why:  "this guard is about the one-row read; the multi-row shape is a different check",
		},
		{
			name: "Scan on something that is not a QueryRow",
			src:  "func f() { decoder.Result().Scan(&n) }",
			want: false,
			why:  "not a database read at all",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			src := "package p\n\n" + tc.src + "\n"
			if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
			aggregates, _ := scan([]string{dir})
			got := len(aggregates) > 0
			if got != tc.want {
				t.Errorf("finding = %v, want %v -- %s\n%s", got, tc.want, tc.why, tc.src)
			}
		})
	}
}

// A test file is never scanned: its fixtures are allowed to be careless, and a
// guard that fires on them is one somebody turns off.
func TestTestFilesAreNotScanned(t *testing.T) {
	dir := t.TempDir()
	src := "package p\n\nfunc f() { s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n) }\n"
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if aggregates, _ := scan([]string{dir}); len(aggregates) != 0 {
		t.Errorf("a _test.go file produced %d finding(s)", len(aggregates))
	}
}

// Every entry in the register says what the zero does. A key with an empty or
// placeholder value is a suppression, which is the thing this list must not
// become.
func TestEveryRegisterEntryCarriesAVerdict(t *testing.T) {
	for key, verdict := range knownZeroAnswers {
		if len(strings.TrimSpace(verdict)) < 20 {
			t.Errorf("register entry %q has no real verdict: %q", key, verdict)
		}
		if !strings.Contains(verdict, "--") {
			t.Errorf("register entry %q does not say what the zero does: %q", key, verdict)
		}
	}
}

// The register matches the tree: no finding is unlisted, and no listed finding
// has gone away without its line being deleted.
func TestTheRegisterMatchesTheTree(t *testing.T) {
	root := repoRoot(t)
	aggregates, _ := scan([]string{filepath.Join(root, "internal"), filepath.Join(root, "cmd")})
	seen := map[string]bool{}
	for _, f := range aggregates {
		// scan() keys by the path it was given, so strip the root back off.
		key := strings.TrimPrefix(f.key, filepath.ToSlash(root)+"/")
		seen[key] = true
		if _, ok := knownZeroAnswers[key]; !ok {
			t.Errorf("%s:%d: %s in %s is an unregistered zero answer\n  %s",
				f.file, f.line, f.dest, f.fn, f.sql)
		}
	}
	for key := range knownZeroAnswers {
		if !seen[key] {
			t.Errorf("stale register entry %q: no longer a finding, delete the line", key)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the repository root")
	return ""
}
