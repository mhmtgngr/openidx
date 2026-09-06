package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/migrations"
)

// The register is a list of verdicts, not a list of names. An entry without a
// reason is a name somebody moved off a report, which is the failure mode the
// register exists to prevent.
func TestEveryRegisterEntryCarriesAVerdict(t *testing.T) {
	for table, verdict := range knownUnwritten {
		if len(verdict) < 60 {
			t.Errorf("%s: verdict is %d characters; say what the absence causes",
				table, len(verdict))
		}
		if !strings.HasSuffix(strings.TrimSpace(verdict), ".") {
			t.Errorf("%s: verdict does not end in a sentence", table)
		}
	}
}

// The fold reads the Up half only. A Down that drops a table describes a
// rollback, not the schema; reading both halves makes every table look dropped
// by its own migration.
func TestFoldReadsOnlyTheUpHalf(t *testing.T) {
	set := []*migrations.Migration{
		{Version: 3, UpSQL: `ALTER TABLE alpha RENAME TO gamma;`},
		{Version: 1, UpSQL: `CREATE TABLE IF NOT EXISTS alpha (id UUID);
			CREATE TABLE IF NOT EXISTS beta (id UUID);`},
		{Version: 2, UpSQL: `DROP TABLE IF EXISTS beta;`,
			DownSQL: `DROP TABLE IF EXISTS alpha;`},
	}
	live, seeded := foldTables(set)

	if _, ok := live["alpha"]; ok {
		t.Error("alpha survived its rename")
	}
	if _, ok := live["beta"]; ok {
		t.Error("beta survived its DROP")
	}
	if origin, ok := live["gamma"]; !ok {
		t.Error("the renamed table is missing")
	} else if origin != 1 {
		t.Errorf("gamma origin = v%d, want v1 (a rename keeps the creating version)", origin)
	}
	if len(seeded) != 0 {
		t.Errorf("seeded = %v, want empty", seeded)
	}
}

// A table a migration seeds has a writer -- the migration. Reporting it would
// make every reference list and singleton cursor a finding, and a guard that
// reports what is fine is one somebody turns off.
func TestAMigrationSeedIsAWriter(t *testing.T) {
	set := []*migrations.Migration{
		{Version: 1, UpSQL: `CREATE TABLE IF NOT EXISTS cursor_row (id INT PRIMARY KEY);
			INSERT INTO cursor_row (id) VALUES (1) ON CONFLICT (id) DO NOTHING;`},
		{Version: 2, UpSQL: `CREATE TABLE IF NOT EXISTS never_filled (id INT PRIMARY KEY);`},
	}
	live, seeded := foldTables(set)

	findings := report(live, seeded, map[string]*usage{})
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	if findings[0].Table != "never_filled" {
		t.Errorf("finding = %q, want never_filled (the seeded table has a writer)", findings[0].Table)
	}
}

// The two verdicts are different defects and the report must not merge them:
// an orphan is dead schema, a read table with no writer is a number shown to
// somebody.
func TestReadWithNoWriterIsNotTheSameAsAnOrphan(t *testing.T) {
	live := map[string]int{"shown": 54, "orphan": 54, "fine": 54}
	use := map[string]*usage{
		"shown": {Readers: []string{"internal/admin/dash.go"}},
		"fine":  {Readers: []string{"a.go"}, Writers: []string{"b.go"}},
	}
	findings := report(live, map[string]int{}, use)

	got := map[string]string{}
	for _, f := range findings {
		got[f.Table] = f.Kind
	}
	if got["shown"] != "read, never written" {
		t.Errorf("shown = %q, want \"read, never written\"", got["shown"])
	}
	if got["orphan"] != "neither read nor written" {
		t.Errorf("orphan = %q, want \"neither read nor written\"", got["orphan"])
	}
	if _, reported := got["fine"]; reported {
		t.Error("a table with a writer was reported")
	}
}

// Prose about SQL is not SQL. internal/admin's analytics handler carries a
// comment quoting the query a previous fix deleted, and a line-based scan reads
// it as a live read of a table dropped two migrations ago -- which is exactly
// what the first draft of this census did.
func TestProseAboutSQLIsNotRead(t *testing.T) {
	dir := t.TempDir()
	src := "package p\n\n" +
		"// It used to read a stored table first:\n" +
		"//\n" +
		"//\tSELECT feature_name FROM feature_adoption ...\n" +
		"//\n" +
		"// and that table is gone.\n" +
		"const q = `SELECT id FROM live_table`\n"
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	use, err := scanUsage([]string{dir}, map[string]int{"feature_adoption": 54, "live_table": 54})
	if err != nil {
		t.Fatal(err)
	}
	if u := use["feature_adoption"]; u != nil {
		t.Errorf("a comment was read as a query: %+v", u)
	}
	if u := use["live_table"]; u == nil || len(u.Readers) != 1 {
		t.Errorf("the real query was missed: %+v", u)
	}
}

// A file the parser cannot read must stop the run, not shrink it. The sibling
// sweep in tools/sqlprepare skipped unparseable files at first, and a stray
// backtick in a comment turned it off for a whole file while the run reported
// one FEWER finding -- which reads exactly like a fix.
func TestAParseFailureIsFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.go"), []byte("package p\nfunc ("), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := scanUsage([]string{dir}, map[string]int{}); err == nil {
		t.Error("an unparseable file was skipped silently")
	}
}

// The verbs that count as writing. UPDATE and DELETE matter as much as INSERT:
// a table whose rows only ever change is still written, and a guard that only
// knows INSERT would report the SIEM cursor.
func TestWriteVerbsAreRecognised(t *testing.T) {
	dir := t.TempDir()
	src := "package p\n" +
		"const a = `INSERT INTO t1 (id) VALUES ($1)`\n" +
		"const b = `UPDATE t2 SET seen = NOW() WHERE id = 1`\n" +
		"const c = `DELETE FROM t3 WHERE id = $1`\n" +
		"const d = `SELECT id FROM t4 JOIN t5 ON t5.id = t4.id`\n"
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	live := map[string]int{"t1": 1, "t2": 1, "t3": 1, "t4": 1, "t5": 1}
	use, err := scanUsage([]string{dir}, live)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"t1", "t2", "t3"} {
		if u := use[table]; u == nil || len(u.Writers) != 1 {
			t.Errorf("%s: not recorded as written: %+v", table, u)
		}
	}
	for _, table := range []string{"t4", "t5"} {
		if u := use[table]; u == nil || len(u.Readers) != 1 || len(u.Writers) != 0 {
			t.Errorf("%s: not recorded as read-only: %+v", table, u)
		}
	}
}

// The registry must actually be foldable: an empty result would make every
// finding disappear and the run report a clean sweep.
func TestTheRealRegistryFoldsToASchema(t *testing.T) {
	live, seeded, err := liveTables()
	if err != nil {
		t.Fatal(err)
	}
	if len(live) < 100 {
		t.Fatalf("live tables = %d; the fold has stopped seeing the registry", len(live))
	}
	for _, must := range []string{"users", "sessions", "audit_events", "organizations"} {
		if _, ok := live[must]; !ok {
			t.Errorf("%s is missing from the derived schema", must)
		}
	}
	if _, ok := seeded["audit_events"]; !ok {
		t.Error("audit_events is seeded by a migration and the fold did not notice")
	}
}
