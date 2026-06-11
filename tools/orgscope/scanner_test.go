package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeGoFixture writes a one-file Go fixture into a temp dir and
// returns the dir.
func writeGoFixture(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.go")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return dir
}

const headerOK = `package fixture

import "context"

type DB interface {
	Exec(ctx context.Context, sql string, args ...any) error
	Query(ctx context.Context, sql string, args ...any) error
	QueryRow(ctx context.Context, sql string, args ...any) error
}
`

func TestScanFile_unscoped_SELECT_flagged(t *testing.T) {
	src := headerOK + "var _ = func(db DB, ctx context.Context) { db.Query(ctx, `SELECT id FROM users WHERE email = $1`, \"a\") }\n"
	dir := writeGoFixture(t, src)
	findings, err := scanDir(dir)
	if err != nil {
		t.Fatalf("scanDir: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Table != "users" {
		t.Errorf("Table = %q, want users", findings[0].Table)
	}
}

func TestScanFile_scopedSELECT_notFlagged(t *testing.T) {
	src := headerOK + "var _ = func(db DB, ctx context.Context) { db.Query(ctx, `SELECT id FROM users WHERE org_id = $1`, \"a\") }\n"
	dir := writeGoFixture(t, src)
	findings, _ := scanDir(dir)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestScanFile_ginCQuery_notFlagged(t *testing.T) {
	// c.Query("client_id") — the gin URL-query helper. NOT a database
	// call; the string arg isn't SQL. The startsWithSQLKeyword filter
	// must catch this.
	src := `package fixture
type Ctx struct{}
func (Ctx) Query(string) string { return "" }
var _ = func(c Ctx) { _ = c.Query("client_id") }
`
	dir := writeGoFixture(t, src)
	findings, _ := scanDir(dir)
	if len(findings) != 0 {
		t.Fatalf("got %d findings on gin.Query call, want 0: %+v", len(findings), findings)
	}
}

func TestScanFile_testFiles_skipped(t *testing.T) {
	dir := t.TempDir()
	prod := filepath.Join(dir, "prod.go")
	test := filepath.Join(dir, "x_test.go")
	src := headerOK + "var _ = func(db DB, ctx context.Context) { db.Query(ctx, `SELECT id FROM users WHERE email = $1`, \"a\") }\n"
	if err := os.WriteFile(prod, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(test, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, _ := scanDir(dir)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (test file should be skipped): %+v", len(findings), findings)
	}
	if !strings.HasSuffix(findings[0].Pos.Filename, "prod.go") {
		t.Errorf("finding came from %s, want prod.go", findings[0].Pos.Filename)
	}
}

func TestScanFile_vendorDir_skipped(t *testing.T) {
	dir := t.TempDir()
	vendor := filepath.Join(dir, "vendor", "fake")
	if err := os.MkdirAll(vendor, 0o755); err != nil {
		t.Fatal(err)
	}
	src := headerOK + "var _ = func(db DB, ctx context.Context) { db.Query(ctx, `SELECT id FROM users WHERE email = $1`, \"a\") }\n"
	if err := os.WriteFile(filepath.Join(vendor, "x.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, _ := scanDir(dir)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 (vendor should be skipped): %+v", len(findings), findings)
	}
}

func TestScanFile_multipleScopedTablesInOneQuery_flaggedSeparately(t *testing.T) {
	src := headerOK + "var _ = func(db DB, ctx context.Context) { db.Query(ctx, `SELECT u.id FROM users u JOIN audit_events a ON a.actor_id = u.id WHERE a.action = $1`) }\n"
	dir := writeGoFixture(t, src)
	findings, _ := scanDir(dir)
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (users + audit_events): %+v", len(findings), findings)
	}
	tables := map[string]bool{}
	for _, f := range findings {
		tables[f.Table] = true
	}
	if !tables["users"] || !tables["audit_events"] {
		t.Errorf("expected both users and audit_events; got %v", tables)
	}
}

func TestScanFile_positionInfoCarried(t *testing.T) {
	src := headerOK + "var _ = func(db DB, ctx context.Context) { db.Query(ctx, `SELECT id FROM users WHERE email = $1`, \"a\") }\n"
	dir := writeGoFixture(t, src)
	findings, _ := scanDir(dir)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Pos.Line == 0 {
		t.Errorf("Pos.Line not populated: %+v", findings[0].Pos)
	}
	if !strings.HasSuffix(findings[0].Pos.Filename, "fixture.go") {
		t.Errorf("Pos.Filename = %q, want fixture.go", findings[0].Pos.Filename)
	}
}

func TestScanFile_doubleQuotedSQL_handled(t *testing.T) {
	// Most repo SQL uses backticks but some uses double-quoted strings.
	src := headerOK + "var _ = func(db DB, ctx context.Context) { db.Query(ctx, \"SELECT id FROM users WHERE email = $1\", \"a\") }\n"
	dir := writeGoFixture(t, src)
	findings, _ := scanDir(dir)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (double-quoted SQL should be detected): %+v", len(findings), findings)
	}
}

func TestScanFile_invalidGoFile_skipsGracefully(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.go"), []byte("not go at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := scanDir(dir)
	if err != nil {
		t.Fatalf("scanDir returned error for invalid file; want graceful skip: %v", err)
	}
	if findings != nil && len(findings) != 0 {
		t.Fatalf("got %d findings on invalid file, want 0: %+v", len(findings), findings)
	}
}
