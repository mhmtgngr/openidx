package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/migrations"
)

// TestCreateMigrationWritesTheFileTheProductApplies pins the fix for a command
// whose entire output was inert.
//
// `openidx migrate create <name>` used to write migrations/NNN_<name>.up.sql
// and .down.sql. Nothing in this repository has ever read that directory: every
// service applies the registry in internal/migrations, whose SQL lives in Go
// constants. The loose tree stopped tracking the registry at 52 of 172
// migrations and nobody noticed, because a file nobody reads cannot go stale
// loudly. A contributor following the command wrote SQL that never ran, then
// saw `openidx migrate up` report success — it had applied the registry.
//
// The test therefore asserts both halves: the file it writes is the one the
// migrator reads, and it does not write into the old tree.
func TestCreateMigrationWritesTheFileTheProductApplies(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "internal", "migrations"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := &CommandContext{RootDir: root, NoColor: true}

	want := nextMigrationVersion()
	if want <= 1 {
		t.Fatalf("nextMigrationVersion() = %d — it is not reading the registry", want)
	}

	if err := createMigration(ctx, "add_widget_table"); err != nil {
		t.Fatalf("createMigration: %v", err)
	}

	created := filepath.Join(root, "internal", "migrations", "sql_v"+itoa(want)+".go")
	body, err := os.ReadFile(created)
	if err != nil {
		t.Fatalf("expected the migration at %s: %v", created, err)
	}
	src := string(body)

	for _, needle := range []string{
		"package migrations",
		"const addWidgetTableUp = ",
		"const addWidgetTableDown = ",
	} {
		if !strings.Contains(src, needle) {
			t.Errorf("generated file is missing %q:\n%s", needle, src)
		}
	}

	// The old tree must stay untouched. A command that still writes there is
	// the original defect, whatever else it also does.
	if _, err := os.Stat(filepath.Join(root, "migrations")); !os.IsNotExist(err) {
		t.Error("createMigration wrote into migrations/ — the directory nothing applies")
	}

	// Re-running must refuse rather than silently overwrite someone's work.
	if err := createMigration(ctx, "add_widget_table"); err == nil {
		t.Error("createMigration overwrote an existing migration file")
	}
}

// TestNextMigrationVersionFollowsTheRegistry: the number comes from what the
// services really apply, never from counting files in a directory. Counting
// files is how the old command produced 053 while the schema was at 172.
func TestNextMigrationVersionFollowsTheRegistry(t *testing.T) {
	highest := 0
	for _, m := range migrations.All() {
		if m.Version > highest {
			highest = m.Version
		}
	}
	if got := nextMigrationVersion(); got != highest+1 {
		t.Errorf("nextMigrationVersion() = %d, want %d (registry high-water %d)", got, highest+1, highest)
	}
}

func TestSQLConstIdent(t *testing.T) {
	cases := map[string]string{
		"add_widget_table":      "addWidgetTable",
		"ispm_ai_org_isolation": "ispmAiOrgIsolation",
		"widen-secret":          "widenSecret",
		"Already Spaced":        "alreadySpaced",
		"2fa_backup_codes":      "migration2faBackupCodes",
		"":                      "migration",
	}
	for in, want := range cases {
		if got := sqlConstIdent(in); got != want {
			t.Errorf("sqlConstIdent(%q) = %q, want %q", in, got, want)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
