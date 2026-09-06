package migrations

import (
	"os"
	"strings"
	"testing"
)

// v178 removes a fixture, so what matters is that it removes only the fixture.
// The row is v10 starter data -- pending, dated Q1 2026, assigned to the seeded
// admin -- and once the overdue-review query was corrected to use end_date it
// became a permanent "1 access review overdue" on every install's SOC 2 report:
// a finding no operator created and none can close by doing their job.
func TestMigrationV178_retiresOnlyTheUntouchedFixture(t *testing.T) {
	m := migrationByVersion(t, 178)
	if m.Name != "retire_seeded_access_review" {
		t.Errorf("v178 Name = %q, want retire_seeded_access_review", m.Name)
	}

	// The guards are the whole point: an install where somebody actually ran
	// this campaign -- completed it, or moved its dates -- keeps the row.
	for _, guard := range []string{
		"id = '70000000-0000-0000-0000-000000000001'",
		"status = 'pending'",
		"start_date::date = DATE '2026-01-01'",
		"end_date::date   = DATE '2026-03-31'",
	} {
		if !strings.Contains(m.UpSQL, guard) {
			t.Errorf("v178 deletes without the guard %q", guard)
		}
	}
	if strings.Contains(m.UpSQL, "DELETE FROM access_reviews\nWHERE id = '70000000-0000-0000-0000-000000000001';") {
		t.Error("v178 deletes the row unconditionally")
	}
	// One row, by id. A DELETE over this table without an id would be an
	// erasure of an operator's campaigns.
	if strings.Count(m.UpSQL, "DELETE FROM") != 1 {
		t.Errorf("v178 issues %d DELETEs, want exactly 1", strings.Count(m.UpSQL, "DELETE FROM"))
	}

	if !strings.Contains(m.DownSQL, "'Q1 2026 Access Review'") ||
		!strings.Contains(m.DownSQL, "ON CONFLICT (id) DO NOTHING") {
		t.Error("v178 Down does not restore v10's row as v10 wrote it")
	}
}

// The correction that made this migration necessary must stay corrected: a
// later edit putting due_date back would restore the silent zero and leave the
// fixture deleted for nothing.
func TestOverdueReviewsUsesEndDate(t *testing.T) {
	src := mustReadFile(t, "../audit/compliance.go")
	if strings.Contains(src, "due_date < NOW()") {
		t.Error("the overdue-review count reads access_reviews.due_date, " +
			"a column the table does not have; the count silently reads 0")
	}
	if !strings.Contains(src, "status = 'pending' AND end_date < NOW()") {
		t.Error("the overdue-review count no longer measures anything")
	}
}

// mustReadFile reads a source file the migration's reasoning depends on.
func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
