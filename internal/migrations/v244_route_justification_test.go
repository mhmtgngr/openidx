package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV244RouteJustificationShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 244 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 244 is not registered")
	}
	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS require_justification BOOLEAN NOT NULL DEFAULT false",
		"ADD COLUMN IF NOT EXISTS justification_ttl_minutes INTEGER NOT NULL DEFAULT 480",
		"BETWEEN 5 AND 1440",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v244 up lacks %q", want)
		}
	}
	for _, want := range []string{"DROP COLUMN IF EXISTS require_justification", "DROP COLUMN IF EXISTS justification_ttl_minutes"} {
		if !strings.Contains(mig.DownSQL, want) {
			t.Errorf("v244 down lacks %q", want)
		}
	}
}
