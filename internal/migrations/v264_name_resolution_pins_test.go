package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV264NameResolutionPinsShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 264 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 264 is not registered")
	}
	for _, want := range []string{
		"name_resolution VARCHAR(16) NOT NULL DEFAULT 'tunnel'",
		"CHECK (name_resolution IN ('tunnel', 'agent'))",
		"ADD COLUMN IF NOT EXISTS pin_ip INET",
		"pin_ip << '100.127.0.0/16'::inet",
		"ON network_targets (org_id, pin_ip) WHERE pin_ip IS NOT NULL",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v264 up lacks %q", want)
		}
	}
	for _, want := range []string{
		"DROP COLUMN IF EXISTS pin_ip", "DROP COLUMN IF EXISTS name_resolution", "DROP INDEX IF EXISTS network_targets_org_pin_ip",
	} {
		if !strings.Contains(mig.DownSQL, want) {
			t.Errorf("v264 down lacks %q", want)
		}
	}
	if strings.Contains(mig.UpSQL, "DO $$") || strings.Contains(mig.DownSQL, "DO $$") {
		t.Error("a migration may not use DO $$ (the splitter cannot handle it)")
	}
}
