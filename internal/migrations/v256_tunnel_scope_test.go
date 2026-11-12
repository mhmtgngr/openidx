package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV256TunnelScopeShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 256 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 256 is not registered")
	}
	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS tunnel_scope",
		"CHECK (tunnel_scope IN ('all', 'tagged', 'off'))",
		"tunnel_tags TEXT[] NOT NULL DEFAULT '{}'",
		"CASE WHEN always_on THEN 'all' ELSE 'off' END",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v256 up lacks %q", want)
		}
	}
	for _, want := range []string{"DROP COLUMN IF EXISTS tunnel_tags", "DROP COLUMN IF EXISTS tunnel_scope"} {
		if !strings.Contains(mig.DownSQL, want) {
			t.Errorf("v256 down lacks %q", want)
		}
	}
}
