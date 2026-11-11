package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV249SitesShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 249 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 249 is not registered")
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS sites",
		"slug ~ '^[a-z0-9][a-z0-9-]{0,38}$'",
		"idx_sites_single_default ON sites ((is_default)) WHERE is_default",
		"VALUES ('default', 'Default site', true)",
		"CREATE TABLE IF NOT EXISTS site_routers",
		"REFERENCES sites(id) ON DELETE RESTRICT",
		"ALTER TABLE network_targets ADD COLUMN IF NOT EXISTS site_id",
		"ALTER TABLE proxy_routes    ADD COLUMN IF NOT EXISTS site_id",
		"ON sites        TO openidx_app",
		"ON site_routers TO openidx_app",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v249 up lacks %q", want)
		}
	}
	if strings.Contains(mig.UpSQL, "ROW LEVEL SECURITY") {
		t.Error("sites are platform tables; v249 must not enable RLS")
	}
	for _, want := range []string{"DROP TABLE IF EXISTS sites", "DROP TABLE IF EXISTS site_routers", "DROP COLUMN IF EXISTS site_id"} {
		if !strings.Contains(mig.DownSQL, want) {
			t.Errorf("v249 down lacks %q", want)
		}
	}
}
