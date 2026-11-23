package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV266LoginAddressesShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 266 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 266 is not registered")
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS user_login_addresses",
		"REFERENCES users(id) ON DELETE CASCADE",
		"CHECK (address = lower(btrim(address)) AND address LIKE '%@%')",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_user_login_addresses_org_address ON user_login_addresses (org_id, address)",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE  ROW LEVEL SECURITY",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON user_login_addresses TO openidx_app",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v266 up lacks %q", want)
		}
	}
	if !strings.Contains(mig.DownSQL, "DROP TABLE IF EXISTS user_login_addresses") {
		t.Error("v266 down does not drop the table")
	}
	if strings.Contains(mig.UpSQL, "DO $$") || strings.Contains(mig.DownSQL, "DO $$") {
		t.Error("a migration may not use DO $$ (the splitter cannot handle it)")
	}
}
