package migrations

import (
	"strings"
	"testing"
)

// TestMigrationV239PamSessionChannelsShape pins v239: five columns on
// pam_entries with safe defaults for a new entry, a check on the mode, the
// upgrade keeping every existing entry's behaviour, and a down that undoes it.
func TestMigrationV239PamSessionChannelsShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 239 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 239 is not registered")
	}
	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS rdp_cert_mode VARCHAR(10) NOT NULL DEFAULT 'verify'",
		"ADD COLUMN IF NOT EXISTS rdp_cert_fingerprints TEXT[] NOT NULL DEFAULT '{}'",
		"ADD COLUMN IF NOT EXISTS allow_copy BOOLEAN NOT NULL DEFAULT true",
		"ADD COLUMN IF NOT EXISTS allow_paste BOOLEAN NOT NULL DEFAULT true",
		"ADD COLUMN IF NOT EXISTS allow_file_transfer BOOLEAN NOT NULL DEFAULT false",
		"CHECK (rdp_cert_mode IN ('verify', 'pin', 'ignore'))",
		// Existing RDP entries keep what the broker did for them.
		"SET rdp_cert_mode = 'ignore'\n WHERE entry_type IN ('rdp', 'windows_app_host')",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v239 up lacks %q", want)
		}
	}
	if strings.Contains(mig.UpSQL, "CREATE TABLE") {
		t.Error("v239 adds columns only")
	}
	for _, col := range []string{"rdp_cert_mode", "rdp_cert_fingerprints", "allow_copy", "allow_paste", "allow_file_transfer"} {
		if !strings.Contains(mig.DownSQL, "DROP COLUMN IF EXISTS "+col) {
			t.Errorf("v239 down does not drop %s", col)
		}
	}
}
