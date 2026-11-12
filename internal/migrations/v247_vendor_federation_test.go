package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV247VendorFederationShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 247 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 247 is not registered")
	}
	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS onboarding_mode VARCHAR(16) NOT NULL DEFAULT 'invitation' CHECK (onboarding_mode IN ('invitation','federated','both'))",
		"ADD COLUMN IF NOT EXISTS idp_id UUID REFERENCES identity_providers(id) ON DELETE SET NULL",
		"ADD COLUMN IF NOT EXISTS sliding_expiry BOOLEAN NOT NULL DEFAULT false",
		"ADD COLUMN IF NOT EXISTS default_group_ids UUID[] NOT NULL DEFAULT '{}'",
		"ADD CONSTRAINT vendor_federated_needs_sponsor CHECK (onboarding_mode = 'invitation' OR default_sponsor_user_id IS NOT NULL)",
		"CREATE INDEX IF NOT EXISTS idx_vendor_organizations_idp_id ON vendor_organizations (idp_id)",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v247 up lacks %q", want)
		}
	}
	if strings.Contains(mig.UpSQL, "DO $$") {
		t.Error("v247 uses a DO block, which the runner cannot split")
	}
	for _, col := range []string{"onboarding_mode", "idp_id", "sliding_expiry", "default_group_ids"} {
		if !strings.Contains(mig.DownSQL, "DROP COLUMN IF EXISTS "+col) {
			t.Errorf("v247 down does not drop %s", col)
		}
	}
}
