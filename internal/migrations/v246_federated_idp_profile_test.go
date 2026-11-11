package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV246FederatedIdPProfileShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 246 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 246 is not registered")
	}
	for _, want := range []string{
		"ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS discovery_url",
		"ADD COLUMN IF NOT EXISTS use_pkce BOOLEAN NOT NULL DEFAULT true",
		"ADD COLUMN IF NOT EXISTS trust_upstream_mfa BOOLEAN NOT NULL DEFAULT false",
		"ADD COLUMN IF NOT EXISTS claims_mapping JSONB NOT NULL DEFAULT '{}'",
		"ADD COLUMN IF NOT EXISTS group_mapping JSONB NOT NULL DEFAULT '[]'",
		"ADD COLUMN IF NOT EXISTS jit_policy JSONB NOT NULL DEFAULT",
		"ADD COLUMN IF NOT EXISTS pass_through_params",
		"ADD COLUMN IF NOT EXISTS external_id_claim VARCHAR(32) NOT NULL DEFAULT 'sub'",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v246 up lacks %q", want)
		}
	}
	if strings.Contains(mig.UpSQL, "DO $$") {
		t.Error("v246 uses a DO block, which the runner cannot split")
	}
	for _, col := range []string{"discovery_url", "use_pkce", "trust_upstream_mfa", "claims_mapping", "group_mapping", "jit_policy", "pass_through_params", "external_id_claim"} {
		if !strings.Contains(mig.DownSQL, "DROP COLUMN IF EXISTS "+col) {
			t.Errorf("v246 down does not drop %s", col)
		}
	}
}
