package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV260AgenticProviderShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 260 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 260 is not registered")
	}
	for _, want := range []string{
		"CHECK (provider IN ('none', 'anthropic', 'openai_compat'))",
		"CHECK (redaction IN ('off', 'mask', 'strict'))",
		"CHECK (provider <> 'anthropic' OR (cloud_consent_at IS NOT NULL AND redaction <> 'off'))",
		"api_key_enc      TEXT         NOT NULL DEFAULT ''",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v260 up lacks %q", want)
		}
	}
	if !strings.Contains(mig.DownSQL, "DROP COLUMN IF EXISTS provider") || strings.Contains(mig.UpSQL, "DO $$") {
		t.Error("v260 down does not drop its columns, or up uses DO $$")
	}
}
