package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV250FleetTokensAndTagsShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 250 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 250 is not registered")
	}
	for _, want := range []string{
		"agent_enrollment_tokens ADD COLUMN IF NOT EXISTS name",
		"ADD COLUMN IF NOT EXISTS max_uses",
		"ADD COLUMN IF NOT EXISTS uses         INTEGER NOT NULL DEFAULT 0",
		"ADD COLUMN IF NOT EXISTS default_tags TEXT[]",
		"ADD COLUMN IF NOT EXISTS last_used_at",
		"CHECK (expires_at <= created_at + INTERVAL '366 days') NOT VALID",
		"enrolled_agents ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}'",
		"ADD COLUMN IF NOT EXISTS enrolled_with_token_id UUID",
		"USING GIN (tags)",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v250 up lacks %q", want)
		}
	}
	for _, want := range []string{"DROP COLUMN IF EXISTS tags", "DROP COLUMN IF EXISTS default_tags", "DROP CONSTRAINT IF EXISTS chk_enrollment_token_ttl_max_one_year"} {
		if !strings.Contains(mig.DownSQL, want) {
			t.Errorf("v250 down lacks %q", want)
		}
	}
}
