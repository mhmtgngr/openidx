package migrations

import (
	"regexp"
	"strings"
	"testing"
)

// TestMigrationV185_refreshTokenAgentBinding pins the shape the code depends
// on: a nullable agent_id column sized like enrolled_agents.agent_id, a partial
// index for the revoke query, and a rollback that removes both. It also pins
// what the migration must NOT do -- backfill -- because a token issued before
// v185 has no device to be bound to, and inventing one would make the device
// revoke sever sessions that never ran on the device.
func TestMigrationV185_refreshTokenAgentBinding(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 185 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v185 not registered in allMigrations()")
	}
	if m.Name != "bind_refresh_tokens_to_agent" {
		t.Errorf("v185 Name = %q, want bind_refresh_tokens_to_agent", m.Name)
	}

	// The column: same width as enrolled_agents.agent_id (v43, VARCHAR(64)),
	// nullable, idempotent.
	if !regexp.MustCompile(`ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS agent_id VARCHAR\(64\);`).MatchString(m.UpSQL) {
		t.Error("v185 does not add oauth_refresh_tokens.agent_id VARCHAR(64) idempotently")
	}
	if regexp.MustCompile(`agent_id VARCHAR\(64\)\s+NOT NULL`).MatchString(m.UpSQL) {
		t.Error("v185 makes agent_id NOT NULL; an unbound token must stay representable")
	}
	// The index: partial, so the revoke's lookup by agent_id is cheap and the
	// (overwhelmingly NULL) console tokens are not indexed.
	if !regexp.MustCompile(`CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_agent\s+ON oauth_refresh_tokens \(agent_id\) WHERE agent_id IS NOT NULL;`).MatchString(m.UpSQL) {
		t.Error("v185 does not create the partial index on agent_id")
	}
	// No backfill.
	if strings.Contains(strings.ToUpper(m.UpSQL), "UPDATE ") {
		t.Error("v185 backfills agent_id; a pre-v185 token has no device to be bound to")
	}

	for _, frag := range []string{
		"DROP INDEX IF EXISTS idx_oauth_refresh_tokens_agent;",
		"ALTER TABLE oauth_refresh_tokens DROP COLUMN IF EXISTS agent_id;",
	} {
		if !strings.Contains(m.DownSQL, frag) {
			t.Errorf("v185 DownSQL missing %q", frag)
		}
	}
}
