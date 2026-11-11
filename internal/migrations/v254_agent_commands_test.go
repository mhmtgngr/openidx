package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV254AgentCommandsShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 254 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 254 is not registered")
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS agent_commands",
		"'restart', 'collect_logs', 'reenroll', 'set_options', 'update_now', 'uninstall'",
		"'queued', 'delivered', 'done', 'failed', 'expired', 'cancelled'",
		"octet_length(artifact) <= 8388608",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON agent_commands TO openidx_app",
		"FORCE  ROW LEVEL SECURITY",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v254 up lacks %q", want)
		}
	}
	if !strings.Contains(mig.DownSQL, "DROP TABLE IF EXISTS agent_commands") {
		t.Error("v254 down does not drop the table")
	}
}
