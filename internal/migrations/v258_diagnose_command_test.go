package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV258DiagnoseCommandShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 258 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 258 is not registered")
	}
	if !strings.Contains(mig.UpSQL, "'update_now', 'uninstall', 'diagnose')") ||
		!strings.Contains(mig.UpSQL, "ADD CONSTRAINT agent_commands_kind_check") {
		t.Error("v258 up does not replace the kind check with one that admits diagnose")
	}
	if !strings.Contains(mig.DownSQL, "DELETE FROM agent_commands WHERE kind = 'diagnose'") ||
		!strings.Contains(mig.DownSQL, "'update_now', 'uninstall'))") {
		t.Error("v258 down does not remove diagnose rows and restore the old check")
	}
}
