package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV255PostureCheckTagsShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 255 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 255 is not registered")
	}
	if !strings.Contains(mig.UpSQL, "posture_checks ADD COLUMN IF NOT EXISTS tags JSONB") {
		t.Error("v255 up does not add posture_checks.tags")
	}
	if !strings.Contains(mig.DownSQL, "DROP COLUMN IF EXISTS tags") {
		t.Error("v255 down does not drop it")
	}
}

// The fleet migrations of this series are contiguous: 250..256, no gap.
func TestFleetMigrationsAreContiguous(t *testing.T) {
	seen := map[int]bool{}
	for _, m := range allMigrations() {
		seen[m.Version] = true
	}
	for v := 250; v <= 256; v++ {
		if !seen[v] {
			t.Errorf("migration %d is missing", v)
		}
	}
}
