package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV242PamWatermarkShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 242 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 242 is not registered")
	}
	if !strings.Contains(mig.UpSQL, "ALTER TABLE org_pam_policy ADD COLUMN IF NOT EXISTS watermark_internal BOOLEAN NOT NULL DEFAULT false") {
		t.Error("v242 up does not add watermark_internal defaulting to false")
	}
	if !strings.Contains(mig.DownSQL, "DROP COLUMN IF EXISTS watermark_internal") {
		t.Error("v242 down does not drop it")
	}
}
