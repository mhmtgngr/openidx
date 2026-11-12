package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV248EAMSigningKeysShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 248 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 248 is not registered")
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS eam_signing_keys",
		"kid             VARCHAR(64) NOT NULL UNIQUE",
		"private_key_enc TEXT NOT NULL",
		"cert_pem        TEXT NOT NULL",
		"not_before      TIMESTAMPTZ NOT NULL",
		"not_after       TIMESTAMPTZ NOT NULL",
		"active          BOOLEAN NOT NULL DEFAULT false",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON eam_signing_keys TO openidx_app",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v248 up lacks %q", want)
		}
	}
	if strings.Contains(mig.UpSQL, "DO $$") {
		t.Error("v248 uses a DO block, which the runner cannot split")
	}
	if strings.Contains(mig.UpSQL, "org_id") {
		t.Error("eam_signing_keys is platform level; it must not carry org_id")
	}
	if !strings.Contains(mig.DownSQL, "DROP TABLE IF EXISTS eam_signing_keys") {
		t.Error("v248 down does not drop the table")
	}
}
