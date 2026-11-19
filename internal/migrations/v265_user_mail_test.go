package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV265UserMailShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 265 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 265 is not registered")
	}
	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS mail VARCHAR(255)",
		"idx_users_org_lower_username ON users (org_id, lower(username))",
		"idx_users_org_lower_email ON users (org_id, lower(email))",
		"idx_users_org_lower_mail ON users (org_id, lower(mail))",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v265 up lacks %q", want)
		}
	}
	// mail is a second address, not an identity: a shared mailbox may be on two
	// accounts, so it must not be unique.
	if strings.Contains(strings.ToUpper(mig.UpSQL), "UNIQUE") {
		t.Error("v265 makes something unique; users.mail must not be")
	}
	for _, want := range []string{"DROP COLUMN IF EXISTS mail", "DROP INDEX IF EXISTS idx_users_org_lower_mail"} {
		if !strings.Contains(mig.DownSQL, want) {
			t.Errorf("v265 down lacks %q", want)
		}
	}
	if strings.Contains(mig.UpSQL, "DO $$") || strings.Contains(mig.DownSQL, "DO $$") {
		t.Error("a migration may not use DO $$ (the splitter cannot handle it)")
	}
}
