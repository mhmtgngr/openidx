package migrations_test

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV239KeepsWhatEveryExistingEntryDid applies v239 over entries made under
// v238 and checks that no session changes on upgrade: an RDP entry (the broker
// wrote ignore-cert on it) is 'ignore', an SSH entry is 'verify', an entry
// whose settings opened a drive or SFTP keeps file transfer, one whose
// settings closed the clipboard keeps it closed, and an entry with nothing
// set gets the defaults. A new entry after the upgrade verifies its
// certificate and has no file transfer, the check refuses an unknown mode,
// and rolling back drops the columns.
func TestV239KeepsWhatEveryExistingEntryDid(t *testing.T) {
	db, _, cleanup := adminPoolOrSkip(t)
	defer cleanup()
	ctx := context.Background()
	pool := db.Pool

	for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("reset schema (%s): %v", stmt, err)
		}
	}
	m := migrations.NewMigrator(pool.Raw(), zap.NewNop())
	if err := m.MigrateTo(ctx, 238); err != nil {
		t.Fatalf("migrate to the version before it: %v", err)
	}
	var org string
	if err := pool.QueryRow(ctx,
		"SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1").Scan(&org); err != nil {
		t.Fatalf("read the oldest org: %v", err)
	}
	seed := func(name, entryType, settings string) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO pam_entries (org_id, name, entry_type, hostname, settings)
			VALUES ($1::uuid, $2, $3, 'h.example.test', $4::jsonb) RETURNING id::text`,
			org, name, entryType, settings).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		return id
	}
	rdp := seed("v239-rdp", "rdp", `{}`)
	appHost := seed("v239-apphost", "windows_app_host", `{}`)
	ssh := seed("v239-ssh", "ssh", `{}`)
	drive := seed("v239-drive", "rdp", `{"enable-drive":"true","drive-path":"/srv"}`)
	sftp := seed("v239-sftp", "ssh", `{"enable-sftp":"TRUE"}`)
	noClip := seed("v239-noclip", "rdp", `{"disable-copy":"true","disable-paste":"true"}`)

	if err := m.MigrateTo(ctx, 239); err != nil {
		t.Fatalf("migrate to 239: %v", err)
	}
	type pol struct {
		mode              string
		copy, paste, file bool
	}
	read := func(id string) pol {
		t.Helper()
		var p pol
		if err := pool.QueryRow(ctx, `SELECT rdp_cert_mode, allow_copy, allow_paste, allow_file_transfer
			FROM pam_entries WHERE id = $1::uuid`, id).Scan(&p.mode, &p.copy, &p.paste, &p.file); err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		return p
	}
	for name, tc := range map[string]struct {
		id   string
		want pol
	}{
		"rdp":       {rdp, pol{"ignore", true, true, false}},
		"app host":  {appHost, pol{"ignore", true, true, false}},
		"ssh":       {ssh, pol{"verify", true, true, false}},
		"drive":     {drive, pol{"ignore", true, true, true}},
		"sftp":      {sftp, pol{"verify", true, true, true}},
		"clip shut": {noClip, pol{"ignore", false, false, false}},
	} {
		if got := read(tc.id); got != tc.want {
			t.Errorf("%s after upgrade = %+v, want %+v", name, got, tc.want)
		}
	}

	fresh := seed("v239-new", "rdp", `{}`)
	if got := read(fresh); got != (pol{"verify", true, true, false}) {
		t.Errorf("a new RDP entry = %+v, want verify with clipboard and no file transfer", got)
	}
	if _, err := pool.Exec(ctx, `UPDATE pam_entries SET rdp_cert_mode = 'trust' WHERE id = $1::uuid`, fresh); err == nil {
		t.Error("the check accepted rdp_cert_mode 'trust'")
	}

	if err := m.RollbackTo(ctx, 238); err != nil {
		t.Fatalf("roll back to 238: %v", err)
	}
	var cols int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_name = 'pam_entries' AND column_name IN
		('rdp_cert_mode','rdp_cert_fingerprints','allow_copy','allow_paste','allow_file_transfer')`).Scan(&cols); err != nil {
		t.Fatalf("read columns: %v", err)
	}
	if cols != 0 {
		t.Errorf("%d policy columns survive the rollback", cols)
	}
	// And forward again, as an upgrade after a rollback would.
	if err := m.MigrateTo(ctx, 239); err != nil {
		t.Fatalf("migrate to 239 again: %v", err)
	}
}
