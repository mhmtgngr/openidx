// Package migrations_test, not migrations, so that it can reach
// adminPoolOrSkip in least_privilege_owner_test.go.
package migrations_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV215EndsAnExternalUsersGrantsWithTheAccount applies v215 and writes
// grants to an external user and to an internal one through each table the
// trigger guards: a grant with no end and one ending after the account are
// cut to the account's end, one ending before it is left alone, and the
// internal user's grants are never touched. Then the account's end moves:
// later, and no grant follows it; earlier, and every grant past the new end is
// cut to it. Rolling back removes both triggers.
func TestV215EndsAnExternalUsersGrantsWithTheAccount(t *testing.T) {
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
	if err := m.MigrateTo(ctx, 215); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var org string
	if err := pool.QueryRow(ctx, "SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1").Scan(&org); err != nil {
		t.Fatalf("read the oldest org: %v", err)
	}
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	internal := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1::uuid, 'v215-internal', 'i@example.test') RETURNING id::text`, org)
	vendor := scalar(`INSERT INTO vendor_organizations (org_id, name) VALUES ($1::uuid, 'v215 vendor') RETURNING id::text`, org)
	accountEnd := time.Now().UTC().Add(10 * 24 * time.Hour).Truncate(time.Second)
	external := scalar(`
		INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
		VALUES ($1::uuid, 'v215-external', 'e@supplier.example.test', 'external', $2::uuid, $3::uuid, $4)
		RETURNING id::text`, org, vendor, internal, accountEnd)
	role := scalar(`SELECT id::text FROM roles WHERE name = 'user' AND org_id = $1::uuid`, org)
	adminRole := scalar(`SELECT id::text FROM roles WHERE name = 'admin' AND org_id = $1::uuid`, org)
	entry := scalar(`INSERT INTO pam_entries (org_id, name, entry_type, url) VALUES ($1::uuid, 'v215 site', 'website', 'https://site.example.test') RETURNING id::text`, org)
	secret := scalar(`INSERT INTO vault_secrets (org_id, name, type) VALUES ($1::uuid, 'v215 secret', 'password') RETURNING id::text`, org)

	later := accountEnd.Add(30 * 24 * time.Hour)
	earlier := accountEnd.Add(-24 * time.Hour)
	ends := func(q string, args ...interface{}) *time.Time {
		t.Helper()
		var v *time.Time
		if err := pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	same := func(got *time.Time, want time.Time) bool { return got != nil && got.Equal(want) }

	// user_roles
	if _, err := pool.Exec(ctx, `INSERT INTO user_roles (user_id, role_id, org_id, expires_at) VALUES ($1::uuid, $2::uuid, $3::uuid, NULL)`,
		external, role, org); err != nil {
		t.Fatal(err)
	}
	if got := ends(`SELECT expires_at FROM user_roles WHERE user_id = $1::uuid`, external); !same(got, accountEnd) {
		t.Errorf("a role with no end for an external user ends %v, want the account's %v", got, accountEnd)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO user_roles (user_id, role_id, org_id, expires_at) VALUES ($1::uuid, $2::uuid, $3::uuid, $4)`,
		internal, adminRole, org, later); err != nil {
		t.Fatal(err)
	}
	if got := ends(`SELECT expires_at FROM user_roles WHERE user_id = $1::uuid`, internal); !same(got, later) {
		t.Errorf("an internal user's role was changed to end %v", got)
	}

	// pam_entry_grants
	grant := func(principal string, until interface{}) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions, expires_at)
			VALUES ($1::uuid, $2::uuid, 'user', $3, '{connect}', $4)
			ON CONFLICT (entry_id, principal_type, principal_id) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
			org, entry, principal, until); err != nil {
			t.Fatal(err)
		}
	}
	grant(external, later)
	if got := ends(`SELECT expires_at FROM pam_entry_grants WHERE principal_id = $1`, external); !same(got, accountEnd) {
		t.Errorf("a PAM grant past the account ends %v, want %v", got, accountEnd)
	}
	grant(external, earlier)
	if got := ends(`SELECT expires_at FROM pam_entry_grants WHERE principal_id = $1`, external); !same(got, earlier) {
		t.Errorf("a PAM grant ending before the account was changed to %v, want %v", got, earlier)
	}
	grant(internal, nil)
	if got := ends(`SELECT expires_at FROM pam_entry_grants WHERE principal_id = $1`, internal); got != nil {
		t.Errorf("an internal user's PAM grant was given an end: %v", got)
	}

	// vault_access_grants
	if _, err := pool.Exec(ctx, `INSERT INTO vault_access_grants (org_id, secret_id, principal_type, principal_id, actions)
		VALUES ($1::uuid, $2::uuid, 'user', $3::uuid, '{use}')`, org, secret, external); err != nil {
		t.Fatal(err)
	}
	if got := ends(`SELECT expires_at FROM vault_access_grants WHERE principal_id = $1::uuid`, external); !same(got, accountEnd) {
		t.Errorf("a vault grant with no end for an external user ends %v, want %v", got, accountEnd)
	}

	// The account's end moves. Later: no grant moves with it. Earlier: every
	// grant past the new end is cut to it, and one ending before it is not.
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
	}
	entry2 := scalar(`INSERT INTO pam_entries (org_id, name, entry_type, url) VALUES ($1::uuid, 'v215 site 2', 'website', 'https://site2.example.test') RETURNING id::text`, org)
	exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions, expires_at)
		VALUES ($1::uuid, $2::uuid, 'user', $3, '{connect}', NULL)`, org, entry2, external)
	exec(`UPDATE users SET account_expires_at = $2 WHERE id = $1::uuid`, external, later)
	if got := ends(`SELECT expires_at FROM user_roles WHERE user_id = $1::uuid`, external); !same(got, accountEnd) {
		t.Errorf("extending the account moved its role's end to %v, want it left at %v", got, accountEnd)
	}
	shorter := accountEnd.Add(-12 * time.Hour) // still after the PAM grant that ends a day before the account
	exec(`UPDATE users SET account_expires_at = $2 WHERE id = $1::uuid`, external, shorter)
	for what, q := range map[string]string{
		"role":              `SELECT expires_at FROM user_roles WHERE user_id = $1::uuid`,
		"vault grant":       `SELECT expires_at FROM vault_access_grants WHERE principal_id = $1::uuid`,
		"PAM grant past it": `SELECT expires_at FROM pam_entry_grants WHERE principal_id = $1 AND entry_id = '` + entry2 + `'::uuid`,
	} {
		if got := ends(q, external); !same(got, shorter) {
			t.Errorf("after the account was shortened its %s ends %v, want the new end %v", what, got, shorter)
		}
	}
	if got := ends(`SELECT expires_at FROM pam_entry_grants WHERE principal_id = $1 AND entry_id = '`+entry+`'::uuid`, external); !same(got, earlier) {
		t.Errorf("a PAM grant ending before the new end was changed to %v, want %v", got, earlier)
	}
	if got := ends(`SELECT expires_at FROM user_roles WHERE user_id = $1::uuid`, internal); !same(got, later) {
		t.Errorf("shortening an external account changed an internal user's role to end %v", got)
	}

	if err := m.RollbackTo(ctx, 214); err != nil {
		t.Fatalf("roll back: %v", err)
	}
	if n := scalar(`SELECT count(*)::text FROM pg_proc WHERE proname IN ('external_grant_window', 'external_account_end_moved')`); n != "0" {
		t.Error("after rollback a trigger function is still there")
	}
}
