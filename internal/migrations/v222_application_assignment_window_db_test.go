package migrations_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV222GivesAnApplicationAssignmentItsWindow applies v222 over a database
// holding assignments written before it:
//
//   - the backfill gives an assignment the latest window of the fulfilled
//     requests for its user and application, and leaves one no request made
//     standing;
//   - an external user's assignment ends no later than the account, on insert
//     and when an upsert moves its end, and is cut again when the account's end
//     moves earlier; an internal user's is never touched;
//   - rolling back drops the column and the trigger, and gives back v215's
//     functions with their own triggers.
func TestV222GivesAnApplicationAssignmentItsWindow(t *testing.T) {
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
	if err := m.MigrateTo(ctx, 221); err != nil {
		t.Fatalf("migrate to 221: %v", err)
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
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
	}
	app := func(name string) string {
		return scalar(`INSERT INTO applications (org_id, client_id, name, type) VALUES ($1::uuid, $2, $2, 'web') RETURNING id::text`, org, name)
	}
	internal := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1::uuid, 'v222-internal', 'i@example.test') RETURNING id::text`, org)
	requested, standing, vendorApp := app("v222-requested"), app("v222-standing"), app("v222-vendor")

	// Before v222: two fulfilled requests for one application, and its plain
	// assignment; an assignment no request made.
	first := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	second := first.Add(2 * time.Hour)
	for _, end := range []time.Time{first, second} {
		exec(`INSERT INTO access_requests (org_id, requester_id, resource_type, resource_id, resource_name, justification, status, expires_at)
			VALUES ($1::uuid, $2::uuid, 'application', $3::uuid, 'app', 'release', 'fulfilled', $4)`, org, internal, requested, end)
	}
	exec(`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid), ($1::uuid, $4::uuid, $3::uuid)`,
		internal, requested, org, standing)

	if err := m.MigrateTo(ctx, 222); err != nil {
		t.Fatalf("migrate to 222: %v", err)
	}
	ends := func(userID, appID string) *time.Time {
		t.Helper()
		var v *time.Time
		if err := pool.QueryRow(ctx, `SELECT expires_at FROM user_application_assignments WHERE user_id = $1::uuid AND application_id = $2::uuid`,
			userID, appID).Scan(&v); err != nil {
			t.Fatalf("read the assignment: %v", err)
		}
		return v
	}
	same := func(got *time.Time, want time.Time) bool { return got != nil && got.Equal(want) }

	if got := ends(internal, requested); !same(got, second) {
		t.Errorf("the backfill ended a requested assignment at %v, want the later request's %v", got, second)
	}
	if got := ends(internal, standing); got != nil {
		t.Errorf("the backfill gave an assignment no request made the end %v", got)
	}

	sponsor := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1::uuid, 'v222-sponsor', 's@example.test') RETURNING id::text`, org)
	vendor := scalar(`INSERT INTO vendor_organizations (org_id, name) VALUES ($1::uuid, 'v222 vendor') RETURNING id::text`, org)
	accountEnd := time.Now().UTC().Add(10 * 24 * time.Hour).Truncate(time.Second)
	external := scalar(`
		INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
		VALUES ($1::uuid, 'v222-external', 'e@supplier.example.test', 'external', $2::uuid, $3::uuid, $4)
		RETURNING id::text`, org, vendor, sponsor, accountEnd)

	exec(`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`, external, vendorApp, org)
	if got := ends(external, vendorApp); !same(got, accountEnd) {
		t.Errorf("an external user's standing assignment ends %v, want the account's %v", got, accountEnd)
	}
	exec(`INSERT INTO user_application_assignments (user_id, application_id, org_id, expires_at) VALUES ($1::uuid, $2::uuid, $3::uuid, $4)
		ON CONFLICT (user_id, application_id) DO UPDATE SET expires_at = EXCLUDED.expires_at`, external, vendorApp, org, accountEnd.Add(30*24*time.Hour))
	if got := ends(external, vendorApp); !same(got, accountEnd) {
		t.Errorf("an upsert moved an external user's assignment to %v, past the account's %v", got, accountEnd)
	}
	exec(`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`, internal, vendorApp, org)
	if got := ends(internal, vendorApp); got != nil {
		t.Errorf("an internal user's standing assignment was given the end %v", got)
	}

	earlier := accountEnd.Add(-3 * 24 * time.Hour)
	exec(`UPDATE users SET account_expires_at = $2 WHERE id = $1::uuid`, external, earlier)
	if got := ends(external, vendorApp); !same(got, earlier) {
		t.Errorf("the account's end moved to %v and the assignment still ends %v", earlier, got)
	}
	if got := ends(internal, vendorApp); got != nil {
		t.Errorf("an external account's end moved an internal user's assignment to %v", got)
	}

	if err := m.RollbackTo(ctx, 221); err != nil {
		t.Fatalf("roll back to 221: %v", err)
	}
	if n := scalar(`SELECT count(*)::text FROM information_schema.columns
		WHERE table_name = 'user_application_assignments' AND column_name = 'expires_at'`); n != "0" {
		t.Error("rolling back left the expires_at column")
	}
	if n := scalar(`SELECT count(*)::text FROM pg_trigger WHERE tgname = 'trg_user_app_assignments_external_window'`); n != "0" {
		t.Error("rolling back left the assignment trigger")
	}
	if n := scalar(`SELECT count(*)::text FROM pg_trigger WHERE tgname IN ('trg_user_roles_external_window',
		'trg_pam_entry_grants_external_window', 'trg_vault_access_grants_external_window', 'trg_users_external_account_end')`); n != "4" {
		t.Errorf("rolling back left %s of v215's four triggers", n)
	}
	if n := scalar(`SELECT count(*)::text FROM pg_proc WHERE proname IN ('external_grant_window', 'external_account_end_moved')
		AND prosrc NOT LIKE '%user_application_assignments%'`); n != "2" {
		t.Errorf("rolling back gave back %s of v215's two functions", n)
	}
}
