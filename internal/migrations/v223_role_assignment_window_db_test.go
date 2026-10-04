package migrations_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV223GivesARequestedRoleItsWindow applies v223 over a database holding
// role assignments written before it:
//
//   - the backfill gives an assignment the latest window of the fulfilled
//     requests for its user and role;
//   - it leaves alone an assignment no request made, one whose request ended
//     (expired), and one that already has a window;
//   - an external user's assignment it backfills still ends no later than the
//     account (v215's trigger);
//   - rolling back changes nothing.
func TestV223GivesARequestedRoleItsWindow(t *testing.T) {
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
	if err := m.MigrateTo(ctx, 222); err != nil {
		t.Fatalf("migrate to 222: %v", err)
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
	role := func(name string) string {
		return scalar(`INSERT INTO roles (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`, org, name)
	}
	request := func(userID, roleID, status string, end time.Time) {
		exec(`INSERT INTO access_requests (org_id, requester_id, resource_type, resource_id, resource_name, justification, status, expires_at)
			VALUES ($1::uuid, $2::uuid, 'role', $3::uuid, 'role', 'release', $4, $5)`, org, userID, roleID, status, end)
	}
	assign := func(userID, roleID string, end *time.Time) {
		exec(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at) VALUES ($1::uuid, $2::uuid, $3::uuid, $4)`, userID, roleID, org, end)
	}
	internal := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1::uuid, 'v223-internal', 'i@example.test') RETURNING id::text`, org)
	requested, standing, ended, timed := role("v223-requested"), role("v223-standing"), role("v223-ended"), role("v223-timed")

	// Before v223: two fulfilled requests for one role and its plain
	// assignment; an assignment no request made; one whose request expired;
	// one an administrator gave until a date, with a live request too.
	first := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	second := first.Add(2 * time.Hour)
	adminEnd := first.Add(24 * time.Hour)
	request(internal, requested, "fulfilled", first)
	request(internal, requested, "fulfilled", second)
	assign(internal, requested, nil)
	assign(internal, standing, nil)
	request(internal, ended, "expired", first)
	assign(internal, ended, nil)
	request(internal, timed, "fulfilled", first)
	assign(internal, timed, &adminEnd)

	// An external user whose account ends before their request's window.
	vendor := scalar(`INSERT INTO vendor_organizations (org_id, name, contract_end) VALUES ($1::uuid, 'v223 vendor', '2099-12-31') RETURNING id::text`, org)
	sponsor := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1::uuid, 'v223-sponsor', 's@example.test') RETURNING id::text`, org)
	accountEnd := first.Add(-time.Hour)
	external := scalar(`INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
		VALUES ($1::uuid, 'v223-external', 'e@supplier.example.test', 'external', $2::uuid, $3::uuid, $4) RETURNING id::text`,
		org, vendor, sponsor, accountEnd)
	userRole := scalar(`SELECT id::text FROM roles WHERE org_id = $1::uuid AND name = 'user'`, org)
	request(external, userRole, "fulfilled", first)
	assign(external, userRole, nil)
	// The trigger already held the plain row to the account's end; clear it
	// to the state a row written before v215 would be in.
	exec(`ALTER TABLE user_roles DISABLE TRIGGER trg_user_roles_external_window`)
	exec(`UPDATE user_roles SET expires_at = NULL WHERE user_id = $1::uuid`, external)
	exec(`ALTER TABLE user_roles ENABLE TRIGGER trg_user_roles_external_window`)

	if err := m.MigrateTo(ctx, 223); err != nil {
		t.Fatalf("migrate to 223: %v", err)
	}
	ends := func(userID, roleID string) *time.Time {
		t.Helper()
		var v *time.Time
		if err := pool.QueryRow(ctx, `SELECT expires_at FROM user_roles WHERE user_id = $1::uuid AND role_id = $2::uuid`,
			userID, roleID).Scan(&v); err != nil {
			t.Fatalf("read the assignment: %v", err)
		}
		return v
	}
	check := func(what string, got *time.Time, want *time.Time) {
		t.Helper()
		switch {
		case want == nil && got != nil:
			t.Errorf("%s ends at %v; want standing", what, got)
		case want != nil && (got == nil || !got.Equal(*want)):
			t.Errorf("%s ends at %v; want %v", what, got, *want)
		}
	}
	check("a role two fulfilled requests gave", ends(internal, requested), &second)
	check("a role no request gave", ends(internal, standing), nil)
	check("a role whose request expired", ends(internal, ended), nil)
	check("a role an administrator gave until a date", ends(internal, timed), &adminEnd)
	check("an external user's requested role", ends(external, userRole), &accountEnd)

	if err := m.RollbackTo(ctx, 222); err != nil {
		t.Fatalf("roll back to 222: %v", err)
	}
	if v, err := m.Version(ctx); err != nil || v != 222 {
		t.Fatalf("after the rollback the schema is at %d (%v); want 222", v, err)
	}
	check("after the rollback, the backfilled role", ends(internal, requested), &second)
	check("after the rollback, the standing role", ends(internal, standing), nil)
}
