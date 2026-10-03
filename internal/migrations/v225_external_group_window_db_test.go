package migrations_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV225HoldsAnExternalUsersGroupsToTheAccount applies v225 over a database
// holding group memberships written before it:
//
//   - the backfill caps an external user's standing membership at the
//     account's end, and leaves an internal user's standing;
//   - a membership written afterwards for the external user, standing or
//     with a later window, ends at the account's end, and an earlier window
//     stays;
//   - moving the account's end earlier cuts the memberships to it;
//   - rolling back drops the trigger and keeps the windows.
func TestV225HoldsAnExternalUsersGroupsToTheAccount(t *testing.T) {
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
	if err := m.MigrateTo(ctx, 224); err != nil {
		t.Fatalf("migrate to 224: %v", err)
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
	group := func(name string) string {
		return scalar(`INSERT INTO groups (org_id, name, external_allowed) VALUES ($1::uuid, $2, true) RETURNING id::text`, org, name)
	}
	join := func(userID, groupID string, end *time.Time) {
		exec(`INSERT INTO group_memberships (user_id, group_id, org_id, expires_at) VALUES ($1::uuid, $2::uuid, $3::uuid, $4)`, userID, groupID, org, end)
	}
	ends := func(userID, groupID string) *time.Time {
		t.Helper()
		var v *time.Time
		if err := pool.QueryRow(ctx, `SELECT expires_at FROM group_memberships WHERE user_id = $1::uuid AND group_id = $2::uuid`,
			userID, groupID).Scan(&v); err != nil {
			t.Fatalf("read the membership: %v", err)
		}
		return v
	}
	check := func(what string, got, want *time.Time) {
		t.Helper()
		switch {
		case want == nil && got != nil:
			t.Errorf("%s ends at %v; want standing", what, got)
		case want != nil && (got == nil || !got.Equal(*want)):
			t.Errorf("%s ends at %v; want %v", what, got, *want)
		}
	}

	accountEnd := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	vendor := scalar(`INSERT INTO vendor_organizations (org_id, name, contract_end) VALUES ($1::uuid, 'v225 vendor', '2099-12-31') RETURNING id::text`, org)
	sponsor := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1::uuid, 'v225-sponsor', 's@example.test') RETURNING id::text`, org)
	external := scalar(`INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
		VALUES ($1::uuid, 'v225-external', 'e@supplier.example.test', 'external', $2::uuid, $3::uuid, $4) RETURNING id::text`,
		org, vendor, sponsor, accountEnd)
	internal := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1::uuid, 'v225-internal', 'i@example.test') RETURNING id::text`, org)
	before, standing, later, earlier := group("v225-before"), group("v225-standing"), group("v225-later"), group("v225-earlier")
	join(external, before, nil)
	join(internal, before, nil)

	if err := m.MigrateTo(ctx, 225); err != nil {
		t.Fatalf("migrate to 225: %v", err)
	}
	check("an external user's membership held before v225", ends(external, before), &accountEnd)
	check("an internal user's standing membership", ends(internal, before), nil)

	laterEnd, earlierEnd := accountEnd.Add(48*time.Hour), accountEnd.Add(-12*time.Hour)
	join(external, standing, nil)
	join(external, later, &laterEnd)
	join(external, earlier, &earlierEnd)
	check("a standing membership written for the external user", ends(external, standing), &accountEnd)
	check("a membership with a window past the account's end", ends(external, later), &accountEnd)
	check("a membership with a window before the account's end", ends(external, earlier), &earlierEnd)

	moved := accountEnd.Add(-18 * time.Hour)
	exec(`UPDATE users SET account_expires_at = $2 WHERE id = $1::uuid`, external, moved)
	check("after the account's end moved earlier, a membership", ends(external, standing), &moved)
	check("after the account's end moved earlier, the earlier window", ends(external, earlier), &moved)

	if err := m.RollbackTo(ctx, 224); err != nil {
		t.Fatalf("roll back to 224: %v", err)
	}
	if got := scalar(`SELECT count(*)::text FROM pg_trigger WHERE tgname = 'trg_group_memberships_external_window'`); got != "0" {
		t.Errorf("after the rollback the group_memberships trigger is still there")
	}
	check("after the rollback, a capped membership", ends(external, standing), &moved)
	after := group("v225-after-rollback")
	join(external, after, nil)
	check("a membership written after the rollback", ends(external, after), nil)
}
