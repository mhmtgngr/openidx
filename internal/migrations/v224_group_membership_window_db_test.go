package migrations_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV224GivesARequestedGroupItsWindow applies v224 over a database holding
// group memberships written before it:
//
//   - the backfill gives a membership the latest window of the fulfilled
//     requests for its user and group;
//   - it leaves standing a membership no request made and one whose request
//     ended (expired);
//   - rolling back drops the column.
func TestV224GivesARequestedGroupItsWindow(t *testing.T) {
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
	if err := m.MigrateTo(ctx, 223); err != nil {
		t.Fatalf("migrate to 223: %v", err)
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
		return scalar(`INSERT INTO groups (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`, org, name)
	}
	request := func(userID, groupID, status string, end time.Time) {
		exec(`INSERT INTO access_requests (org_id, requester_id, resource_type, resource_id, resource_name, justification, status, expires_at)
			VALUES ($1::uuid, $2::uuid, 'group', $3::uuid, 'group', 'release', $4, $5)`, org, userID, groupID, status, end)
	}
	join := func(userID, groupID string) {
		exec(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`, userID, groupID, org)
	}
	member := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1::uuid, 'v224-member', 'm@example.test') RETURNING id::text`, org)
	requested, standing, ended := group("v224-requested"), group("v224-standing"), group("v224-ended")

	first := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	second := first.Add(2 * time.Hour)
	request(member, requested, "fulfilled", first)
	request(member, requested, "fulfilled", second)
	join(member, requested)
	join(member, standing)
	request(member, ended, "expired", first)
	join(member, ended)

	if err := m.MigrateTo(ctx, 224); err != nil {
		t.Fatalf("migrate to 224: %v", err)
	}
	ends := func(groupID string) *time.Time {
		t.Helper()
		var v *time.Time
		if err := pool.QueryRow(ctx, `SELECT expires_at FROM group_memberships WHERE user_id = $1::uuid AND group_id = $2::uuid`,
			member, groupID).Scan(&v); err != nil {
			t.Fatalf("read the membership: %v", err)
		}
		return v
	}
	if got := ends(requested); got == nil || !got.Equal(second) {
		t.Errorf("a membership two fulfilled requests gave ends at %v; want %v", got, second)
	}
	if got := ends(standing); got != nil {
		t.Errorf("a membership no request gave ends at %v; want standing", got)
	}
	if got := ends(ended); got != nil {
		t.Errorf("a membership whose request expired ends at %v; want standing", got)
	}

	if err := m.RollbackTo(ctx, 223); err != nil {
		t.Fatalf("roll back to 223: %v", err)
	}
	if got := scalar(`SELECT count(*)::text FROM information_schema.columns
		WHERE table_name = 'group_memberships' AND column_name = 'expires_at'`); got != "0" {
		t.Errorf("after the rollback group_memberships still has expires_at")
	}
	if got := scalar(`SELECT count(*)::text FROM group_memberships WHERE user_id = $1::uuid`, member); got != "3" {
		t.Errorf("the rollback left %s of the three memberships", got)
	}
}
