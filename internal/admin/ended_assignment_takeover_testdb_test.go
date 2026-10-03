package admin

import (
	"encoding/json"
	"testing"
)

// A role (v223) or group membership (v224) whose window has ended stays until
// the expiry sweep deletes it. The console's bulk assign_role and
// add_to_group inserted with ON CONFLICT DO NOTHING, so for a user holding
// such a row they did nothing and reported success: the sweep then removed
// the row, and the user was left without the role or group the administrator
// had just given. Now they take the ended row over as standing, and leave a
// live one, time-bound or not, as it is.
func TestABulkGrantTakesOverAnEndedAssignment(t *testing.T) {
	f, cleanup := newAttFixture(t)
	if f == nil {
		return
	}
	defer cleanup()
	org := f.orgA
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := f.db.Pool.QueryRow(f.ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	role := scalar(`INSERT INTO roles (name, description, org_id) VALUES ('to-bulk-role', 'seeded', $1::uuid) RETURNING id::text`, org)
	group := scalar(`INSERT INTO groups (name, org_id) VALUES ('to-bulk-group', $1::uuid) RETURNING id::text`, org)
	ended, live := f.seedUser("to-ended", org, true), f.seedUser("to-live", org, true)
	for _, u := range []struct{ id, ends string }{{ended, "-5 minutes"}, {live, "1 hour"}} {
		scalar(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at) VALUES ($1::uuid, $2::uuid, $3::uuid, NOW() + $4::interval)
			RETURNING user_id::text`, u.id, role, org, u.ends)
		scalar(`INSERT INTO group_memberships (user_id, group_id, org_id, expires_at) VALUES ($1::uuid, $2::uuid, $3::uuid, NOW() + $4::interval)
			RETURNING user_id::text`, u.id, group, org, u.ends)
	}
	bulk := func(opType, param, value string, ids ...string) {
		t.Helper()
		params, _ := json.Marshal(map[string]string{param: value})
		op := scalar(`INSERT INTO bulk_operations (type, status, total_items, parameters, org_id)
			VALUES ($1, 'running', $2, $3, $4::uuid) RETURNING id::text`, opType, len(ids), params, org)
		f.svc.executeBulkOperation(org, op, opType, ids, params)
	}
	bulk("assign_role", "role_id", role, ended, live)
	bulk("add_to_group", "group_id", group, ended, live)

	window := func(table, col, id, userID string) string {
		t.Helper()
		return scalar(`SELECT CASE WHEN expires_at IS NULL THEN 'standing' WHEN expires_at > NOW() THEN 'live' ELSE 'ended' END
			FROM `+table+` WHERE user_id = $1::uuid AND `+col+` = $2::uuid`, userID, id)
	}
	for _, c := range []struct{ what, table, col, id, user, want string }{
		{"the ended role", "user_roles", "role_id", role, ended, "standing"},
		{"the ended membership", "group_memberships", "group_id", group, ended, "standing"},
		{"the live role", "user_roles", "role_id", role, live, "live"},
		{"the live membership", "group_memberships", "group_id", group, live, "live"},
	} {
		if got := window(c.table, c.col, c.id, c.user); got != c.want {
			t.Errorf("after the bulk grant %s is %s; want %s", c.what, got, c.want)
		}
	}
}
