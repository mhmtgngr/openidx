package provisioning

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// A role (v223) or group membership (v224) whose window has ended stays until
// the expiry sweep deletes it. A provisioning rule that adds a group or a role
// inserted with ON CONFLICT DO NOTHING, so for a user holding such a row it
// did nothing: the sweep then removed the row, and the rule's grant was lost.
// Now the rule takes the ended row over as standing, and leaves a live one,
// time-bound or not, as it is.
func TestARuleTakesOverAnEndedAssignment(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(bg, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	user := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email, enabled) VALUES ($1, $2::text, $2::text || '@example.test', true) RETURNING id::text`,
			org, name+"-"+suffix)
	}
	roleName, groupName := "tr-role-"+suffix, "tr-group-"+suffix
	role := scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1, $2, '') RETURNING id::text`, org, roleName)
	group := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, groupName)
	ended, live := user("tr-ended"), user("tr-live")
	for _, u := range []struct{ id, ends string }{{ended, "-5 minutes"}, {live, "1 hour"}} {
		scalar(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at) VALUES ($1, $2, $3, NOW() + $4::interval)
			RETURNING user_id::text`, u.id, role, org, u.ends)
		scalar(`INSERT INTO group_memberships (user_id, group_id, org_id, expires_at) VALUES ($1, $2, $3, NOW() + $4::interval)
			RETURNING user_id::text`, u.id, group, org, u.ends)
	}

	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	for _, u := range []string{ended, live} {
		svc.applyRuleAction(ctx, org, u, RuleAction{Type: "add_to_group", Target: groupName}, "tr-rule")
		svc.applyRuleAction(ctx, org, u, RuleAction{Type: "assign_role", Target: roleName}, "tr-rule")
	}

	window := func(table, col, id, userID string) string {
		t.Helper()
		return scalar(`SELECT CASE WHEN expires_at IS NULL THEN 'standing' WHEN expires_at > NOW() THEN 'live' ELSE 'ended' END
			FROM `+table+` WHERE user_id = $1 AND `+col+` = $2`, userID, id)
	}
	for _, c := range []struct{ what, table, col, id, user, want string }{
		{"the ended role", "user_roles", "role_id", role, ended, "standing"},
		{"the ended membership", "group_memberships", "group_id", group, ended, "standing"},
		{"the live role", "user_roles", "role_id", role, live, "live"},
		{"the live membership", "group_memberships", "group_id", group, live, "live"},
	} {
		if got := window(c.table, c.col, c.id, c.user); got != c.want {
			t.Errorf("after the rule %s is %s; want %s", c.what, got, c.want)
		}
	}
}
