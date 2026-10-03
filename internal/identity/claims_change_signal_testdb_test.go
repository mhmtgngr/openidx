package identity

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/ssfsignal"
	"github.com/openidx/openidx/internal/revocation"
)

// Every identity path that changes a user's roles or groups tells the tenant's
// SSF receivers that a token issued for the user now says something else (CAEP
// token-claims-change), once, with the path as its reason; every path that
// takes one away also cuts the user's outstanding tokens; and a path that
// changed nothing does neither. On the migrated schema:
//
//   - the console's role grant, role-set edit, role removal and role deletion;
//   - the console's group member add and removal, and group deletion;
//   - a lifecycle rule's assign_role, remove_role, assign_group and
//     remove_group. The removals cut no token before this;
//   - the expiry sweep, which runs in no organization and tells the user's
//     own, for a lapsed role and a lapsed group membership.
func TestEveryRoleAndGroupChangeTellsTheReceivers(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	const org = "00000000-0000-0000-0000-000000000010"
	seed := orgctx.WithBypassRLS(context.Background())
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(seed, q, args...).Scan(&id); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
		return id
	}
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(seed, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	user := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email, enabled) VALUES ($1, $2::text, $2::text || '@example.test', true) RETURNING id::text`,
			org, name+"-"+suffix)
	}
	role := func(name string) string {
		return scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1, $2, '') RETURNING id::text`, org, name+"-"+suffix)
	}
	group := func(name string) string {
		return scalar(`INSERT INTO groups (org_id, name, description) VALUES ($1, $2, '') RETURNING id::text`, org, name+"-"+suffix)
	}
	holds := func(userID, roleID string, until *time.Time) {
		exec(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at) VALUES ($1, $2, $3, $4)`, userID, roleID, org, until)
	}
	joins := func(userID, groupID string) {
		exec(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1, $2, $3)`, userID, groupID, org)
	}
	joinsUntil := func(userID, groupID string, until time.Time) {
		exec(`INSERT INTO group_memberships (user_id, group_id, org_id, expires_at) VALUES ($1, $2, $3, $4)`, userID, groupID, org, until)
	}

	mini := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	svc := NewService(db, &database.RedisClient{Client: rc}, &config.Config{}, zap.NewNop())

	// reasons lists the user's token-claims-change signals by reason, and
	// fails on one addressed to another organization.
	reasons := func(userID string) []string {
		t.Helper()
		rows, err := db.Pool.Query(seed, `SELECT org_id::text, claims->>'reason' FROM ssf_pending_events
			WHERE subject_id = $1 AND event_type = $2 ORDER BY id`, userID, ssfsignal.TokenClaimsChange)
		if err != nil {
			t.Fatalf("read the signals: %v", err)
		}
		defer rows.Close()
		var got []string
		for rows.Next() {
			var to, why string
			if err := rows.Scan(&to, &why); err != nil {
				t.Fatalf("scan a signal: %v", err)
			}
			if to != org {
				t.Errorf("a signal about %s went to organization %s, not the user's %s", userID, to, org)
			}
			got = append(got, why)
		}
		return got
	}
	cut := func(userID string) bool {
		return mini.Exists(revocation.UserTokensRevokedAtKey(userID))
	}
	// expect checks the user's signals and whether the user's tokens were cut.
	expect := func(step, userID string, wantCut bool, want ...string) {
		t.Helper()
		got := reasons(userID)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: token-claims-change reasons %v, want %v", step, got, want)
		}
		if c := cut(userID); c != wantCut {
			t.Errorf("%s: tokens cut = %v, want %v", step, c, wantCut)
		}
	}
	lifecycle := func(userID string, action map[string]interface{}) {
		t.Helper()
		if err := svc.executeLifecycleAction(ctx, userID, action); err != nil {
			t.Fatalf("lifecycle %v: %v", action, err)
		}
	}
	must := func(step string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
	}
	admin := user("cc-admin")
	engineer, auditor, retired := role("cc-engineer"), role("cc-auditor"), role("cc-retired")
	staff, project := group("cc-staff"), group("cc-project")

	// The console's role paths.
	granted := user("cc-granted")
	must("assign", svc.AssignUserRole(ctx, granted, engineer, admin, nil))
	expect("a role grant", granted, false, "identity.AssignUserRole")

	widened, unchanged, narrowed := user("cc-widened"), user("cc-unchanged"), user("cc-narrowed")
	holds(widened, engineer, nil)
	holds(unchanged, engineer, nil)
	holds(narrowed, engineer, nil)
	holds(narrowed, auditor, nil)
	must("widen", svc.UpdateUserRoles(ctx, widened, []string{engineer, auditor}, admin))
	must("keep", svc.UpdateUserRoles(ctx, unchanged, []string{engineer}, admin))
	must("narrow", svc.UpdateUserRoles(ctx, narrowed, []string{engineer}, admin))
	expect("a role set that only adds", widened, false, "identity.UpdateUserRoles")
	expect("a role set saved unchanged", unchanged, false)
	expect("a role set that drops one", narrowed, true, "identity.UpdateUserRoles")

	removed := user("cc-removed")
	holds(removed, auditor, nil)
	must("remove", svc.RemoveUserRole(ctx, removed, auditor))
	expect("a role removal", removed, true, "identity.RemoveUserRole")

	holderA, holderB := user("cc-holder-a"), user("cc-holder-b")
	holds(holderA, retired, nil)
	holds(holderB, retired, nil)
	must("delete role", svc.DeleteRole(ctx, retired))
	expect("a role deletion, first holder", holderA, true, "identity.DeleteRole")
	expect("a role deletion, second holder", holderB, true, "identity.DeleteRole")

	// The console's group paths.
	joined := user("cc-joined")
	must("add member", svc.AddGroupMember(ctx, staff, joined))
	expect("a group member added", joined, false, "identity.AddGroupMember")

	left := user("cc-left")
	joins(left, staff)
	must("remove member", svc.RemoveGroupMember(ctx, staff, left))
	expect("a group member removed", left, true, "identity.RemoveGroupMember")

	memberA, memberB := user("cc-member-a"), user("cc-member-b")
	joins(memberA, project)
	joins(memberB, project)
	must("delete group", svc.DeleteGroup(ctx, project))
	expect("a group deletion, first member", memberA, true, "identity.DeleteGroup")
	expect("a group deletion, second member", memberB, true, "identity.DeleteGroup")

	// A lifecycle rule's role and group actions, each run twice: the second
	// run changes nothing and says nothing.
	mover := user("cc-mover")
	lifecycle(mover, map[string]interface{}{"type": "assign_role", "role_id": auditor})
	lifecycle(mover, map[string]interface{}{"type": "assign_role", "role_id": auditor})
	expect("lifecycle assign_role", mover, false, "identity.lifecycle.assign_role")

	leaver := user("cc-leaver")
	holds(leaver, engineer, nil)
	lifecycle(leaver, map[string]interface{}{"type": "remove_role", "role_id": engineer})
	lifecycle(leaver, map[string]interface{}{"type": "remove_role", "role_id": engineer})
	expect("lifecycle remove_role", leaver, true, "identity.lifecycle.remove_role")

	stranger := user("cc-stranger")
	lifecycle(stranger, map[string]interface{}{"type": "remove_role", "role_id": engineer})
	lifecycle(stranger, map[string]interface{}{"type": "remove_group", "group_id": staff})
	expect("lifecycle removals of what the user does not hold", stranger, false)

	joiner := user("cc-joiner")
	lifecycle(joiner, map[string]interface{}{"type": "assign_group", "group_id": staff})
	lifecycle(joiner, map[string]interface{}{"type": "assign_group", "group_id": staff})
	expect("lifecycle assign_group", joiner, false, "identity.lifecycle.assign_group")

	departer := user("cc-departer")
	joins(departer, staff)
	lifecycle(departer, map[string]interface{}{"type": "remove_group", "group_id": staff})
	lifecycle(departer, map[string]interface{}{"type": "remove_group", "group_id": staff})
	expect("lifecycle remove_group", departer, true, "identity.lifecycle.remove_group")

	// The expiry sweep, in no organization: a role and a group membership
	// whose window has ended, and one of each whose window has not.
	lapsed, current := user("cc-lapsed"), user("cc-current")
	lapsedMember, currentMember := user("cc-lapsed-member"), user("cc-current-member")
	ago, ahead := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	holds(lapsed, auditor, &ago)
	holds(current, auditor, &ahead)
	joinsUntil(lapsedMember, staff, ago)
	joinsUntil(currentMember, staff, ahead)
	svc.cleanupExpiredAccess(orgctx.WithBypassRLS(context.Background()))
	expect("the expiry sweep, a lapsed role", lapsed, true, "identity.role_expiry")
	expect("the expiry sweep, a current role", current, false)
	expect("the expiry sweep, a lapsed group membership", lapsedMember, true, "identity.group_expiry")
	expect("the expiry sweep, a current group membership", currentMember, false)
	memberships := func(userID string) string {
		return scalar(`SELECT count(*)::text FROM group_memberships WHERE user_id = $1`, userID)
	}
	if n := memberships(lapsedMember); n != "0" {
		t.Errorf("the expiry sweep left %s lapsed group memberships", n)
	}
	if n := memberships(currentMember); n != "1" {
		t.Errorf("the expiry sweep removed a current group membership: %s left", n)
	}

	// Nothing went anywhere else: one signal for each change above.
	var total int
	if err := db.Pool.QueryRow(seed, `SELECT count(*) FROM ssf_pending_events WHERE event_type = $1`,
		ssfsignal.TokenClaimsChange).Scan(&total); err != nil {
		t.Fatalf("count the signals: %v", err)
	}
	if total != 16 {
		t.Errorf("%d token-claims-change signals in all, want 16", total)
	}
}
