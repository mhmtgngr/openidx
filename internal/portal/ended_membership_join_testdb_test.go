package portal

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// A membership whose window has ended (v224) stays until the expiry sweep
// deletes it. A self-join, and an approved join request, inserted with ON
// CONFLICT DO NOTHING, so for a user holding such a row they did nothing: the
// sweep then removed the row, and the user was left out of the group they
// had just joined. The group list also showed them as a member, with no Join
// to press. Now the join takes the ended row over as standing, a live
// membership is left as it is, and the list reads the window.
func TestAJoinTakesOverAnEndedMembership(t *testing.T) {
	db, cleanup := portalMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
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
	group := func(name string, approval bool) string {
		return scalar(`INSERT INTO groups (org_id, name, allow_self_join, require_approval) VALUES ($1, $2, true, $3) RETURNING id::text`,
			org, name+"-"+suffix, approval)
	}
	hold := func(userID, groupID, ends string) {
		scalar(`INSERT INTO group_memberships (user_id, group_id, org_id, expires_at) VALUES ($1, $2, $3, NOW() + $4::interval)
			RETURNING user_id::text`, userID, groupID, org, ends)
	}
	window := func(userID, groupID string) string {
		return scalar(`SELECT CASE WHEN expires_at IS NULL THEN 'standing' WHEN expires_at > NOW() THEN 'live' ELSE 'ended' END
			FROM group_memberships WHERE user_id = $1 AND group_id = $2`, userID, groupID)
	}
	svc := NewService(db, zap.NewNop())
	open, guarded := group("tj-open", false), group("tj-guarded", true)
	selfJoiner, approvedJoiner, liveMember, reviewer := user("tj-self"), user("tj-approved"), user("tj-live"), user("tj-reviewer")
	hold(selfJoiner, open, "-5 minutes")
	hold(approvedJoiner, guarded, "-5 minutes")
	hold(liveMember, open, "1 hour")

	listed, err := svc.GetAvailableGroups(ctx, selfJoiner)
	if err != nil {
		t.Fatalf("GetAvailableGroups: %v", err)
	}
	for _, g := range listed {
		if g["id"] == open && g["is_member"] == true {
			t.Errorf("the group list shows the user as a member of a group whose membership has ended")
		}
	}

	if err := svc.RequestGroupJoin(ctx, selfJoiner, open, "back on call"); err != nil {
		t.Fatalf("self-join: %v", err)
	}
	if got := window(selfJoiner, open); got != "standing" {
		t.Errorf("after the self-join the membership is %s; want standing", got)
	}
	if err := svc.RequestGroupJoin(ctx, approvedJoiner, guarded, "back on call"); err != nil {
		t.Fatalf("request a guarded group: %v", err)
	}
	req := scalar(`SELECT id::text FROM group_join_requests WHERE user_id = $1 AND group_id = $2`, approvedJoiner, guarded)
	if err := svc.ReviewGroupRequest(ctx, req, reviewer, "approved", "ok"); err != nil {
		t.Fatalf("approve the request: %v", err)
	}
	if got := window(approvedJoiner, guarded); got != "standing" {
		t.Errorf("after the approved request the membership is %s; want standing", got)
	}
	if err := svc.RequestGroupJoin(ctx, liveMember, open, "again"); err != nil {
		t.Fatalf("self-join of a group already held: %v", err)
	}
	if got := window(liveMember, open); got != "live" {
		t.Errorf("a self-join of a group already held made the membership %s; want its window kept", got)
	}
}
