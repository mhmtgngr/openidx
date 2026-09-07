package admin

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/notifications"
)

// TestISPMReminderRespectsTheNotificationPreference drives the ISPM MFA
// reminder against two users, one of whom has switched security reminders off.
//
// Before this, the switch was read by nothing on this path. remediateFinding
// wrote `INSERT INTO notifications` directly -- a set-based write that never
// went near CreateNotification and therefore never near isNotificationEnabled.
// Three other senders did the same. So the preferences page had switches that
// changed nothing, and the four types it did not even list arrived regardless.
//
// The predicate is now in the statement itself, and this is what that means in
// practice: the user who opted out gets nothing, and the user who never touched
// the page gets the reminder, because an absent row means enabled -- the same
// default isNotificationEnabled applies.
func TestISPMReminderRespectsTheNotificationPreference(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	seedCtx := orgctx.WithBypassRLS(context.Background())
	const (
		orgID   = "00000000-0000-0000-0000-0000000000f1"
		optedIn = "33333333-0000-0000-0000-0000000000f1"
		optedNo = "33333333-0000-0000-0000-0000000000f2"
	)
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(seedCtx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1, 'Org F (notify test)', 'org-f-notify-test')`, orgID)
	exec(`INSERT INTO users (id, username, email, enabled, org_id) VALUES
	        ($1, 'notify-on',  'notify-on@test.local',  true, $3),
	        ($2, 'notify-off', 'notify-off@test.local', true, $3)`, optedIn, optedNo, orgID)
	// One user has turned security reminders off. The other has never opened
	// the page, so there is no row for them at all.
	exec(`INSERT INTO notification_preferences (id, user_id, channel, event_type, enabled, org_id)
	      VALUES (gen_random_uuid(), $1, 'in_app', $2, false, $3)`,
		optedNo, notifications.TypeSecurity, orgID)

	svc := &Service{db: db, logger: zap.NewNop()}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	for _, user := range []string{optedIn, optedNo} {
		out := svc.remediateFinding(ctx, orgID, "mfa_adoption", "user", user)
		if out.Action == "failed" {
			t.Fatalf("remediate for %s: %s", user, out.Message)
		}
	}

	count := func(user string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(seedCtx,
			`SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND type = $2`,
			user, notifications.TypeSecurity).Scan(&n); err != nil {
			t.Fatalf("count notifications for %s: %v", user, err)
		}
		return n
	}

	if got := count(optedIn); got != 1 {
		t.Errorf("the user who never changed a preference received %d reminder(s), want 1: "+
			"an absent row means enabled", got)
	}
	if got := count(optedNo); got != 0 {
		t.Errorf("the user who switched security reminders OFF received %d reminder(s), want 0: "+
			"the switch does not enforce", got)
	}
}
