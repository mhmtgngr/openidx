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

// A SCIM push of a group replaces its members, and a member the push keeps
// keeps the membership's window (migration v224). On the migrated schema,
// through UpdateSCIMGroup (the choke point of PUT and of PATCH members):
//
//   - a membership an access request gave keeps its window, so it still ends
//     with the request instead of coming back standing;
//   - a standing membership stays standing;
//   - a member the push adds is standing, and one it leaves out is gone.
func TestASCIMGroupPushKeepsEachMembersWindow(t *testing.T) {
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
	group := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "sg-group-"+suffix)
	windowed, standing, added, dropped := user("sg-windowed"), user("sg-standing"), user("sg-added"), user("sg-dropped")
	end := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Microsecond)
	if _, err := db.Pool.Exec(ctx, `INSERT INTO group_memberships (user_id, group_id, org_id, expires_at) VALUES
		($1, $3, $4, $5), ($2, $3, $4, NULL)`, windowed, standing, group, org, end); err != nil {
		t.Fatalf("seed the memberships: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1, $2, $3)`,
		dropped, group, org); err != nil {
		t.Fatalf("seed the memberships: %v", err)
	}

	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	push := &SCIMGroup{DisplayName: "sg-group-" + suffix, Members: []SCIMMember{{Value: windowed}, {Value: standing}, {Value: added}}}
	if _, err := svc.UpdateSCIMGroup(ctx, group, push); err != nil {
		t.Fatalf("push the group: %v", err)
	}
	membership := func(userID string) string {
		return scalar(`SELECT COALESCE((SELECT CASE WHEN expires_at IS NULL THEN 'standing'
			WHEN expires_at = $3 THEN 'its window' ELSE 'another window' END
			FROM group_memberships WHERE user_id = $1 AND group_id = $2), 'none')`, userID, group, end)
	}
	for _, c := range []struct{ who, userID, want string }{
		{"a membership an access request gave", windowed, "its window"},
		{"a standing membership", standing, "standing"},
		{"a member the push added", added, "standing"},
		{"a member the push left out", dropped, "none"},
	} {
		if got := membership(c.userID); got != c.want {
			t.Errorf("after the push, %s is %s; want %s", c.who, got, c.want)
		}
	}
}
