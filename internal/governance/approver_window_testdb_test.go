package governance

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// A role or a group membership an access request gave ends with its window
// (v223, v224), and the expiry sweep deletes the row within a minute. Until it
// does, governance counted it in two places that decide who may do what:
//
//   - a role or group approval step named its holders as approvers, so a user
//     whose approver role had ended could still be asked, and decide;
//   - auto-approve's allowed_roles and allowed_groups conditions held for a
//     requester whose role or group had ended, so the request skipped its
//     approvers.
//
// On the migrated schema: the steps name only the live holder, and the
// conditions hold only for a live role or group.
func TestAnEndedRoleOrGroupNeitherApprovesNorAutoApproves(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate: %v", err)
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
		return scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
			org, name+"-"+suffix)
	}
	role := scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1, $2, '') RETURNING id::text`, org, "approvers-"+suffix)
	group := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "approver-group-"+suffix)
	hold := func(userID, ends string) {
		scalar(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at)
			VALUES ($1, $2, $3, NOW() + $4::interval) RETURNING user_id::text`, userID, role, org, ends)
		scalar(`INSERT INTO group_memberships (user_id, group_id, org_id, expires_at)
			VALUES ($1, $2, $3, NOW() + $4::interval) RETURNING user_id::text`, userID, group, org, ends)
	}
	ended, live, requester := user("ended-approver"), user("live-approver"), user("requester")
	hold(ended, "-5 minutes")
	hold(live, "1 hour")

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	for _, step := range []ApprovalStep{
		{Order: 1, Type: ApprovalStepTypeRole, RoleID: role},
		{Order: 1, Type: ApprovalStepTypeGroup, GroupID: group},
	} {
		got, err := s.resolveStepApprovers(ctx, org, step, requester)
		if err != nil || !slices.Equal(got, []string{live}) {
			t.Errorf("a %s step's approvers = %v, %v; want only the live holder %s", step.Type, got, err, live)
		}
	}

	for _, tc := range []struct {
		what      string
		requester string
		cond      AutoApproveConditions
		want      bool
	}{
		{"an ended role", ended, AutoApproveConditions{AllowedRoles: []string{"approvers-" + suffix}}, false},
		{"a live role", live, AutoApproveConditions{AllowedRoles: []string{"approvers-" + suffix}}, true},
		{"an ended group", ended, AutoApproveConditions{AllowedGroups: []string{"approver-group-" + suffix}}, false},
		{"a live group", live, AutoApproveConditions{AllowedGroups: []string{"approver-group-" + suffix}}, true},
	} {
		cond := tc.cond
		if got := s.autoApproveConditionsMet(ctx, org, tc.requester, &cond); got != tc.want {
			t.Errorf("auto-approve for a requester with %s = %v; want %v", tc.what, got, tc.want)
		}
	}
}
