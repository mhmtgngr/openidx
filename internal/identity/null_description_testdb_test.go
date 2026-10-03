package identity

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// A role or a group with no description reads like one with an empty one.
// roles.description and groups.description are nullable, and a row written
// by SQL, a migration or an older version can hold NULL. Scanned into a
// string, a NULL failed the whole read: the user's roles could not be read,
// so the separation-of-duty check before a role edit answered 403 "unable to
// evaluate separation-of-duty policies", and the role and group pages
// failed to load. On the migrated schema, every read of a role or a group.
func TestARoleOrGroupWithNoDescriptionStillReads(t *testing.T) {
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
		var v string
		if err := db.Pool.QueryRow(seed, q, args...).Scan(&v); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
		return v
	}
	user := scalar(`INSERT INTO users (org_id, username, email, enabled) VALUES ($1, $2::text, $2::text || '@example.test', true) RETURNING id::text`,
		org, "nd-user-"+suffix)
	role := scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1, $2, NULL) RETURNING id::text`, org, "nd-role-"+suffix)
	group := scalar(`INSERT INTO groups (org_id, name, description) VALUES ($1, $2, NULL) RETURNING id::text`, org, "nd-group-"+suffix)
	scalar(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1, $2, $3) RETURNING user_id::text`, user, role, org)
	scalar(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1, $2, $3) RETURNING user_id::text`, user, group, org)
	svc := NewService(db, nil, &config.Config{}, zap.NewNop())

	if roles, err := svc.GetUserRoles(ctx, user); err != nil || len(roles) != 1 || roles[0].Description != "" {
		t.Errorf("GetUserRoles: %v, %v; want the role with an empty description", roles, err)
	}
	if as, err := svc.GetUserRoleAssignments(ctx, user); err != nil || len(as) != 1 {
		t.Errorf("GetUserRoleAssignments: %v, %v; want the assignment", as, err)
	}
	if r, err := svc.GetRole(ctx, role); err != nil || r.Description != "" {
		t.Errorf("GetRole: %v, %v; want the role with an empty description", r, err)
	}
	if roles, _, err := svc.ListRoles(ctx, 0, 500); err != nil || len(roles) == 0 {
		t.Errorf("ListRoles: %d roles, %v; want the list", len(roles), err)
	}
	if g, err := svc.GetGroup(ctx, group); err != nil || g == nil {
		t.Errorf("GetGroup: %v, %v; want the group", g, err)
	}
	if groups, _, err := svc.ListGroups(ctx, 0, 500); err != nil || len(groups) == 0 {
		t.Errorf("ListGroups: %d groups, %v; want the list", len(groups), err)
	}
}
