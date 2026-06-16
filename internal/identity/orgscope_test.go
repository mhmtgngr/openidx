package identity

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The v1.7.0 org-scoping contract for the identity management surface:
// every user and identity-provider management method reads the org
// from context and refuses to run without one. The guard fires before
// any database access, so these hold with a nil pool — proving the
// check is the first thing each method does, not something reachable
// only after a query has already run unscoped.

func newUnboundService(t *testing.T) *Service {
	t.Helper()
	return NewService(nil, nil, nil, zap.NewNop())
}

func TestUserManagement_requireOrgContext(t *testing.T) {
	s := newUnboundService(t)
	ctx := context.Background() // no org attached

	t.Run("GetUser", func(t *testing.T) {
		_, err := s.GetUser(ctx, "user-1")
		assertNoOrgContext(t, err)
	})
	t.Run("ListUsers", func(t *testing.T) {
		_, _, err := s.ListUsers(ctx, 0, 10)
		assertNoOrgContext(t, err)
	})
	t.Run("ListUsers_withSearch", func(t *testing.T) {
		_, _, err := s.ListUsers(ctx, 0, 10, "alice")
		assertNoOrgContext(t, err)
	})
	t.Run("CreateUser", func(t *testing.T) {
		assertNoOrgContext(t, s.CreateUser(ctx, &User{ID: "u-1", UserName: "u"}))
	})
	t.Run("UpdateUser", func(t *testing.T) {
		assertNoOrgContext(t, s.UpdateUser(ctx, &User{ID: "u-1"}))
	})
	t.Run("DeleteUser", func(t *testing.T) {
		assertNoOrgContext(t, s.DeleteUser(ctx, "u-1"))
	})
	t.Run("SearchUsers", func(t *testing.T) {
		_, err := s.SearchUsers(ctx, "alice", 10)
		assertNoOrgContext(t, err)
	})
}

func TestIdentityProviderManagement_requireOrgContext(t *testing.T) {
	s := newUnboundService(t)
	ctx := context.Background()

	t.Run("CreateIdentityProvider", func(t *testing.T) {
		assertNoOrgContext(t, s.CreateIdentityProvider(ctx, &IdentityProvider{Name: "idp"}))
	})
	t.Run("GetIdentityProvider", func(t *testing.T) {
		_, err := s.GetIdentityProvider(ctx, "idp-1")
		assertNoOrgContext(t, err)
	})
	t.Run("ListIdentityProviders", func(t *testing.T) {
		_, _, err := s.ListIdentityProviders(ctx, 0, 10)
		assertNoOrgContext(t, err)
	})
	t.Run("UpdateIdentityProvider", func(t *testing.T) {
		assertNoOrgContext(t, s.UpdateIdentityProvider(ctx, &IdentityProvider{Name: "idp"}))
	})
	t.Run("DeleteIdentityProvider", func(t *testing.T) {
		assertNoOrgContext(t, s.DeleteIdentityProvider(ctx, "idp-1"))
	})
}

func TestGroupManagement_requireOrgContext(t *testing.T) {
	s := newUnboundService(t)
	ctx := context.Background()

	t.Run("ListGroups", func(t *testing.T) {
		_, _, err := s.ListGroups(ctx, 0, 10)
		assertNoOrgContext(t, err)
	})
	t.Run("ListGroups_withSearch", func(t *testing.T) {
		_, _, err := s.ListGroups(ctx, 0, 10, "eng")
		assertNoOrgContext(t, err)
	})
	t.Run("GetGroup", func(t *testing.T) {
		_, err := s.GetGroup(ctx, "g-1")
		assertNoOrgContext(t, err)
	})
	t.Run("GetGroupMembers", func(t *testing.T) {
		_, err := s.GetGroupMembers(ctx, "g-1")
		assertNoOrgContext(t, err)
	})
	t.Run("GetGroupMembersPaginated", func(t *testing.T) {
		_, _, err := s.GetGroupMembersPaginated(ctx, "g-1", "", 0, 10)
		assertNoOrgContext(t, err)
	})
	t.Run("CreateGroup", func(t *testing.T) {
		assertNoOrgContext(t, s.CreateGroup(ctx, &Group{ID: "g-1"}))
	})
	t.Run("UpdateGroup", func(t *testing.T) {
		assertNoOrgContext(t, s.UpdateGroup(ctx, &Group{ID: "g-1"}))
	})
	t.Run("DeleteGroup", func(t *testing.T) {
		assertNoOrgContext(t, s.DeleteGroup(ctx, "g-1"))
	})
	t.Run("AddGroupMember", func(t *testing.T) {
		assertNoOrgContext(t, s.AddGroupMember(ctx, "g-1", "u-1"))
	})
	t.Run("RemoveGroupMember", func(t *testing.T) {
		assertNoOrgContext(t, s.RemoveGroupMember(ctx, "g-1", "u-1"))
	})
	t.Run("GetSubgroups", func(t *testing.T) {
		_, err := s.GetSubgroups(ctx, "g-1")
		assertNoOrgContext(t, err)
	})
}

func TestRoleManagement_requireOrgContext(t *testing.T) {
	s := newUnboundService(t)
	ctx := context.Background()

	t.Run("ListRoles", func(t *testing.T) {
		_, _, err := s.ListRoles(ctx, 0, 10)
		assertNoOrgContext(t, err)
	})
	t.Run("GetRole", func(t *testing.T) {
		_, err := s.GetRole(ctx, "r-1")
		assertNoOrgContext(t, err)
	})
	t.Run("CreateRole", func(t *testing.T) {
		assertNoOrgContext(t, s.CreateRole(ctx, &Role{ID: "r-1", Name: "admin"}))
	})
	t.Run("UpdateRole", func(t *testing.T) {
		assertNoOrgContext(t, s.UpdateRole(ctx, &Role{ID: "r-1"}))
	})
	t.Run("DeleteRole", func(t *testing.T) {
		assertNoOrgContext(t, s.DeleteRole(ctx, "r-1"))
	})
	t.Run("GetUserRoles", func(t *testing.T) {
		_, err := s.GetUserRoles(ctx, "u-1")
		assertNoOrgContext(t, err)
	})
	t.Run("GetUserRoleAssignments", func(t *testing.T) {
		_, err := s.GetUserRoleAssignments(ctx, "u-1")
		assertNoOrgContext(t, err)
	})
	t.Run("AssignUserRole", func(t *testing.T) {
		assertNoOrgContext(t, s.AssignUserRole(ctx, "u-1", "r-1", "admin", nil))
	})
	t.Run("RemoveUserRole", func(t *testing.T) {
		assertNoOrgContext(t, s.RemoveUserRole(ctx, "u-1", "r-1"))
	})
	t.Run("UpdateUserRoles", func(t *testing.T) {
		assertNoOrgContext(t, s.UpdateUserRoles(ctx, "u-1", []string{"r-1"}, "admin"))
	})
	t.Run("GetRolePermissions", func(t *testing.T) {
		_, err := s.GetRolePermissions(ctx, "r-1")
		assertNoOrgContext(t, err)
	})
	t.Run("SetRolePermissions", func(t *testing.T) {
		assertNoOrgContext(t, s.SetRolePermissions(ctx, "r-1", []string{"p-1"}))
	})
}

func assertNoOrgContext(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, orgctx.ErrNoOrgContext) {
		t.Fatalf("err = %v, want orgctx.ErrNoOrgContext (method must refuse to run without an org)", err)
	}
}
