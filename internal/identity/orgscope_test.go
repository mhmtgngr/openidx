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

func assertNoOrgContext(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, orgctx.ErrNoOrgContext) {
		t.Fatalf("err = %v, want orgctx.ErrNoOrgContext (method must refuse to run without an org)", err)
	}
}
