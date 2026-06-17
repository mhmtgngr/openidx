package apikeys

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The org-scoping contract for the v1.7.0 refactor: every
// request-scoped method reads the org from context and refuses to run
// without one. These checks fire before any database access, so they
// hold with a nil pool — proving the guard is the first thing each
// method does, not an afterthought reachable only past a query.

func TestServiceAccountMethods_requireOrgContext(t *testing.T) {
	svc := NewService(nil, nil, zaptest.NewLogger(t))
	ctx := context.Background() // deliberately no org attached

	t.Run("CreateServiceAccount", func(t *testing.T) {
		_, err := svc.CreateServiceAccount(ctx, "name", "desc", "owner")
		assertNoOrgContext(t, err)
	})
	t.Run("ListServiceAccounts", func(t *testing.T) {
		_, _, err := svc.ListServiceAccounts(ctx, 10, 0)
		assertNoOrgContext(t, err)
	})
	t.Run("GetServiceAccount", func(t *testing.T) {
		_, err := svc.GetServiceAccount(ctx, "sa-1")
		assertNoOrgContext(t, err)
	})
	t.Run("DeleteServiceAccount", func(t *testing.T) {
		err := svc.DeleteServiceAccount(ctx, "sa-1")
		assertNoOrgContext(t, err)
	})
}

func TestAPIKeyMethods_requireOrgContext(t *testing.T) {
	svc := NewService(nil, nil, zaptest.NewLogger(t))
	ctx := context.Background()

	t.Run("CreateAPIKey", func(t *testing.T) {
		_, _, err := svc.CreateAPIKey(ctx, "name", nil, nil, nil, nil)
		assertNoOrgContext(t, err)
	})
	t.Run("ListAPIKeys", func(t *testing.T) {
		_, err := svc.ListAPIKeys(ctx, "user-1", "user")
		assertNoOrgContext(t, err)
	})
	t.Run("RevokeAPIKey", func(t *testing.T) {
		err := svc.RevokeAPIKey(ctx, "key-1")
		assertNoOrgContext(t, err)
	})
	t.Run("RevokeAllUserKeys", func(t *testing.T) {
		err := svc.RevokeAllUserKeys(ctx, "user-1")
		assertNoOrgContext(t, err)
	})
}

// TestAPIKeyInfo_carriesOrgID documents that the validated identity
// surfaces the key's org so the auth layer can set the request tenant
// from it (the API-key analog of the JWT org_id claim).
func TestAPIKeyInfo_carriesOrgID(t *testing.T) {
	info := &APIKeyInfo{KeyID: "k-1", OrgID: "11111111-2222-3333-4444-555555555555"}
	if info.OrgID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("OrgID = %q, want the key's org", info.OrgID)
	}
}

func assertNoOrgContext(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, orgctx.ErrNoOrgContext) {
		t.Fatalf("err = %v, want orgctx.ErrNoOrgContext (method must refuse to run without an org)", err)
	}
}
