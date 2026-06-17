package provisioning

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// v1.7.0 org-scoping contract: every SCIM and provisioning-rule method
// reads the org from context and refuses to run without one — the guard
// fires before any DB access, so these hold with a nil pool.
func newUnboundService(t *testing.T) *Service {
	t.Helper()
	return NewService(nil, nil, &config.Config{}, zap.NewNop())
}

func TestProvisioning_requireOrgContext(t *testing.T) {
	s := newUnboundService(t)
	ctx := context.Background()

	t.Run("CreateSCIMUser", func(t *testing.T) {
		_, err := s.CreateSCIMUser(ctx, &SCIMUser{UserName: "u"})
		assertNoOrgContext(t, err)
	})
	t.Run("GetSCIMUser", func(t *testing.T) {
		_, err := s.GetSCIMUser(ctx, "u-1")
		assertNoOrgContext(t, err)
	})
	t.Run("UpdateSCIMUser", func(t *testing.T) {
		_, err := s.UpdateSCIMUser(ctx, "u-1", &SCIMUser{})
		assertNoOrgContext(t, err)
	})
	t.Run("DeleteSCIMUser", func(t *testing.T) {
		assertNoOrgContext(t, s.DeleteSCIMUser(ctx, "u-1"))
	})
	t.Run("ListSCIMUsers", func(t *testing.T) {
		_, err := s.ListSCIMUsers(ctx, 1, 10, "")
		assertNoOrgContext(t, err)
	})
	t.Run("CreateSCIMGroup", func(t *testing.T) {
		_, err := s.CreateSCIMGroup(ctx, &SCIMGroup{DisplayName: "g"})
		assertNoOrgContext(t, err)
	})
	t.Run("GetSCIMGroup", func(t *testing.T) {
		_, err := s.GetSCIMGroup(ctx, "g-1")
		assertNoOrgContext(t, err)
	})
	t.Run("UpdateSCIMGroup", func(t *testing.T) {
		_, err := s.UpdateSCIMGroup(ctx, "g-1", &SCIMGroup{})
		assertNoOrgContext(t, err)
	})
	t.Run("DeleteSCIMGroup", func(t *testing.T) {
		assertNoOrgContext(t, s.DeleteSCIMGroup(ctx, "g-1"))
	})
	t.Run("ListSCIMGroups", func(t *testing.T) {
		_, err := s.ListSCIMGroups(ctx, 1, 10, "")
		assertNoOrgContext(t, err)
	})
	t.Run("CreateRule", func(t *testing.T) {
		_, err := s.CreateRule(ctx, &ProvisioningRule{Name: "r"})
		assertNoOrgContext(t, err)
	})
	t.Run("GetRule", func(t *testing.T) {
		_, err := s.GetRule(ctx, "r-1")
		assertNoOrgContext(t, err)
	})
	t.Run("ListRules", func(t *testing.T) {
		_, _, err := s.ListRules(ctx, 0, 10)
		assertNoOrgContext(t, err)
	})
	t.Run("UpdateRule", func(t *testing.T) {
		_, err := s.UpdateRule(ctx, "r-1", &ProvisioningRule{})
		assertNoOrgContext(t, err)
	})
	t.Run("DeleteRule", func(t *testing.T) {
		assertNoOrgContext(t, s.DeleteRule(ctx, "r-1"))
	})
}

func assertNoOrgContext(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, orgctx.ErrNoOrgContext) {
		t.Fatalf("err = %v, want orgctx.ErrNoOrgContext (method must refuse to run without an org)", err)
	}
}
