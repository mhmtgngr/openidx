package admin

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// v1.7.0 org-scoping contract: admin service methods that touch a tenant-scoped
// table read the org from context and refuse to run without one. The guard fires
// before any DB access, so these hold with a nil pool. The admin API resolves the
// org at the v1 route group (after auth), so every admin request carries one. The
// background paths (bulk-operation execution, lifecycle deprovisioning, audit
// archival, the DSAR processor ticker) capture/derive the org from the request or
// the row they sweep, so they are exercised through their request entry points
// elsewhere rather than asserted here.
func TestAdmin_requireOrgContext(t *testing.T) {
	s := &Service{logger: zap.NewNop()}
	ctx := context.Background()

	t.Run("GetDashboard", func(t *testing.T) {
		_, err := s.GetDashboard(ctx)
		assertNoOrg(t, err)
	})
	t.Run("ListApplications", func(t *testing.T) {
		_, _, err := s.ListApplications(ctx, 0, 20)
		assertNoOrg(t, err)
	})
	t.Run("CreateApplication", func(t *testing.T) {
		assertNoOrg(t, s.CreateApplication(ctx, &Application{}))
	})
	t.Run("GetCompliancePosture", func(t *testing.T) {
		_, err := s.GetCompliancePosture(ctx)
		assertNoOrg(t, err)
	})
	t.Run("GetEntitlementCatalog", func(t *testing.T) {
		_, _, err := s.GetEntitlementCatalog(ctx, 0, 20, "", "", "")
		assertNoOrg(t, err)
	})
	t.Run("GetEntitlementStats", func(t *testing.T) {
		_, err := s.GetEntitlementStats(ctx)
		assertNoOrg(t, err)
	})
	t.Run("UpdateApplication", func(t *testing.T) {
		// org guard fires before the no-valid-fields validation
		assertNoOrg(t, s.UpdateApplication(ctx, "app-1", map[string]interface{}{"name": "x"}))
	})
}

func assertNoOrg(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, orgctx.ErrNoOrgContext) {
		t.Fatalf("err = %v, want orgctx.ErrNoOrgContext", err)
	}
}
