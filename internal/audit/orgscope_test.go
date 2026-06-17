package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// v1.7.0 org-scoping contract: audit read/report methods that touch a
// tenant-scoped table read the org from context and refuse to run without one.
// The guard fires before any DB access, so these hold with a nil pool. Audit
// endpoints run behind the resolver, so the request always carries an org. The
// deliberately non-fail-closed path is the writer (LogEvent / anomaly storeAlerts):
// audit events must never be dropped, so an unresolved org falls back to the
// default org rather than erroring — hence the writers are not asserted here.
func TestAudit_requireOrgContext(t *testing.T) {
	s := &Service{logger: zap.NewNop()}
	ctx := context.Background()
	now := time.Now()

	t.Run("QueryEvents", func(t *testing.T) {
		_, _, err := s.QueryEvents(ctx, &AuditQuery{})
		assertNoOrg(t, err)
	})
	t.Run("GetEventStatistics", func(t *testing.T) {
		_, err := s.GetEventStatistics(ctx, now.AddDate(0, 0, -30), now)
		assertNoOrg(t, err)
	})
	t.Run("ListComplianceReports", func(t *testing.T) {
		_, _, err := s.ListComplianceReports(ctx, 0, 10)
		assertNoOrg(t, err)
	})
	t.Run("GetComplianceReport", func(t *testing.T) {
		_, err := s.GetComplianceReport(ctx, "r-1")
		assertNoOrg(t, err)
	})
}

func assertNoOrg(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, orgctx.ErrNoOrgContext) {
		t.Fatalf("err = %v, want orgctx.ErrNoOrgContext", err)
	}
}
