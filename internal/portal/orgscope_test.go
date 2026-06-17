package portal

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// v1.7.0 org-scoping contract: portal self-service methods read the org
// from context and refuse to run without one — the guard fires before
// any DB access, so these hold with a nil pool.
func TestPortal_requireOrgContext(t *testing.T) {
	s := NewService(nil, zap.NewNop())
	ctx := context.Background()

	t.Run("GetMyApplications", func(t *testing.T) {
		_, err := s.GetMyApplications(ctx, "u-1")
		assertNoOrgContext(t, err)
	})
	t.Run("GetAvailableGroups", func(t *testing.T) {
		_, err := s.GetAvailableGroups(ctx, "u-1")
		assertNoOrgContext(t, err)
	})
	t.Run("RequestGroupJoin", func(t *testing.T) {
		assertNoOrgContext(t, s.RequestGroupJoin(ctx, "u-1", "g-1", "please"))
	})
	t.Run("GetMyGroupRequests", func(t *testing.T) {
		_, err := s.GetMyGroupRequests(ctx, "u-1")
		assertNoOrgContext(t, err)
	})
	t.Run("GetAccessOverview", func(t *testing.T) {
		_, err := s.GetAccessOverview(ctx, "u-1")
		assertNoOrgContext(t, err)
	})
	t.Run("ReviewGroupRequest", func(t *testing.T) {
		assertNoOrgContext(t, s.ReviewGroupRequest(ctx, "req-1", "admin-1", "approved", ""))
	})
}

func assertNoOrgContext(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, orgctx.ErrNoOrgContext) {
		t.Fatalf("err = %v, want orgctx.ErrNoOrgContext", err)
	}
}
