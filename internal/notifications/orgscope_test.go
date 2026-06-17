package notifications

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// GetUserNotifications scopes its count + list to the caller's org; the
// guard fires before any DB access, so it holds with a nil pool.
func TestNotifications_requireOrgContext(t *testing.T) {
	s := NewService(nil, zap.NewNop())
	_, _, err := s.GetUserNotifications(context.Background(), "u-1", "", false, 10, 0)
	if !errors.Is(err, orgctx.ErrNoOrgContext) {
		t.Fatalf("err = %v, want orgctx.ErrNoOrgContext", err)
	}
}
