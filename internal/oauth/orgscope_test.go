package oauth

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// v1.7.0 org-scoping contract: OAuth client/token methods read the org
// from context and refuse to run without one. The guard fires before
// any DB access, so these hold with a nil pool (a &Service{} with no
// db). Token endpoints run behind the resolver, so the request always
// carries an org; the only deliberately cross-org path is the
// background session-expiry sweep (session_worker), marked
// //orgscope:ignore.
func TestOAuth_requireOrgContext(t *testing.T) {
	// The client methods now delegate to the OAuthClientStore, which performs the
	// org-context check. Wire a store (no DB needed to reach the orgctx guard,
	// which runs before any query).
	s := &Service{logger: zap.NewNop(), clients: NewPostgresOAuthClientStore(nil)}
	ctx := context.Background()

	t.Run("GetClient", func(t *testing.T) {
		_, err := s.GetClient(ctx, "client-1")
		assertNoOrg(t, err)
	})
	t.Run("DeleteClient", func(t *testing.T) {
		assertNoOrg(t, s.DeleteClient(ctx, "client-1"))
	})
	t.Run("GetAuthorizationCode", func(t *testing.T) {
		_, err := s.GetAuthorizationCode(ctx, "code-1")
		assertNoOrg(t, err)
	})
	t.Run("GetRefreshToken", func(t *testing.T) {
		_, err := s.GetRefreshToken(ctx, "tok-1")
		assertNoOrg(t, err)
	})
	t.Run("RevokeRefreshToken", func(t *testing.T) {
		assertNoOrg(t, s.RevokeRefreshToken(ctx, "tok-1"))
	})
	t.Run("GetUserInfo", func(t *testing.T) {
		_, err := s.GetUserInfo(ctx, "u-1")
		assertNoOrg(t, err)
	})
	t.Run("GenerateJWT", func(t *testing.T) {
		_, err := s.GenerateJWT(ctx, "u-1", "client-1", "openid", 3600)
		assertNoOrg(t, err)
	})
	t.Run("GenerateIDToken", func(t *testing.T) {
		_, err := s.GenerateIDToken(ctx, "u-1", "client-1", "nonce", 3600)
		assertNoOrg(t, err)
	})
}

func assertNoOrg(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, orgctx.ErrNoOrgContext) {
		t.Fatalf("err = %v, want orgctx.ErrNoOrgContext", err)
	}
}
