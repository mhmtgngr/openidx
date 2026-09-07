package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/revocation"
)

// The two halves of "revoke everything this user holds", pinned together.
//
// internal/governance sets the marker when an access review revokes somebody's
// access; internal/oauth reads it here, in the check that decides whether an
// access token still works. They used to write and read DIFFERENT KEYS --
// governance wrote auth:user_revoked:<uid>, a format that came from
// internal/auth's TokenService, which no binary reaches -- so an access review
// could revoke access, record it, audit it, and leave the user's live session
// and outstanding tokens working until they expired on their own.
//
// Neither half looked wrong on its own. That is why this test writes the marker
// the way governance writes it, through the shared package, and requires THIS
// service's check to see it. If the key, the value format or the comparison
// ever separates again, this fails.

func revocationMarkerService(t *testing.T) (*Service, *miniredis.Miniredis) {
	t.Helper()
	mini := miniredis.RunT(t)
	return &Service{
		redis:  &database.RedisClient{Client: redis.NewClient(&redis.Options{Addr: mini.Addr()})},
		logger: zap.NewNop(),
	}, mini
}

func TestAnAccessReviewsRevocationReachesTheTokenCheck(t *testing.T) {
	svc, _ := revocationMarkerService(t)
	ctx := context.Background()
	const user = "22222222-0000-0000-0000-000000000001"

	issuedAt := time.Now().Add(-time.Minute).Unix()

	// Before the review: the token is good.
	revoked, err := svc.IsAccessTokenRevoked(ctx, "some-token", user, issuedAt)
	if err != nil {
		t.Fatalf("IsAccessTokenRevoked: %v", err)
	}
	if revoked {
		t.Fatal("a token was revoked before anything revoked it")
	}

	// Exactly what internal/governance's killUserSessions does.
	if err := svc.redis.Client.Set(ctx,
		revocation.UserTokensRevokedAtKey(user),
		revocation.MarkerValue(time.Now()),
		revocation.MarkerTTL).Err(); err != nil {
		t.Fatalf("write the marker: %v", err)
	}

	revoked, err = svc.IsAccessTokenRevoked(ctx, "some-token", user, issuedAt)
	if err != nil {
		t.Fatalf("IsAccessTokenRevoked: %v", err)
	}
	if !revoked {
		t.Error("the access review revoked this user and their token still works; the marker was written where the check does not look")
	}

	// A token minted after the revocation is a fresh login and must work.
	revoked, err = svc.IsAccessTokenRevoked(ctx, "some-token", user, time.Now().Add(time.Minute).Unix())
	if err != nil {
		t.Fatalf("IsAccessTokenRevoked: %v", err)
	}
	if revoked {
		t.Error("a token issued after the revocation was refused; re-authenticating would not help the user")
	}
}

func TestLogoutAllAndAnAccessReviewUseTheSameMarker(t *testing.T) {
	// MarkUserTokensRevoked is /oauth/logout-all's writer. Whatever it writes,
	// governance must be able to write too -- one marker, two callers.
	svc, mini := revocationMarkerService(t)
	ctx := context.Background()
	const user = "22222222-0000-0000-0000-000000000002"

	if err := svc.MarkUserTokensRevoked(ctx, user); err != nil {
		t.Fatalf("MarkUserTokensRevoked: %v", err)
	}
	key := revocation.UserTokensRevokedAtKey(user)
	v, err := mini.Get(key)
	if err != nil {
		t.Fatalf("logout-all did not write %s, so governance writing it would be writing somewhere else: %v", key, err)
	}
	if _, err := revocation.ParseMarker(v); err != nil {
		t.Errorf("logout-all wrote a value the shared parser cannot read: %v", err)
	}
	if ttl := mini.TTL(key); ttl <= 0 || ttl > revocation.MarkerTTL {
		t.Errorf("marker TTL is %v, want a positive value no greater than %v", ttl, revocation.MarkerTTL)
	}
}

func TestATokenIssuedInTheSameSecondAsTheRevocationIsRefused(t *testing.T) {
	// Redis stores seconds. A strict `<` comparison would leave a one-second
	// window in which a token minted at the very moment somebody said "revoke
	// everything" keeps working -- which is exactly when a compromised session
	// is racing the operator.
	now := time.Now().Unix()
	if !revocation.IsRevoked(now, now) {
		t.Error("a token issued in the same second as the revocation survived it")
	}
	if revocation.IsRevoked(now+1, now) {
		t.Error("a token issued after the revocation was refused")
	}
	if revocation.IsRevoked(0, now) {
		t.Error("a missing iat was treated as revoked; that would refuse tokens no one revoked")
	}
	if revocation.IsRevoked(now, 0) {
		t.Error("an absent marker revoked a token")
	}
}
