package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/common/zitisyncq"
)

func TestPopulateLoginHistory_UsesPreResetStats(t *testing.T) {
	prev := time.Now().Add(-30 * time.Minute)
	u := &identity.User{ID: "u1", FailedLoginCount: 0, HasPriorLoginStats: true, PriorFailedLoginCount: 3, PriorLastLoginAt: &prev}
	var gotBefore time.Time
	lookup := func(_ context.Context, id string, before time.Time) (string, float64, float64, time.Time, bool) {
		gotBefore = before
		return "198.51.100.7", 41.0082, 28.9784, prev, true
	}
	lc := &identity.LoginContext{}
	populateLoginHistory(context.Background(), lc, u, lookup)
	if lc.FailedAttempts != 3 || lc.LastLoginIP != "198.51.100.7" || lc.LastLoginLat != 41.0082 || lc.LastLoginTime == nil {
		t.Fatalf("history not populated: %+v", lc)
	}
	if !gotBefore.Equal(prev) {
		t.Fatalf("lookup bound = %v, want previous last_login_at", gotBefore)
	}
}

func TestPopulateLoginHistory_NoHistory(t *testing.T) {
	lc := &identity.LoginContext{}
	populateLoginHistory(context.Background(), lc, &identity.User{ID: "u", FailedLoginCount: 2}, nil)
	if lc.FailedAttempts != 2 || lc.LastLoginTime != nil {
		t.Fatalf("unexpected: %+v", lc)
	}
}

func TestRequestBrowZerUserSync_Queues(t *testing.T) {
	m := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: m.Addr()})
	s := &Service{redis: &database.RedisClient{Client: rc}}
	s.requestBrowZerUserSync(context.Background(), "user-1")
	if got := zitisyncq.Drain(context.Background(), rc, 5); len(got) != 1 || got[0] != "user-1" {
		t.Fatalf("queued = %v", got)
	}
	(&Service{}).requestBrowZerUserSync(context.Background(), "u") // nil-safe
}
