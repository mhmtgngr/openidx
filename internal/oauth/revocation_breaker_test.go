package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/resilience"
)

// TestRevocationBreakerFastFailsOnRedisOutage proves Tier 2.8: once Redis is
// unreachable, the revocation-check circuit breaker opens and IsAccessTokenRevoked
// returns FAST (an error the caller fails-closed on) instead of every request
// paying the Redis read timeout. Being able to open cheaply is the whole point.
func TestRevocationBreakerFastFailsOnRedisOutage(t *testing.T) {
	mini := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{
		Addr: mini.Addr(),
		// Tight timeouts so the test is fast even before the breaker opens.
		ReadTimeout:  200 * time.Millisecond,
		DialTimeout:  200 * time.Millisecond,
		WriteTimeout: 200 * time.Millisecond,
		MaxRetries:   -1,
	})
	defer rc.Close()

	s := &Service{
		redis:  &database.RedisClient{Client: rc},
		logger: zap.NewNop(),
		redisBreaker: resilience.NewCircuitBreaker(resilience.CircuitBreakerConfig{
			Name:         "test-oauth-redis-revocation",
			Threshold:    3,
			ResetTimeout: time.Second,
			Logger:       zap.NewNop(),
		}),
	}

	ctx := context.Background()

	// Healthy: a normal check succeeds and reports "not revoked".
	if revoked, err := s.IsAccessTokenRevoked(ctx, "tok", "user-1", time.Now().Unix()); err != nil || revoked {
		t.Fatalf("healthy check: revoked=%v err=%v, want false/nil", revoked, err)
	}
	if got := s.redisBreaker.State(); got != resilience.StateClosed {
		t.Fatalf("breaker should be closed while Redis is healthy, got %v", got)
	}

	// Redis goes down.
	mini.Close()

	// Drive enough failures to trip the breaker (threshold=3).
	for i := 0; i < 3; i++ {
		if _, err := s.IsAccessTokenRevoked(ctx, "tok", "user-1", time.Now().Unix()); err == nil {
			t.Fatalf("call %d: expected an error while Redis is down", i)
		}
	}

	// Breaker must now be OPEN so subsequent calls fail fast.
	if got := s.redisBreaker.State(); got != resilience.StateOpen {
		t.Fatalf("breaker should be open after repeated Redis failures, got %v", got)
	}

	// A call while open should return quickly (well under the Redis read timeout)
	// and still surface an error so the caller fails closed.
	start := time.Now()
	revoked, err := s.IsAccessTokenRevoked(ctx, "tok", "user-1", time.Now().Unix())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("open breaker should still surface an error (caller fails closed)")
	}
	if revoked {
		t.Fatal("error path must not report a token as revoked=true")
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("open breaker should fast-fail, took %v", elapsed)
	}
}
