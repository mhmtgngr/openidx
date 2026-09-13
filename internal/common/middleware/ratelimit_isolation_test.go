package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/common/database"
)

// The rate limiter is the one Redis consumer an attacker can drive at will: a
// flood of source addresses is a flood of counter keys. When counters share an
// instance with login state and revocation markers, that flood either OOMs the
// login path (noeviction) or evicts a revocation marker (allkeys-lru). This
// test pins the isolation contract at the seam the services use: given a
// RedisClient with a dedicated rate-limit role, the limiter writes to that role
// and only that role, and the primary sees no counter at all.
func TestDistributedRateLimit_WritesOnlyToTheRateLimitRole(t *testing.T) {
	primaryMini, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(primaryMini.Close)
	rlMini, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(rlMini.Close)

	primary := redis.NewClient(&redis.Options{Addr: primaryMini.Addr()})
	rl := redis.NewClient(&redis.Options{Addr: rlMini.Addr()})
	t.Cleanup(func() { _ = primary.Close(); _ = rl.Close() })

	rc := database.NewRedisClientWithRoles(primary, rl, nil)
	cfg := RateLimitConfig{Requests: 3, Window: time.Minute, AuthRequests: 2, AuthWindow: time.Minute}
	r := newRateLimitRouter(rc.RateLimitDB(), cfg)

	// Ten distinct "attackers" against the auth tier: the fourth request from
	// each is refused, and every counter lives on the rate-limit instance.
	for i := 0; i < 10; i++ {
		ip := "203.0.113." + string(rune('0'+i))
		for n := 0; n < 3; n++ {
			w := doReqFrom(r, http.MethodPost, "/oauth/login", ip)
			if n < 2 {
				assert.Equal(t, http.StatusOK, w)
			} else {
				assert.Equal(t, http.StatusTooManyRequests, w)
			}
		}
	}

	assert.Empty(t, primaryMini.Keys(), "the primary (session/revocation) instance must never see a rate-limit counter")
	assert.Len(t, rlMini.Keys(), 10, "one sliding-window counter per source on the rate-limit instance")
	for _, k := range rlMini.Keys() {
		assert.Contains(t, k, "ratelimit:")
		ttl := rlMini.TTL(k)
		assert.Greater(t, ttl, time.Duration(0), "every counter must carry a TTL so an LRU instance can also age it out")
	}
}

// Losing the rate-limit instance keeps its existing contract (auth fails closed,
// everything else fails open) and — the point of the split — the primary's
// session keys are untouched by the outage.
func TestDistributedRateLimit_RateLimitRoleOutageDoesNotTouchPrimary(t *testing.T) {
	primaryMini, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(primaryMini.Close)
	rlMini, err := miniredis.Run()
	require.NoError(t, err)

	primary := redis.NewClient(&redis.Options{Addr: primaryMini.Addr()})
	rl := redis.NewClient(&redis.Options{Addr: rlMini.Addr(), MaxRetries: 0})
	t.Cleanup(func() { _ = primary.Close(); _ = rl.Close() })
	require.NoError(t, primaryMini.Set("login_session:abc", "params"))

	rc := database.NewRedisClientWithRoles(primary, rl, nil)
	r := newRateLimitRouter(rc.RateLimitDB(), RateLimitConfig{Requests: 100, Window: time.Minute, AuthRequests: 5, AuthWindow: time.Minute})

	rlMini.Close() // the counter instance dies

	assert.Equal(t, http.StatusServiceUnavailable, doReq(r, http.MethodPost, "/oauth/login"))
	assert.Equal(t, http.StatusOK, doReq(r, http.MethodGet, "/api/v1/identity/users"))

	v, err := primaryMini.Get("login_session:abc")
	require.NoError(t, err)
	assert.Equal(t, "params", v, "session state on the primary survives a rate-limit instance outage")
}

// doReqFrom issues a request whose peer address is ip, so the per-IP bucket is
// the one under test rather than httptest's fixed default.
func doReqFrom(r *gin.Engine, method, path, ip string) int {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = ip + ":40000"
	r.ServeHTTP(w, req)
	return w.Code
}
