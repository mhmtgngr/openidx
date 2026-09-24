package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A Redis restart used to be a login outage of exactly its own length: the
// first failed INCR turned every auth request into a 503. With a bounded local
// window the blip costs nothing, the tier is still enforced (from a per-replica
// share), and a real outage still fails closed once the window is spent.
func TestDistributedRateLimit_RedisBlipIsRiddenOutLocally(t *testing.T) {
	// The five requests below must fall in one auth window: the local share is
	// counted per window epoch, so a sequence that straddles a minute boundary
	// splits across two buckets and never reaches the limit. On a loaded CI
	// runner, with the Redis client retrying its dials, the sequence took over
	// a second and crossed 21:41:59 -> 21:42:00, and the fourth login came back
	// 200 instead of 429.
	startInsideWindow(t, time.Minute, 15*time.Second)

	s, client := setupExtendedTestRedis(t)
	cfg := RateLimitConfig{
		Requests: 100, Window: time.Minute,
		AuthRequests: 6, AuthWindow: time.Minute,
		LocalFallbackMax: 60 * time.Second,
		ReplicaCountHint: 3, // per-replica share = 2
	}
	r := newRateLimitRouter(client, cfg)

	require.Equal(t, http.StatusOK, doReq(r, http.MethodPost, "/oauth/login"))

	s.Close() // Redis goes away

	// Two logins from this source are admitted (6 / 3 replicas), the third is
	// limited — enforced, not open, not closed.
	assert.Equal(t, http.StatusOK, doReq(r, http.MethodPost, "/oauth/login"))
	assert.Equal(t, http.StatusOK, doReq(r, http.MethodPost, "/oauth/login"))
	w := doReqRec(r, http.MethodPost, "/oauth/login")
	assert.Equal(t, http.StatusTooManyRequests, w.Code, "the local share is enforced, not fail-open")
	assert.NotEmpty(t, w.Header().Get("Retry-After"))

	// A different source has its own share.
	assert.Equal(t, http.StatusOK, doReqFrom(r, http.MethodPost, "/oauth/login", "198.51.100.2"))

	// Non-auth paths keep failing open, as before.
	assert.Equal(t, http.StatusOK, doReq(r, http.MethodGet, "/api/v1/identity/users"))
}

// Past the window the limiter is back to fail-closed: a long outage must not
// leave the fleet on hint× the intended rate indefinitely.
func TestDistributedRateLimit_FallbackWindowExpiresToFailClosed(t *testing.T) {
	cfg := RateLimitConfig{Requests: 100, Window: time.Minute, AuthRequests: 10, AuthWindow: time.Minute,
		LocalFallbackMax: 150 * time.Millisecond, ReplicaCountHint: 1}
	r := newRateLimitRouter(nil, cfg) // Redis never there

	assert.Equal(t, http.StatusOK, doReq(r, http.MethodPost, "/oauth/login"), "inside the window: served locally")
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, http.StatusServiceUnavailable, doReq(r, http.MethodPost, "/oauth/login"), "past the window: fail closed")
}

// Zero keeps the strict contract the existing tests pin: first failure = 503.
func TestDistributedRateLimit_ZeroWindowIsStrictFailClosed(t *testing.T) {
	cfg := RateLimitConfig{Requests: 100, Window: time.Minute, AuthRequests: 10, AuthWindow: time.Minute}
	r := newRateLimitRouter(nil, cfg)
	assert.Equal(t, http.StatusServiceUnavailable, doReq(r, http.MethodPost, "/oauth/login"))
}

// When Redis comes back, the clock resets and counting moves back to Redis;
// the next outage gets a fresh window rather than the tail of the old one.
func TestDistributedRateLimit_RecoveryResetsTheWindow(t *testing.T) {
	s, client := setupExtendedTestRedis(t)
	cfg := RateLimitConfig{Requests: 100, Window: time.Minute, AuthRequests: 10, AuthWindow: time.Minute,
		LocalFallbackMax: 200 * time.Millisecond, ReplicaCountHint: 1}
	r := newRateLimitRouter(client, cfg)

	s.Close()
	assert.Equal(t, http.StatusOK, doReq(r, http.MethodPost, "/oauth/login"))
	time.Sleep(120 * time.Millisecond)

	// Redis returns at the same address.
	require.NoError(t, s.Restart())
	assert.Equal(t, http.StatusOK, doReq(r, http.MethodPost, "/oauth/login"), "served from Redis again")

	// Outage again: a FRESH window, so 120ms later we are still inside it.
	s.Close()
	time.Sleep(120 * time.Millisecond)
	assert.Equal(t, http.StatusOK, doReq(r, http.MethodPost, "/oauth/login"), "fresh window after recovery")
}

// A Redis outage must not also be a memory exhaustion: a flood of distinct
// sources during the window fills the local map to its cap, after which NEW
// sources fail closed rather than allocate. Existing sources keep their share.
func TestLocalFallback_IsBoundedAndFailsClosedOnOverflow(t *testing.T) {
	f := newLocalFallback(3)
	const epoch = int64(1)
	for _, k := range []string{"a", "b", "c"} {
		out, _ := f.decide(k, epoch, 5, time.Minute)
		assert.Equal(t, fallbackAllowed, out)
	}
	out, _ := f.decide("d", epoch, 5, time.Minute)
	assert.Equal(t, fallbackOverflow, out, "fourth distinct key exceeds the cap")

	out, remaining := f.decide("a", epoch, 5, time.Minute)
	assert.Equal(t, fallbackAllowed, out, "known keys still served")
	assert.Equal(t, 3, remaining)

	// A new window sweeps old buckets and frees room.
	out, _ = f.decide("d", epoch+1, 5, time.Minute)
	assert.Equal(t, fallbackAllowed, out)
}

func TestPerReplicaQuota(t *testing.T) {
	assert.Equal(t, 2, perReplicaQuota(6, 3))
	assert.Equal(t, 6, perReplicaQuota(6, 0), "no hint = whole limit")
	assert.Equal(t, 1, perReplicaQuota(2, 10), "never zero: that would be fail-closed wearing a different name")
}

// startInsideWindow waits for the next window when fewer than need remain in
// the current one. The limiter's window epoch is the wall clock divided by
// the window (ratelimit.go), so a test that counts requests into one window
// has to start far enough from its end to finish inside it.
func startInsideWindow(t *testing.T, window, need time.Duration) {
	t.Helper()
	into := time.Duration(time.Now().UnixNano()) % window
	if left := window - into; left < need {
		time.Sleep(left + 100*time.Millisecond)
	}
}

// doReqRec is doReq but returns the recorder so headers can be asserted.
func doReqRec(r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	r.ServeHTTP(w, req)
	return w
}
