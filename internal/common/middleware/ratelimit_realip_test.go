package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Behind an edge, the per-IP limiter is only as good as the client-IP chain in
// front of it. If the services do not trust the edge's hop, every request
// resolves to the edge's own address and the whole world shares one bucket:
// one attacker can 429 everyone, and a brute force from a thousand sources
// looks like one client. If the services trust EVERY hop, the caller picks its
// own bucket. This test pins the middle: with the edge's CIDR trusted, two
// clients arriving through the same edge address land in two buckets, and a
// caller that is not a trusted hop cannot move itself by sending the header.
func newRealIPRouter(t *testing.T, trusted, edgeCIDRs string) (*gin.Engine, *miniredis.Miniredis) {
	t.Helper()
	t.Setenv("OIDX_TRUSTED_PROXIES", trusted)
	t.Setenv("OIDX_EDGE_TRUSTED_CIDRS", edgeCIDRs)

	mini, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mini.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	gin.SetMode(gin.TestMode)
	r := gin.New()
	ConfigureTrustedProxies(r, zap.NewNop())
	r.Use(DistributedRateLimit(rdb, RateLimitConfig{Requests: 100, Window: time.Minute, AuthRequests: 2, AuthWindow: time.Minute}, zap.NewNop()))
	r.Any("/*any", func(c *gin.Context) { c.String(http.StatusOK, c.ClientIP()) })
	return r, mini
}

func viaEdge(r *gin.Engine, peer, xff string) (int, string) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/login", nil)
	req.RemoteAddr = peer + ":51000"
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	r.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func TestRateLimit_TrustedEdgeYieldsOneBucketPerClient(t *testing.T) {
	r, mini := newRealIPRouter(t, "10.42.0.0/16", "")

	// Two clients, same edge hop. Each gets its own budget of 2.
	for i := 0; i < 2; i++ {
		code, ip := viaEdge(r, "10.42.7.7", "203.0.113.10")
		assert.Equal(t, http.StatusOK, code)
		assert.Equal(t, "203.0.113.10", ip)
	}
	code, _ := viaEdge(r, "10.42.7.7", "203.0.113.10")
	assert.Equal(t, http.StatusTooManyRequests, code, "third attempt from client A is refused")

	code, ip := viaEdge(r, "10.42.7.7", "203.0.113.11")
	assert.Equal(t, http.StatusOK, code, "client B behind the same edge hop is a different bucket")
	assert.Equal(t, "203.0.113.11", ip)

	var buckets []string
	for _, k := range mini.Keys() {
		if strings.HasPrefix(k, "ratelimit:ip:") {
			buckets = append(buckets, k)
		}
	}
	assert.Len(t, buckets, 2, "one counter per real client, none for the edge's own address")
	for _, k := range buckets {
		assert.NotContains(t, k, "10.42.7.7", "the edge hop must never be the bucket key")
	}
}

func TestRateLimit_UntrustedEdgeCollapsesToOneBucket(t *testing.T) {
	// The failure mode this task exists to remove: nothing trusted but
	// loopback, so the edge's address is the client for everyone.
	r, mini := newRealIPRouter(t, "", "")

	code, ip := viaEdge(r, "10.42.7.7", "203.0.113.10")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "10.42.7.7", ip, "with the edge untrusted the client IS the edge")
	viaEdge(r, "10.42.7.7", "203.0.113.11")
	code, _ = viaEdge(r, "10.42.7.7", "203.0.113.12")
	assert.Equal(t, http.StatusTooManyRequests, code, "a third, unrelated client is refused: one shared bucket")

	n := 0
	for _, k := range mini.Keys() {
		if strings.HasPrefix(k, "ratelimit:ip:") {
			n++
			assert.Contains(t, k, "10.42.7.7")
		}
	}
	assert.Equal(t, 1, n)
}

func TestRateLimit_CallerCannotChooseItsBucketByForgingTheHeader(t *testing.T) {
	r, _ := newRealIPRouter(t, "10.42.0.0/16", "")

	// A direct caller (not a trusted hop) sends a forged header. gin must
	// resolve it to its own peer address and keep it in ONE bucket no matter
	// how many addresses it claims.
	for i, forged := range []string{"203.0.113.50", "203.0.113.51", "203.0.113.52"} {
		code, ip := viaEdge(r, "198.51.100.9", forged)
		if i < 2 {
			assert.Equal(t, http.StatusOK, code)
			assert.Equal(t, "198.51.100.9", ip, "forged header from an untrusted peer is ignored")
		} else {
			assert.Equal(t, http.StatusTooManyRequests, code, "third request from the same untrusted peer is refused despite three different forged addresses")
		}
	}
}

func TestRateLimit_EdgeCIDRListIsUnionedAndCannotBeWildcard(t *testing.T) {
	// The provider list arrives through OIDX_EDGE_TRUSTED_CIDRS and adds to
	// the operator's list. A "*" in it is dropped, not honoured.
	r, _ := newRealIPRouter(t, "10.42.0.0/16", "173.245.48.0/20, *")

	_, ip := viaEdge(r, "173.245.48.5", "203.0.113.20")
	assert.Equal(t, "203.0.113.20", ip, "a hop in the edge CIDR list is trusted")

	_, ip = viaEdge(r, "10.42.1.1", "203.0.113.21")
	assert.Equal(t, "203.0.113.21", ip, "the operator's own list still applies")

	_, ip = viaEdge(r, "198.51.100.9", "203.0.113.22")
	assert.Equal(t, "198.51.100.9", ip, "\"*\" inside the edge list did not widen trust to everyone")
}
