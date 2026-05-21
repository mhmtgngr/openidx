package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// newRateLimitRouter builds a gin engine with the distributed rate limiter and
// a catch-all handler that returns 200, so tests can assert middleware behavior.
func newRateLimitRouter(client *redis.Client, cfg RateLimitConfig) *gin.Engine {
	r := gin.New()
	r.Use(DistributedRateLimit(client, cfg, zap.NewNop()))
	r.Any("/*any", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func doReq(r *gin.Engine, method, path string) int {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	r.ServeHTTP(w, req)
	return w.Code
}

func TestDistributedRateLimit_AuthFailsClosedWhenRedisNil(t *testing.T) {
	cfg := RateLimitConfig{Requests: 100, Window: time.Minute, AuthRequests: 5, AuthWindow: time.Minute}
	r := newRateLimitRouter(nil, cfg) // no Redis backend

	// Auth path must fail closed (503) so brute-force protection isn't lost.
	assert.Equal(t, http.StatusServiceUnavailable, doReq(r, http.MethodPost, "/oauth/login"))
	assert.Equal(t, http.StatusServiceUnavailable, doReq(r, http.MethodPost, "/api/v1/identity/users/forgot-password"))

	// Non-auth path stays available (fail open).
	assert.Equal(t, http.StatusOK, doReq(r, http.MethodGet, "/api/v1/identity/users"))
}

func TestDistributedRateLimit_AuthFailsClosedWhenRedisDown(t *testing.T) {
	s, client := setupExtendedTestRedis(t)
	cfg := RateLimitConfig{Requests: 100, Window: time.Minute, AuthRequests: 5, AuthWindow: time.Minute}
	r := newRateLimitRouter(client, cfg)

	// While Redis is up, auth requests are allowed.
	assert.Equal(t, http.StatusOK, doReq(r, http.MethodPost, "/oauth/token"))

	// Simulate Redis being down: auth requests must now be rejected.
	s.Close()
	assert.Equal(t, http.StatusServiceUnavailable, doReq(r, http.MethodPost, "/oauth/token"))
	// Non-auth still fails open.
	assert.Equal(t, http.StatusOK, doReq(r, http.MethodGet, "/api/v1/identity/users"))
}

func TestDistributedRateLimit_AuthFailOpenOptOut(t *testing.T) {
	cfg := RateLimitConfig{Requests: 100, Window: time.Minute, AuthRequests: 5, AuthWindow: time.Minute, AuthFailOpen: true}
	r := newRateLimitRouter(nil, cfg)

	// Opted into availability-over-enforcement: auth path is allowed.
	assert.Equal(t, http.StatusOK, doReq(r, http.MethodPost, "/oauth/login"))
}

func TestIsAuthPath_CoversSensitiveEndpoints(t *testing.T) {
	authy := []string{
		"/oauth/login",
		"/oauth/token",
		"/oauth/mfa-verify",
		"/oauth/mfa-send-otp",
		"/oauth/stepup-verify",
		"/oauth/magic-link",
		"/oauth/magic-link-verify", // covered by the /oauth/magic-link prefix
		"/api/v1/identity/users/login",
		"/api/v1/identity/users/forgot-password",
		"/api/v1/identity/users/reset-password",
	}
	for _, p := range authy {
		assert.Truef(t, isAuthPath(p), "expected %s to be treated as an auth path", p)
	}

	notAuthy := []string{"/api/v1/identity/users", "/health", "/oauth/userinfo"}
	for _, p := range notAuthy {
		assert.Falsef(t, isAuthPath(p), "did not expect %s to be an auth path", p)
	}
}
