package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestDistributedRateLimit_UsernameKeyedLogin: with PerUser on, rotating the
// source IP does not reset the budget for one submitted username on
// /oauth/login, the handler still sees the full body, and another username
// is unaffected.
func TestDistributedRateLimit_UsernameKeyedLogin(t *testing.T) {
	resetMetrics()
	s, client := setupExtendedTestRedis(t)
	defer s.Close()

	cfg := RateLimitConfig{Requests: 100, Window: 60 * time.Second, AuthRequests: 3, AuthWindow: 60 * time.Second, PerUser: true}
	router := gin.New()
	router.Use(DistributedRateLimit(client, cfg, testLogger(t)))
	var seen string
	router.POST("/oauth/login", func(c *gin.Context) {
		b, _ := io.ReadAll(c.Request.Body)
		seen = string(b)
		c.String(http.StatusOK, "OK")
	})

	do := func(ip, body string) int {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/oauth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = ip + ":1234"
		router.ServeHTTP(w, req)
		return w.Code
	}

	body := `{"username":"Alice","password":"x"}`
	for i := 0; i < 3; i++ {
		assert.Equal(t, http.StatusOK, do("10.0.0."+string(rune('1'+i)), body))
		assert.Equal(t, body, seen, "body must be restored for the handler")
	}
	assert.Equal(t, http.StatusTooManyRequests, do("10.0.0.9", `{"username":" alice "}`))
	assert.Equal(t, http.StatusOK, do("10.0.0.9", `{"username":"bob"}`))
}

func TestDistributedRateLimit_UsernameKeyedOffByDefault(t *testing.T) {
	resetMetrics()
	s, client := setupExtendedTestRedis(t)
	defer s.Close()
	cfg := RateLimitConfig{Requests: 100, Window: 60 * time.Second, AuthRequests: 1, AuthWindow: 60 * time.Second}
	router := gin.New()
	router.Use(DistributedRateLimit(client, cfg, testLogger(t)))
	router.POST("/oauth/login", func(c *gin.Context) { c.String(http.StatusOK, "OK") })
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/oauth/login", strings.NewReader(`{"username":"alice"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = ip + ":1"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}
}

func TestPeekUsername_FormAndQuery(t *testing.T) {
	var rc io.ReadCloser = io.NopCloser(strings.NewReader("username=Carol&password=x"))
	assert.Equal(t, "carol", peekUsername(&rc, "application/x-www-form-urlencoded", nil))
	rest, _ := io.ReadAll(rc)
	assert.Equal(t, "username=Carol&password=x", string(rest))

	rc = io.NopCloser(strings.NewReader(""))
	assert.Equal(t, "dave@x", peekUsername(&rc, "", map[string][]string{"login_hint": {"Dave@X"}}))
	assert.True(t, isUsernameKeyedPath("/eam/authorize"))
	assert.False(t, isUsernameKeyedPath("/oauth/token"))
}
