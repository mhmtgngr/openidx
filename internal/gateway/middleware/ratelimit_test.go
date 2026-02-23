// Package middleware provides rate limiting middleware tests
package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/gateway"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// mockRateLimitLogger implements gateway.Logger
type mockRateLimitLogger struct {
	warnCount int
	lastMsg   string
}

func (m *mockRateLimitLogger) Debug(msg string, fields ...interface{}) {}
func (m *mockRateLimitLogger) Info(msg string, fields ...interface{})  {}
func (m *mockRateLimitLogger) Warn(msg string, fields ...interface{}) {
	m.warnCount++
	m.lastMsg = msg
}
func (m *mockRateLimitLogger) Error(msg string, fields ...interface{}) {}
func (m *mockRateLimitLogger) Fatal(msg string, fields ...interface{}) {}
func (m *mockRateLimitLogger) Sync() error                             { return nil }

// setupTestRedis creates a miniredis client for testing
func setupTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	s, err := miniredis.Run()
	require.NoError(t, err)

	client := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	return s, client
}

func TestNewRateLimitMiddleware(t *testing.T) {
	t.Run("Creates middleware with valid config", func(t *testing.T) {
		logger := &mockRateLimitLogger{}
		_, redisClient := setupTestRedis(t)
		defer redisClient.Close()

		config := gateway.RateLimitConfig{
			RequestsPerMinute:     100,
			AuthRequestsPerMinute: 20,
			WindowSeconds:         60,
		}

		middleware := NewRateLimitMiddleware(redisClient, logger, config)

		assert.NotNil(t, middleware)
		assert.Equal(t, 100, middleware.requestsPerMin)
		assert.Equal(t, 20, middleware.authRequestsPerMin)
		assert.Equal(t, 60, middleware.windowSeconds)
	})
}

func TestRateLimitMiddleware_AllowsWithinLimit(t *testing.T) {
	t.Run("Allows requests within limit", func(t *testing.T) {
		logger := &mockRateLimitLogger{}
		s, redisClient := setupTestRedis(t)
		defer s.Close()

		config := gateway.RateLimitConfig{
			RequestsPerMinute:     5,
			AuthRequestsPerMinute: 3,
			WindowSeconds:         60,
		}

		middleware := NewRateLimitMiddleware(redisClient, logger, config)

		router := gin.New()
		router.Use(middleware.RateLimit("test-service"))
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		// Make requests within limit
		for i := 0; i < 5; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.1:1234"
			router.ServeHTTP(w, req)

			assert.Equal(t, 200, w.Code, "Request %d should succeed", i+1)
			assert.NotEmpty(t, w.Header().Get("X-RateLimit-Limit"))
			assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"))
		}
	})
}

func TestRateLimitMiddleware_BlocksWhenExceeded(t *testing.T) {
	t.Run("Blocks requests when exceeded", func(t *testing.T) {
		logger := &mockRateLimitLogger{}
		s, redisClient := setupTestRedis(t)
		defer s.Close()

		config := gateway.RateLimitConfig{
			RequestsPerMinute:     3,
			AuthRequestsPerMinute: 2,
			WindowSeconds:         60,
		}

		middleware := NewRateLimitMiddleware(redisClient, logger, config)

		router := gin.New()
		router.Use(middleware.RateLimit("test-service"))
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		// Use up the limit
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.2:1234"
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}

		// Next request should be blocked
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.2:1234"
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Contains(t, w.Body.String(), "rate limit exceeded")
	})
}

func TestRateLimitMiddleware_AuthRequests(t *testing.T) {
	t.Run("Auth requests use lower limit", func(t *testing.T) {
		logger := &mockRateLimitLogger{}
		s, redisClient := setupTestRedis(t)
		defer s.Close()

		config := gateway.RateLimitConfig{
			RequestsPerMinute:     100,
			AuthRequestsPerMinute: 3,
			WindowSeconds:         60,
		}

		middleware := NewRateLimitMiddleware(redisClient, logger, config)

		router := gin.New()
		router.Use(middleware.RateLimit("test-service"))
		router.POST("/api/v1/oauth/token", func(c *gin.Context) {
			c.String(200, "OK")
		})

		// Auth endpoint should use lower limit
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/api/v1/oauth/token", nil)
			req.RemoteAddr = "192.168.1.3:1234"
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}

		// 4th request should be blocked
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/oauth/token", nil)
		req.RemoteAddr = "192.168.1.3:1234"
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})
}

func TestRateLimitMiddleware_UserBased(t *testing.T) {
	t.Run("User-based rate limiting", func(t *testing.T) {
		logger := &mockRateLimitLogger{}
		s, redisClient := setupTestRedis(t)
		defer s.Close()

		config := gateway.RateLimitConfig{
			RequestsPerMinute:     5,
			AuthRequestsPerMinute: 3,
			WindowSeconds:         60,
		}

		middleware := NewRateLimitMiddleware(redisClient, logger, config)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("user_id", "user-123")
			c.Next()
		})
		router.Use(middleware.RateLimit("test-service"))
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		// Make requests for user
		for i := 0; i < 5; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.4:1234"
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}

		// 6th should be blocked
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.4:1234"
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})
}

func TestSlidingWindowRateLimit(t *testing.T) {
	t.Run("Creates sliding window rate limiter", func(t *testing.T) {
		logger := &mockRateLimitLogger{}
		s, redisClient := setupTestRedis(t)
		defer s.Close()

		limiter := NewSlidingWindowRateLimit(redisClient, logger, 10, 60)

		assert.NotNil(t, limiter)
		assert.Equal(t, 10, limiter.limit)
		assert.Equal(t, 60, limiter.windowSeconds)
	})

	t.Run("Allows requests within sliding window limit", func(t *testing.T) {
		logger := &mockRateLimitLogger{}
		s, redisClient := setupTestRedis(t)
		defer s.Close()

		limiter := NewSlidingWindowRateLimit(redisClient, logger, 5, 60)

		// Make requests within limit
		for i := 0; i < 5; i++ {
			allowed, _, _, err := limiter.Check(context.Background(), "ip:10.1.1.1")
			require.NoError(t, err)
			assert.True(t, allowed, "Request %d should be allowed", i+1)
		}

		// Next should be blocked
		allowed, _, _, err := limiter.Check(context.Background(), "ip:10.1.1.1")
		require.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("Different identifiers have separate limits", func(t *testing.T) {
		logger := &mockRateLimitLogger{}
		s, redisClient := setupTestRedis(t)
		defer s.Close()

		limiter := NewSlidingWindowRateLimit(redisClient, logger, 2, 60)

		// IP1 uses up limit
		allowed, _, _, err := limiter.Check(context.Background(), "ip:10.1.1.2")
		require.NoError(t, err)
		assert.True(t, allowed)
		allowed, _, _, err = limiter.Check(context.Background(), "ip:10.1.1.2")
		require.NoError(t, err)
		assert.True(t, allowed)

		// IP1 blocked
		allowed, _, _, err = limiter.Check(context.Background(), "ip:10.1.1.2")
		require.NoError(t, err)
		assert.False(t, allowed)

		// IP2 should still be allowed
		allowed, _, _, err = limiter.Check(context.Background(), "ip:10.1.1.3")
		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("Window slides correctly", func(t *testing.T) {
		logger := &mockRateLimitLogger{}
		s, redisClient := setupTestRedis(t)
		defer s.Close()

		limiter := NewSlidingWindowRateLimit(redisClient, logger, 3, 2)

		// Use up the limit
		for i := 0; i < 3; i++ {
			allowed, _, _, err := limiter.Check(context.Background(), "ip:10.1.1.4")
			require.NoError(t, err)
			assert.True(t, allowed)
		}

		// Should be blocked
		allowed, _, _, err := limiter.Check(context.Background(), "ip:10.1.1.4")
		require.NoError(t, err)
		assert.False(t, allowed)

		// Fast forward time
		s.FastForward(3 * time.Second)

		// Should be allowed again
		allowed, _, _, err = limiter.Check(context.Background(), "ip:10.1.1.4")
		require.NoError(t, err)
		assert.True(t, allowed)
	})
}

func TestIPBasedRateLimit(t *testing.T) {
	t.Run("IP-based rate limiting works", func(t *testing.T) {
		logger := &mockRateLimitLogger{}
		s, redisClient := setupTestRedis(t)
		defer s.Close()

		router := gin.New()
		router.Use(IPBasedRateLimit(redisClient, logger, 3))
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		// Make requests within limit
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "10.1.1.5:9999"
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}

		// Should be blocked
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.1.1.5:9999"
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})

	t.Run("Different IPs have separate limits", func(t *testing.T) {
		logger := &mockRateLimitLogger{}
		s, redisClient := setupTestRedis(t)
		defer s.Close()

		router := gin.New()
		router.Use(IPBasedRateLimit(redisClient, logger, 2))
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		// IP1 uses up limit
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "10.1.1.6:8888"
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}

		// IP1 blocked
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.1.1.6:8888"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		// IP2 allowed
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.1.1.7:8888"
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code)
	})
}

func TestUserBasedRateLimit(t *testing.T) {
	t.Run("User-based rate limiting works", func(t *testing.T) {
		logger := &mockRateLimitLogger{}
		s, redisClient := setupTestRedis(t)
		defer s.Close()

		router := gin.New()
		router.Use(UserBasedRateLimit(redisClient, logger, 5))
		router.GET("/test", func(c *gin.Context) {
			// Simulate authenticated user
			c.Set("user_id", "user-456")
			c.String(200, "OK")
		})

		// Make requests within limit
		for i := 0; i < 5; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "10.2.2.1:7777"
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}

		// Should be blocked
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.2.2.1:7777"
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})
}

func TestGetRateLimitHeaders(t *testing.T) {
	t.Run("Returns rate limit headers", func(t *testing.T) {
		resetAt := time.Now().Add(60 * time.Second)

		headers := GetRateLimitHeaders(100, 75, resetAt)

		assert.Equal(t, "100", headers["X-RateLimit-Limit"])
		assert.Equal(t, "75", headers["X-RateLimit-Remaining"])
		assert.NotEmpty(t, headers["X-RateLimit-Reset"])
		assert.NotEmpty(t, headers["X-RateLimit-Reset-After"])
	})
}

// Benchmark tests
func BenchmarkRateLimitMiddleware(b *testing.B) {
	logger := &mockRateLimitLogger{}
	s, redisClient := setupTestRedis(&testing.T{})
	defer s.Close()

	config := gateway.RateLimitConfig{
		RequestsPerMinute:     1000,
		AuthRequestsPerMinute: 200,
		WindowSeconds:         60,
	}

	middleware := NewRateLimitMiddleware(redisClient, logger, config)

	router := gin.New()
	router.Use(middleware.RateLimit("test-service"))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:5555"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
