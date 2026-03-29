// Package middleware provides benchmark tests for rate limiting
package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// BenchmarkRateLimitCheck benchmarks the in-memory rate limit check
func BenchmarkRateLimitCheck(b *testing.B) {
	// Use in-memory rate limiter (non-distributed)
	cfg := RateLimitConfig{
		Requests: 100,
		Window:   time.Minute,
	}

	limiter := RateLimit(cfg.Requests, cfg.Window)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

// BenchmarkRateLimitAllow benchmarks rate limit checks within the allowed threshold
func BenchmarkRateLimitAllow(b *testing.B) {
	cfg := RateLimitConfig{
		Requests: 10000, // High limit to stay within threshold during benchmark
		Window:   time.Minute,
	}

	limiter := RateLimit(cfg.Requests, cfg.Window)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

// BenchmarkRateLimitMultipleIPs benchmarks rate limiting across different IP addresses
func BenchmarkRateLimitMultipleIPs(b *testing.B) {
	cfg := RateLimitConfig{
		Requests: 100,
		Window:   time.Minute,
	}

	limiter := RateLimit(cfg.Requests, cfg.Window)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Use different IPs to avoid hitting rate limit
	ips := make([]string, 100)
	for i := 0; i < 100; i++ {
		ips[i] = "192.168.1." + string(rune('1'+i%10))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = ips[i%len(ips)] + ":12345"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

// BenchmarkRateLimitAuthPath benchmarks rate limiting on auth-sensitive paths
func BenchmarkRateLimitAuthPath(b *testing.B) {
	cfg := RateLimitConfig{
		Requests:     100,
		Window:       time.Minute,
		AuthRequests: 10, // Stricter limit for auth paths
		AuthWindow:   time.Minute,
	}

	limiter := RateLimit(cfg.Requests, cfg.Window)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(limiter)
	router.POST("/oauth/login", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/oauth/login", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

// BenchmarkRateLimitSkipPath benchmarks rate limit skipping for health endpoints
func BenchmarkRateLimitSkipPath(b *testing.B) {
	cfg := RateLimitConfig{
		Requests: 1, // Very low limit
		Window:   time.Minute,
	}

	limiter := RateLimit(cfg.Requests, cfg.Window)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(limiter)
	router.GET("/health", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/health", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

// BenchmarkDistributedRateLimit benchmarks Redis-backed distributed rate limiting
func BenchmarkDistributedRateLimit(b *testing.B) {
	// Try to connect to Redis
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		b.Skip("Skipping distributed benchmark: redis not available")
	}

	cfg := RateLimitConfig{
		Requests:     1000,
		Window:       time.Minute,
		AuthRequests: 100,
		AuthWindow:   time.Minute,
		PerUser:      false,
	}

	logger := zap.NewNop()
	limiter := DistributedRateLimit(client, cfg, logger)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1." + string(rune('1'+b.N%10)) + ":12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

// BenchmarkDistributedRateLimitPerUser benchmarks per-user rate limiting
func BenchmarkDistributedRateLimitPerUser(b *testing.B) {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		b.Skip("Skipping distributed benchmark: redis not available")
	}

	cfg := RateLimitConfig{
		Requests: 1000,
		Window:   time.Minute,
		PerUser:  true, // Track per-user
	}

	logger := zap.NewNop()
	limiter := DistributedRateLimit(client, cfg, logger)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	userIDs := make([]string, 50)
	for i := 0; i < 50; i++ {
		userIDs[i] = "user-" + string(rune('A'+i%26))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.100:12345"

		w := httptest.NewRecorder()
		// Set user context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userIDs[i%len(userIDs)])

		// Call middleware directly
		limiter(c)
		if !c.IsAborted() {
			c.Status(http.StatusOK)
		}
	}
}

// BenchmarkRateLimitHeaders benchmarks rate limit header generation
func BenchmarkRateLimitHeaders(b *testing.B) {
	cfg := RateLimitConfig{
		Requests: 100,
		Window:   time.Minute,
	}

	limiter := RateLimit(cfg.Requests, cfg.Window)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		// Access headers (this is what we're benchmarking)
		_ = w.Header().Get("X-RateLimit-Limit")
		_ = w.Header().Get("X-RateLimit-Remaining")
	}
}

// BenchmarkRateLimitBlocked benchmarks requests that are blocked by rate limit
func BenchmarkRateLimitBlocked(b *testing.B) {
	cfg := RateLimitConfig{
		Requests: 1, // Very low limit to trigger blocking
		Window:   time.Minute,
	}

	limiter := RateLimit(cfg.Requests, cfg.Window)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

// BenchmarkIsAuthPath benchmarks the auth path detection function
func BenchmarkIsAuthPath(b *testing.B) {
	testPaths := []string{
		"/oauth/login",
		"/api/v1/users",
		"/health",
		"/oauth/token",
		"/api/v1/identity/users/login",
		"/oauth/authorize/callback",
		"/api/v1/identity/users",
		"/metrics",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := testPaths[i%len(testPaths)]
		_ = isAuthPath(path)
	}
}

// BenchmarkConcurrentRequests benchmarks concurrent rate limit requests
func BenchmarkConcurrentRequests(b *testing.B) {
	cfg := RateLimitConfig{
		Requests: 1000,
		Window:   time.Minute,
	}

	limiter := RateLimit(cfg.Requests, cfg.Window)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1." + string(rune('1'+(i%10))) + ":12345"
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			i++
		}
	})
}
