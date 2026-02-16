package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// RateLimitConfig configures the distributed rate limiter
type RateLimitConfig struct {
	// Default rate limit (requests per window)
	Requests int
	// Default window duration
	Window time.Duration
	// Auth-sensitive paths get a stricter limit
	AuthRequests int
	// Auth window duration
	AuthWindow time.Duration
	// Whether to also track per-user (when user_id is in context)
	PerUser bool
}

// authPaths are paths that get the stricter auth rate limit tier
var authPaths = []string{
	"/oauth/login",
	"/oauth/mfa-verify",
	"/oauth/authorize/callback",
	"/oauth/token",
	"/api/v1/identity/users/login",
}

// skipPaths are paths exempt from rate limiting
var skipPaths = []string{
	"/health",
	"/metrics",
	"/ready",
}

// DistributedRateLimit implements Redis-backed distributed rate limiting using a
// sliding window counter. If Redis is unavailable, it fails open (allows the request).
func DistributedRateLimit(redisClient *redis.Client, cfg RateLimitConfig, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// Skip health/metrics/readiness endpoints
		for _, sp := range skipPaths {
			if path == sp {
				c.Next()
				return
			}
		}

		// Determine rate limit tier
		limit := cfg.Requests
		window := cfg.Window
		if isAuthPath(path) && cfg.AuthRequests > 0 {
			limit = cfg.AuthRequests
			window = cfg.AuthWindow
		}

		// Build key: per-IP by default, optionally per-user
		identifier := c.ClientIP()
		scope := "ip"
		if cfg.PerUser {
			if userID, exists := c.Get("user_id"); exists {
				if uid, ok := userID.(string); ok && uid != "" {
					identifier = uid
					scope = "user"
				}
			}
		}

		windowEpoch := time.Now().Unix() / int64(window.Seconds())
		key := fmt.Sprintf("ratelimit:%s:%s:%d", scope, identifier, windowEpoch)

		// If Redis is nil, fail open
		if redisClient == nil {
			rlFailOpenTotal.WithLabelValues(scope).Inc()
			c.Next()
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 200*time.Millisecond)
		defer cancel()

		count, err := redisClient.Incr(ctx, key).Result()
		if err != nil {
			// Fail open: allow request, log warning
			rlFailOpenTotal.WithLabelValues(scope).Inc()
			logger.Warn("Rate limit Redis error, failing open",
				zap.Error(err),
				zap.String("key", key))
			c.Next()
			return
		}

		// Set expiry on first increment
		if count == 1 {
			redisClient.Expire(ctx, key, window+time.Second)
		}

		// Set rate limit headers
		remaining := int64(limit) - count
		if remaining < 0 {
			remaining = 0
		}
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

		if count > int64(limit) {
			retryAfter := int64(window.Seconds()) - (time.Now().Unix() % int64(window.Seconds()))
			c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			rlHitsTotal.WithLabelValues(scope).Inc()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			return
		}

		c.Next()
	}
}

// isAuthPath checks if the request path matches an auth-sensitive path
func isAuthPath(path string) bool {
	for _, ap := range authPaths {
		if strings.HasPrefix(path, ap) {
			return true
		}
	}
	return false
}
