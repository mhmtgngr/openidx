// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// RateLimitConfig holds configuration for the rate limiter
type RateLimitConfig struct {
	// Requests per minute for IP-based limiting
	IPRequestsPerMin int
	// Requests per minute for user-based limiting (when authenticated)
	UserRequestsPerMin int
	// Sliding window duration
	Window time.Duration
	// Whether to track per-user limits (requires auth middleware to set user_id)
	PerUser bool
	// Paths to skip from rate limiting
	SkipPaths []string
}

// DefaultRateLimitConfig returns the default rate limit configuration
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		IPRequestsPerMin:   100, // 100 requests per minute per IP
		UserRequestsPerMin: 200, // 200 requests per minute per user
		Window:             time.Minute,
		PerUser:            true,
		SkipPaths:          []string{"/health", "/metrics", "/ready"},
	}
}

// RateLimitConfigFromEnv creates rate limit config from environment variables
// Env vars: RATE_LIMIT_IP_REQUESTS, RATE_LIMIT_USER_REQUESTS, RATE_LIMIT_WINDOW_SECONDS
func RateLimitConfigFromEnv() RateLimitConfig {
	cfg := DefaultRateLimitConfig()

	// Can be overridden by env vars if needed
	// This is a placeholder for env-based configuration
	return cfg
}

// rateLimitKey represents the JSON structure stored in Redis for sliding window
type rateLimitKey struct {
	Timestamps []int64 `json:"ts"`
}

// SlidingWindowRateLimit returns a Redis-backed sliding window rate limiter middleware
// It tracks requests per-IP and optionally per-user with configurable limits.
// Returns 429 with Retry-After header when limit is exceeded.
func SlidingWindowRateLimit(redisClient *redis.Client, cfg RateLimitConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip configured paths
		for _, skipPath := range cfg.SkipPaths {
			if c.Request.URL.Path == skipPath {
				c.Next()
				return
			}
		}

		// Determine limit type (IP vs User) and identifier
		identifier := c.ClientIP()
		limit := cfg.IPRequestsPerMin
		keyType := "ip"

		// If per-user tracking is enabled and user_id is in context, use user-based limit
		if cfg.PerUser {
			if userID, exists := c.Get("user_id"); exists {
				if uid, ok := userID.(string); ok && uid != "" {
					identifier = uid
					limit = cfg.UserRequestsPerMin
					keyType = "user"
				}
			}
		}

		// If Redis is not available, fail open (allow the request)
		if redisClient == nil {
			c.Next()
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 200*time.Millisecond)
		defer cancel()

		now := time.Now().Unix()
		windowStart := now - int64(cfg.Window.Seconds())

		// Redis key for this identifier
		redisKey := fmt.Sprintf("ratelimit:%s:%s", keyType, identifier)

		// Get current window data
		val, err := redisClient.Get(ctx, redisKey).Result()
		var rlData rateLimitKey
		if err == nil && val != "" {
			json.Unmarshal([]byte(val), &rlData.Timestamps)
		}

		// Filter out timestamps outside the current window
		validTimestamps := make([]int64, 0, len(rlData.Timestamps))
		for _, ts := range rlData.Timestamps {
			if ts > windowStart {
				validTimestamps = append(validTimestamps, ts)
			}
		}

		// Check if limit exceeded
		currentCount := len(validTimestamps)
		remaining := limit - currentCount - 1

		// Set rate limit headers
		c.Header("X-RateLimit-Limit", strconv.Itoa(limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(max(remaining, 0)))
		c.Header("X-RateLimit-Window", strconv.Itoa(int(cfg.Window.Seconds())))

		if currentCount >= limit {
			// Calculate retry-after (time until oldest request expires)
			oldestInWindow := validTimestamps[0]
			retryAfter := oldestInWindow - now + int64(cfg.Window.Seconds()) + 1
			if retryAfter < 1 {
				retryAfter = 1
			}
			c.Header("Retry-After", strconv.Itoa(int(retryAfter)))

			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "rate limit exceeded",
				"limit":       limit,
				"window":      cfg.Window.String(),
				"retry_after": retryAfter,
			})
			return
		}

		// Add current timestamp to window
		validTimestamps = append(validTimestamps, now)
		rlData.Timestamps = validTimestamps

		// Store back in Redis with expiration
		data, _ := json.Marshal(rlData.Timestamps)
		pipe := redisClient.Pipeline()
		pipe.Set(ctx, redisKey, data, cfg.Window+time.Second)
		_, _ = pipe.Exec(ctx)

		c.Next()
	}
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
