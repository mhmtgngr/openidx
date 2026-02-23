// Package middleware provides rate limiting middleware for the gateway
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/gateway"
	"github.com/redis/go-redis/v9"
)

// RateLimitMiddleware provides sliding window rate limiting using Redis
type RateLimitMiddleware struct {
	redis           *redis.Client
	logger          gateway.Logger
	requestsPerMin  int
	authRequestsPerMin int
	windowSeconds   int
}

// NewRateLimitMiddleware creates a new rate limiting middleware
func NewRateLimitMiddleware(redisClient *redis.Client, logger gateway.Logger, config gateway.RateLimitConfig) *RateLimitMiddleware {
	return &RateLimitMiddleware{
		redis:           redisClient,
		logger:          logger,
		requestsPerMin:  config.RequestsPerMinute,
		authRequestsPerMin: config.AuthRequestsPerMinute,
		windowSeconds:   config.WindowSeconds,
	}
}

// RateLimit creates a Gin middleware for rate limiting
func (m *RateLimitMiddleware) RateLimit(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get identifier for rate limiting
		identifier := m.getIdentifier(c)

		// Determine limit based on whether this is an auth request
		limit := m.requestsPerMin
		if m.isAuthRequest(c) {
			limit = m.authRequestsPerMin
		}

		// Check rate limit
		allowed, remaining, resetAt, err := m.checkRateLimit(c.Request.Context(), identifier, serviceName, limit)
		if err != nil {
			// Log error but allow request (fail open)
			m.logger.Warn("Rate limit check failed, allowing request",
				"identifier", identifier,
				"service", serviceName,
				"error", err.Error())
			c.Next()
			return
		}

		// Set rate limit headers
		m.setRateLimitHeaders(c, remaining, resetAt)

		if !allowed {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "rate limit exceeded",
				"retry_after": int64(resetAt.Sub(time.Now()).Seconds()),
			})
			return
		}

		c.Next()
	}
}

// getIdentifier gets the rate limit identifier for the request
func (m *RateLimitMiddleware) getIdentifier(c *gin.Context) string {
	// First try to use user_id from authenticated context
	if userID, exists := c.Get("user_id"); exists {
		return fmt.Sprintf("user:%v", userID)
	}

	// Fall back to IP address
	return fmt.Sprintf("ip:%s", c.ClientIP())
}

// isAuthRequest checks if this is an authentication-related request
func (m *RateLimitMiddleware) isAuthRequest(c *gin.Context) bool {
	path := c.Request.URL.Path
	return path == "/api/v1/oauth/token" ||
		   path == "/api/v1/oauth/authorize" ||
		   path == "/api/v1/identity/login" ||
		   path == "/api/v1/identity/logout" ||
		   path == "/api/v1/identity/mfa/verify"
}

// checkRateLimit performs a sliding window rate limit check
func (m *RateLimitMiddleware) checkRateLimit(ctx context.Context, identifier, serviceName string, limit int) (bool, int, time.Time, error) {
	now := time.Now()
	windowStart := now.Truncate(time.Duration(m.windowSeconds) * time.Second)
	windowEnd := windowStart.Add(time.Duration(m.windowSeconds) * time.Second)

	// Redis key for this window
	key := fmt.Sprintf("ratelimit:%s:%s:%d", identifier, serviceName, windowStart.Unix())

	// Get current count
	countStr, err := m.redis.Get(ctx, key).Result()
	if err != nil && err != redis.Nil {
		return false, 0, time.Time{}, err
	}

	count := 0
	if countStr != "" {
		count, _ = strconv.Atoi(countStr)
	}

	// Check if limit exceeded
	if count >= limit {
		// Check if we've moved to a new window
		if now.After(windowEnd) {
			// New window, reset count
			pipe := m.redis.Pipeline()
			pipe.Set(ctx, key, 1, time.Duration(m.windowSeconds)*time.Second)
			pipe.Expire(ctx, key, time.Duration(m.windowSeconds)*time.Second)
			_, err := pipe.Exec(ctx)
			if err != nil {
				return false, 0, time.Time{}, err
			}
			return true, limit - 1, windowEnd, nil
		}
		return false, 0, windowEnd, nil
	}

	// Increment count
	pipe := m.redis.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, time.Duration(m.windowSeconds)*time.Second)
	_, err = pipe.Exec(ctx)
	if err != nil {
		return false, 0, time.Time{}, err
	}

	newCount := int(incrCmd.Val())
	remaining := limit - newCount
	if remaining < 0 {
		remaining = 0
	}

	return true, remaining, windowEnd, nil
}

// setRateLimitHeaders sets rate limit related headers on the response
func (m *RateLimitMiddleware) setRateLimitHeaders(c *gin.Context, remaining int, resetAt time.Time) {
	c.Header("X-RateLimit-Limit", strconv.Itoa(m.requestsPerMin))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Reset", strconv.FormatInt(resetAt.Unix(), 10))
	c.Header("X-RateLimit-Reset-After", strconv.FormatInt(int64(resetAt.Sub(time.Now()).Seconds()), 10))
}

// SlidingWindowRateLimit implements a more accurate sliding window algorithm
type SlidingWindowRateLimit struct {
	redis         *redis.Client
	logger        gateway.Logger
	limit         int
	windowSeconds int
}

// NewSlidingWindowRateLimit creates a new sliding window rate limiter
func NewSlidingWindowRateLimit(redis *redis.Client, logger gateway.Logger, limit, windowSeconds int) *SlidingWindowRateLimit {
	return &SlidingWindowRateLimit{
		redis:         redis,
		logger:        logger,
		limit:         limit,
		windowSeconds: windowSeconds,
	}
}

// Check performs the sliding window rate limit check
func (sw *SlidingWindowRateLimit) Check(ctx context.Context, identifier string) (bool, int, time.Time, error) {
	now := time.Now()
	windowStart := now.Add(-time.Duration(sw.windowSeconds) * time.Second)

	// Use sorted sets to implement sliding window
	key := fmt.Sprintf("ratelimit:sliding:%s", identifier)

	// Remove old entries outside the window
	_, err := sw.redis.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart.UnixMilli(), 10)).Result()
	if err != nil && err != redis.Nil {
		return false, 0, time.Time{}, err
	}

	// Count current requests
	count, err := sw.redis.ZCard(ctx, key).Result()
	if err != nil && err != redis.Nil {
		return false, 0, time.Time{}, err
	}

	// Check if limit exceeded
	if count >= int64(sw.limit) {
		// Get oldest entry to calculate reset time
		entries, err := sw.redis.ZRange(ctx, key, 0, 0).Result()
		if err != nil || len(entries) == 0 {
			return false, 0, time.Now().Add(time.Duration(sw.windowSeconds) * time.Second), nil
		}
		// The window resets when the oldest entry expires
		return false, 0, time.Now().Add(time.Duration(sw.windowSeconds) * time.Second), nil
	}

	// Add current request
	pipe := sw.redis.Pipeline()
	pipe.ZAdd(ctx, key, redis.Z{
		Score:  float64(now.UnixMilli()),
		Member: now.UnixNano(),
	})
	pipe.Expire(ctx, key, time.Duration(sw.windowSeconds)*time.Second)
	_, err = pipe.Exec(ctx)
	if err != nil {
		return false, 0, time.Time{}, err
	}

	remaining := sw.limit - int(count) - 1
	if remaining < 0 {
		remaining = 0
	}

	resetTime := now.Add(time.Duration(sw.windowSeconds) * time.Second)

	return true, remaining, resetTime, nil
}

// GetRateLimitHeaders returns the rate limit headers for a response
func GetRateLimitHeaders(limit, remaining int, resetAt time.Time) map[string]string {
	return map[string]string{
		"X-RateLimit-Limit":      strconv.Itoa(limit),
		"X-RateLimit-Remaining":  strconv.Itoa(remaining),
		"X-RateLimit-Reset":      strconv.FormatInt(resetAt.Unix(), 10),
		"X-RateLimit-Reset-After": strconv.FormatInt(int64(resetAt.Sub(time.Now()).Seconds()), 10),
	}
}

// IPBasedRateLimit creates a middleware that rate limits based on IP address
func IPBasedRateLimit(redis *redis.Client, logger gateway.Logger, requestsPerMinute int) gin.HandlerFunc {
	limiter := NewSlidingWindowRateLimit(redis, logger, requestsPerMinute, 60)

	return func(c *gin.Context) {
		identifier := fmt.Sprintf("ip:%s", c.ClientIP())

		allowed, remaining, resetAt, err := limiter.Check(c.Request.Context(), identifier)
		if err != nil {
			// Log error but allow request
			logger.Warn("Rate limit check failed",
				"ip", c.ClientIP(),
				"error", err.Error())
			c.Next()
			return
		}

		headers := GetRateLimitHeaders(requestsPerMinute, remaining, resetAt)
		for k, v := range headers {
			c.Header(k, v)
		}

		if !allowed {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			return
		}

		c.Next()
	}
}

// UserBasedRateLimit creates a middleware that rate limits based on user ID
func UserBasedRateLimit(redis *redis.Client, logger gateway.Logger, requestsPerMinute int) gin.HandlerFunc {
	limiter := NewSlidingWindowRateLimit(redis, logger, requestsPerMinute, 60)

	return func(c *gin.Context) {
		// Try to get user_id, fall back to IP
		identifier := fmt.Sprintf("ip:%s", c.ClientIP())
		if userID, exists := c.Get("user_id"); exists {
			identifier = fmt.Sprintf("user:%v", userID)
		}

		allowed, remaining, resetAt, err := limiter.Check(c.Request.Context(), identifier)
		if err != nil {
			logger.Warn("Rate limit check failed",
				"identifier", identifier,
				"error", err.Error())
			c.Next()
			return
		}

		headers := GetRateLimitHeaders(requestsPerMinute, remaining, resetAt)
		for k, v := range headers {
			c.Header(k, v)
		}

		if !allowed {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			return
		}

		c.Next()
	}
}
