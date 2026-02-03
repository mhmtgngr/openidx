// Package handlers provides handler decorators for cross-cutting concerns.
// Decorators can be composed to add logging, metrics, caching, rate limiting,
// and other behaviors to HTTP handlers without modifying the handler code.
package handlers

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// Decorator wraps a handler with additional behavior
type Decorator func(gin.HandlerFunc) gin.HandlerFunc

// Decorate applies multiple decorators to a handler (in reverse order)
func Decorate(handler gin.HandlerFunc, decorators ...Decorator) gin.HandlerFunc {
	// Apply decorators in reverse order so the first decorator is outermost
	for i := len(decorators) - 1; i >= 0; i-- {
		handler = decorators[i](handler)
	}
	return handler
}

// Chain creates a decorator that combines multiple decorators
func Chain(decorators ...Decorator) Decorator {
	return func(handler gin.HandlerFunc) gin.HandlerFunc {
		return Decorate(handler, decorators...)
	}
}

// ============================================================================
// Logging Decorator
// ============================================================================

// WithLogging adds request/response logging
func WithLogging(logger *zap.Logger) Decorator {
	return func(handler gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			start := time.Now()

			// Log request
			logger.Debug("Request started",
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("client_ip", c.ClientIP()),
			)

			// Execute handler
			handler(c)

			// Log response
			duration := time.Since(start)
			logger.Info("Request completed",
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.Int("status", c.Writer.Status()),
				zap.Duration("duration", duration),
			)
		}
	}
}

// WithErrorLogging logs errors
func WithErrorLogging(logger *zap.Logger) Decorator {
	return func(handler gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			handler(c)

			// Log any errors
			if len(c.Errors) > 0 {
				for _, err := range c.Errors {
					logger.Error("Handler error",
						zap.String("path", c.Request.URL.Path),
						zap.Error(err.Err),
					)
				}
			}
		}
	}
}

// ============================================================================
// Metrics Decorator
// ============================================================================

var (
	requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_handler_duration_seconds",
			Help:    "Duration of HTTP handlers",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"handler", "method", "status"},
	)

	requestTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_handler_requests_total",
			Help: "Total number of HTTP handler requests",
		},
		[]string{"handler", "method", "status"},
	)
)

// WithMetrics adds Prometheus metrics
func WithMetrics(handlerName string) Decorator {
	return func(handler gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			start := time.Now()

			handler(c)

			duration := time.Since(start)
			status := fmt.Sprintf("%d", c.Writer.Status())

			requestDuration.WithLabelValues(handlerName, c.Request.Method, status).Observe(duration.Seconds())
			requestTotal.WithLabelValues(handlerName, c.Request.Method, status).Inc()
		}
	}
}

// ============================================================================
// Rate Limiting Decorator
// ============================================================================

// RateLimiter interface for rate limiting
type RateLimiter interface {
	Allow(key string) bool
	Remaining(key string) int
}

// SimpleRateLimiter is a basic in-memory rate limiter
type SimpleRateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

// NewSimpleRateLimiter creates a new rate limiter
func NewSimpleRateLimiter(limit int, window time.Duration) *SimpleRateLimiter {
	return &SimpleRateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Allow checks if a request is allowed
func (r *SimpleRateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.window)

	// Clean old requests
	times := r.requests[key]
	valid := make([]time.Time, 0)
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= r.limit {
		r.requests[key] = valid
		return false
	}

	r.requests[key] = append(valid, now)
	return true
}

// Remaining returns remaining requests
func (r *SimpleRateLimiter) Remaining(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.window)

	count := 0
	for _, t := range r.requests[key] {
		if t.After(cutoff) {
			count++
		}
	}

	remaining := r.limit - count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// WithRateLimit adds rate limiting by IP
func WithRateLimit(limiter RateLimiter) Decorator {
	return func(handler gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			key := c.ClientIP()

			if !limiter.Allow(key) {
				c.Header("X-RateLimit-Remaining", "0")
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error": "rate_limit_exceeded",
					"message": "Too many requests, please try again later",
				})
				c.Abort()
				return
			}

			c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", limiter.Remaining(key)))
			handler(c)
		}
	}
}

// WithRateLimitByKey adds rate limiting by custom key
func WithRateLimitByKey(limiter RateLimiter, keyFunc func(*gin.Context) string) Decorator {
	return func(handler gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			key := keyFunc(c)

			if !limiter.Allow(key) {
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error": "rate_limit_exceeded",
				})
				c.Abort()
				return
			}

			handler(c)
		}
	}
}

// ============================================================================
// Caching Decorator
// ============================================================================

// Cache interface for response caching
type Cache interface {
	Get(key string) ([]byte, bool)
	Set(key string, value []byte, ttl time.Duration)
	Delete(key string)
}

// MemoryCache is a simple in-memory cache
type MemoryCache struct {
	mu    sync.RWMutex
	items map[string]cacheItem
}

type cacheItem struct {
	value     []byte
	expiresAt time.Time
}

// NewMemoryCache creates a new memory cache
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		items: make(map[string]cacheItem),
	}
}

// Get retrieves a cached value
func (c *MemoryCache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.items[key]
	if !ok || time.Now().After(item.expiresAt) {
		return nil, false
	}
	return item.value, true
}

// Set stores a value in cache
func (c *MemoryCache) Set(key string, value []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = cacheItem{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
}

// Delete removes a value from cache
func (c *MemoryCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

// WithCache adds response caching for GET requests
func WithCache(cache Cache, ttl time.Duration) Decorator {
	return func(handler gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			// Only cache GET requests
			if c.Request.Method != http.MethodGet {
				handler(c)
				return
			}

			key := c.Request.URL.String()

			// Check cache
			if cached, ok := cache.Get(key); ok {
				c.Header("X-Cache", "HIT")
				c.Data(http.StatusOK, "application/json", cached)
				return
			}

			// Execute handler with response capture
			w := &responseCapture{ResponseWriter: c.Writer, body: make([]byte, 0)}
			c.Writer = w

			handler(c)

			// Cache successful responses
			if c.Writer.Status() == http.StatusOK && len(w.body) > 0 {
				cache.Set(key, w.body, ttl)
			}

			c.Header("X-Cache", "MISS")
		}
	}
}

// responseCapture captures the response body
type responseCapture struct {
	gin.ResponseWriter
	body []byte
}

func (r *responseCapture) Write(b []byte) (int, error) {
	r.body = append(r.body, b...)
	return r.ResponseWriter.Write(b)
}

// ============================================================================
// Timeout Decorator
// ============================================================================

// WithTimeout adds a timeout to the handler
func WithTimeout(timeout time.Duration) Decorator {
	return func(handler gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			// Create a channel to signal completion
			done := make(chan struct{})

			go func() {
				handler(c)
				close(done)
			}()

			select {
			case <-done:
				// Handler completed
			case <-time.After(timeout):
				c.JSON(http.StatusGatewayTimeout, gin.H{
					"error": "timeout",
					"message": "Request timed out",
				})
				c.Abort()
			}
		}
	}
}

// ============================================================================
// Recovery Decorator
// ============================================================================

// WithRecovery recovers from panics
func WithRecovery(logger *zap.Logger) Decorator {
	return func(handler gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			defer func() {
				if err := recover(); err != nil {
					logger.Error("Panic recovered",
						zap.Any("error", err),
						zap.String("path", c.Request.URL.Path),
					)
					c.JSON(http.StatusInternalServerError, gin.H{
						"error": "internal_server_error",
					})
					c.Abort()
				}
			}()

			handler(c)
		}
	}
}

// ============================================================================
// Validation Decorator
// ============================================================================

// ValidatorFunc validates the request
type ValidatorFunc func(*gin.Context) error

// WithValidation adds request validation
func WithValidation(validator ValidatorFunc) Decorator {
	return func(handler gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			if err := validator(c); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "validation_error",
					"message": err.Error(),
				})
				c.Abort()
				return
			}
			handler(c)
		}
	}
}

// ============================================================================
// Authorization Decorator
// ============================================================================

// AuthorizerFunc checks if the request is authorized
type AuthorizerFunc func(*gin.Context) bool

// WithAuthorization adds authorization check
func WithAuthorization(authorizer AuthorizerFunc) Decorator {
	return func(handler gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			if !authorizer(c) {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "forbidden",
					"message": "You don't have permission to access this resource",
				})
				c.Abort()
				return
			}
			handler(c)
		}
	}
}

// WithRoles checks if user has required roles
func WithRoles(roles ...string) Decorator {
	return WithAuthorization(func(c *gin.Context) bool {
		userRoles, exists := c.Get("roles")
		if !exists {
			return false
		}

		roleList, ok := userRoles.([]string)
		if !ok {
			return false
		}

		for _, required := range roles {
			for _, has := range roleList {
				if has == required {
					return true
				}
			}
		}
		return false
	})
}

// ============================================================================
// Audit Decorator
// ============================================================================

// AuditLogger interface for audit logging
type AuditLogger interface {
	Log(event string, userID string, resource string, action string, details map[string]interface{})
}

// WithAudit adds audit logging
func WithAudit(logger AuditLogger, eventType string) Decorator {
	return func(handler gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			handler(c)

			// Log after handler completes
			userID, _ := c.Get("user_id")
			logger.Log(
				eventType,
				fmt.Sprintf("%v", userID),
				c.Request.URL.Path,
				c.Request.Method,
				map[string]interface{}{
					"status":    c.Writer.Status(),
					"client_ip": c.ClientIP(),
				},
			)
		}
	}
}

// ============================================================================
// Preset Decorator Chains
// ============================================================================

// StandardAPI returns standard decorators for API handlers
func StandardAPI(logger *zap.Logger, handlerName string) Decorator {
	return Chain(
		WithRecovery(logger),
		WithLogging(logger),
		WithMetrics(handlerName),
		WithErrorLogging(logger),
	)
}

// SecureAPI returns decorators for secure API handlers
func SecureAPI(logger *zap.Logger, handlerName string, limiter RateLimiter) Decorator {
	return Chain(
		WithRecovery(logger),
		WithLogging(logger),
		WithMetrics(handlerName),
		WithRateLimit(limiter),
		WithErrorLogging(logger),
	)
}

// AdminAPI returns decorators for admin API handlers
func AdminAPI(logger *zap.Logger, handlerName string) Decorator {
	return Chain(
		WithRecovery(logger),
		WithLogging(logger),
		WithMetrics(handlerName),
		WithRoles("admin"),
		WithErrorLogging(logger),
	)
}
