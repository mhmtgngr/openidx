// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/logsafe"
)

// RequestID header name constants
const (
	HeaderXRequestID = "X-Request-ID"
)

// Context key type for request ID to avoid collisions
type contextKey string

const RequestIDKey contextKey = "request_id"

// GetRequestID retrieves the request ID from the Gin context
func GetRequestID(c *gin.Context) string {
	if requestID, exists := c.Get(string(RequestIDKey)); exists {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}

// GetRequestIDFromContext retrieves the request ID from a context.Context
// This is useful for accessing request ID in downstream function calls
func GetRequestIDFromContext(ctx context.Context) string {
	if requestID := ctx.Value(RequestIDKey); requestID != nil {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}

// ContextWithRequestID adds a request ID to a context.Context
func ContextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

// RequestID generates a unique request ID for each incoming request.
// It propagates the request ID through the Gin context and adds it to response headers.
// An inbound X-Request-ID is adopted when it is id-shaped (logsafe.PlausibleID),
// so a caller can correlate across services; anything else is replaced with a
// fresh UUID rather than echoed back and logged.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to get existing request ID from header
		requestID := c.GetHeader(HeaderXRequestID)

		// Generate new UUID if absent or not id-shaped
		if !logsafe.PlausibleID(requestID) {
			requestID = uuid.New().String()
		}

		// Store in Gin context
		c.Set(string(RequestIDKey), requestID)

		// Add to request context for downstream use
		ctx := ContextWithRequestID(c.Request.Context(), requestID)
		c.Request = c.Request.WithContext(ctx)

		// Add to response headers
		c.Header(HeaderXRequestID, requestID)

		c.Next()
	}
}

// RequestIDWithGenerator allows using a custom request ID generator function
type RequestIDGenerator func() string

// RequestIDWithCustomGenerator returns a RequestID middleware that uses a custom generator
func RequestIDWithCustomGenerator(generator RequestIDGenerator) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to get existing request ID from header
		requestID := c.GetHeader(HeaderXRequestID)

		// Use custom generator if absent or not id-shaped
		if !logsafe.PlausibleID(requestID) {
			requestID = generator()
		}

		// Store in Gin context
		c.Set(string(RequestIDKey), requestID)

		// Add to request context for downstream use
		ctx := ContextWithRequestID(c.Request.Context(), requestID)
		c.Request = c.Request.WithContext(ctx)

		// Add to response headers
		c.Header(HeaderXRequestID, requestID)

		c.Next()
	}
}
