// Package middleware provides correlation ID middleware for distributed tracing
package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	// CorrelationIDHeader is the header name for correlation ID
	CorrelationIDHeader = "X-Correlation-ID"

	// RequestIDHeader is the header name for request ID
	RequestIDHeader = "X-Request-ID"
)

// CorrelationIDConfig holds configuration for correlation ID middleware
type CorrelationIDConfig struct {
	// GenerateIfMissing generates a new ID if not present
	GenerateIfMissing bool

	// UseRequestIDHeader falls back to X-Request-ID if X-Correlation-ID is missing
	UseRequestIDHeader bool

	// PropagateToDownstream adds the correlation ID to downstream requests
	PropagateToDownstream bool
}

// DefaultCorrelationIDConfig returns default configuration
func DefaultCorrelationIDConfig() CorrelationIDConfig {
	return CorrelationIDConfig{
		GenerateIfMissing:     true,
		UseRequestIDHeader:    true,
		PropagateToDownstream: true,
	}
}

// CorrelationID creates a Gin middleware for correlation ID handling
func CorrelationID(config CorrelationIDConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		correlationID := c.GetHeader(CorrelationIDHeader)

		// Try X-Request-ID if configured and correlation ID is missing
		if correlationID == "" && config.UseRequestIDHeader {
			correlationID = c.GetHeader(RequestIDHeader)
		}

		// Generate new ID if configured and still missing
		if correlationID == "" && config.GenerateIfMissing {
			correlationID = generateID()
		}

		// Store in context
		c.Set("correlation_id", correlationID)

		// Add to response headers
		c.Header(CorrelationIDHeader, correlationID)

		// Propagate to downstream services if configured
		if config.PropagateToDownstream {
			// Store in request context for later use
			c.Set("downstream_headers", map[string]string{
				CorrelationIDHeader: correlationID,
			})
		}

		c.Next()
	}
}

// CorrelationIDGenerator defines the interface for generating correlation IDs
type CorrelationIDGenerator interface {
	Generate() string
	Validate(id string) bool
}

// UUIDGenerator generates UUID-based correlation IDs
type UUIDGenerator struct{}

// Generate generates a new UUID v4
func (g *UUIDGenerator) Generate() string {
	return uuid.New().String()
}

// Validate checks if the ID is a valid UUID
func (g *UUIDGenerator) Validate(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}

// NanosecondGenerator generates nanosecond-based correlation IDs
type NanosecondGenerator struct{}

// Generate generates a nanosecond timestamp-based ID
func (g *NanosecondGenerator) Generate() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// Validate always returns true for this generator
func (g *NanosecondGenerator) Validate(id string) bool {
	return id != ""
}

// PrefixGenerator adds a prefix to correlation IDs
type PrefixGenerator struct {
	prefix    string
	generator CorrelationIDGenerator
}

// NewPrefixGenerator creates a new prefix generator
func NewPrefixGenerator(prefix string, generator CorrelationIDGenerator) *PrefixGenerator {
	return &PrefixGenerator{
		prefix:    prefix,
		generator: generator,
	}
}

// Generate generates a prefixed ID
func (g *PrefixGenerator) Generate() string {
	return fmt.Sprintf("%s-%s", g.prefix, g.generator.Generate())
}

// Validate checks if the ID has the correct prefix
func (g *PrefixGenerator) Validate(id string) bool {
	if !strings.HasPrefix(id, g.prefix+"-") {
		return false
	}
	// Validate the rest
	rest := strings.TrimPrefix(id, g.prefix+"-")
	return g.generator.Validate(rest)
}

// GetOrGenerate returns the correlation ID from context or generates a new one
func GetOrGenerate(c *gin.Context) string {
	if correlationID, exists := c.Get("correlation_id"); exists {
		if id, ok := correlationID.(string); ok {
			return id
		}
	}
	return generateID()
}

// InjectHeaders injects correlation ID headers into an HTTP request
func InjectHeaders(c *gin.Context, req *http.Request) {
	if correlationID, exists := c.Get("correlation_id"); exists {
		if id, ok := correlationID.(string); ok {
			req.Header.Set(CorrelationIDHeader, id)
		}
	}

	// Also inject any stored downstream headers
	if headers, exists := c.Get("downstream_headers"); exists {
		if headerMap, ok := headers.(map[string]string); ok {
			for k, v := range headerMap {
				req.Header.Set(k, v)
			}
		}
	}
}

// GetCorrelationID retrieves the correlation ID from the Gin context
func GetCorrelationID(c *gin.Context) string {
	if correlationID, exists := c.Get("correlation_id"); exists {
		if id, ok := correlationID.(string); ok {
			return id
		}
	}
	return ""
}

// SetCorrelationID sets a custom correlation ID in the context
func SetCorrelationID(c *gin.Context, id string) {
	c.Set("correlation_id", id)
	c.Header(CorrelationIDHeader, id)
}

// WithCorrelationID creates a context with correlation ID for use with loggers
func WithCorrelationID(c *gin.Context, baseCtx interface{}) interface{} {
	correlationID := GetCorrelationID(c)
	if correlationID == "" {
		return baseCtx
	}
	// This is a placeholder - actual implementation depends on context type
	return baseCtx
}

// generateID generates a new unique correlation ID
func generateID() string {
	return uuid.New().String()
}

// TracingHeaders creates a map of tracing headers for downstream requests
func TracingHeaders(c *gin.Context) map[string]string {
	headers := make(map[string]string)

	if correlationID := GetCorrelationID(c); correlationID != "" {
		headers[CorrelationIDHeader] = correlationID
	}

	// Add request ID if present
	if requestID := c.GetHeader(RequestIDHeader); requestID != "" {
		headers[RequestIDHeader] = requestID
	}

	// Add trace parent for OpenTelemetry if present
	if traceParent := c.GetHeader("traceparent"); traceParent != "" {
		headers["traceparent"] = traceParent
	}

	return headers
}

// AddTracingHeaders adds tracing headers to an HTTP request
func AddTracingHeaders(c *gin.Context, req *http.Request) {
	headers := TracingHeaders(c)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}
