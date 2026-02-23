// Package middleware provides structured logging middleware for the gateway
package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/gateway"
)

// LoggingMiddlewareConfig holds configuration for the logging middleware
type LoggingMiddlewareConfig struct {
	// LogRequestBody enables logging of request bodies
	LogRequestBody bool

	// LogResponseBody enables logging of response bodies
	LogResponseBody bool

	// MaxBodySize limits the size of logged bodies
	MaxBodySize int64

	// SkipHealthCheck skips logging for health check endpoints
	SkipHealthCheck bool

	// LogAsJSON logs all fields as JSON
	LogAsJSON bool
}

// DefaultLoggingConfig returns default logging configuration
func DefaultLoggingConfig() LoggingMiddlewareConfig {
	return LoggingMiddlewareConfig{
		LogRequestBody:   false,
		LogResponseBody:  false,
		MaxBodySize:      1024 * 64, // 64KB
		SkipHealthCheck:  true,
		LogAsJSON:        true,
	}
}

// RequestLogger creates a Gin middleware for structured request logging
func RequestLogger(logger gateway.Logger, config LoggingMiddlewareConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		// Store logger in context
		c.Set("logger", logger)

		// Skip health check logging if configured
		if config.SkipHealthCheck && (path == "/health" || path == "/ready" || path == "/metrics") {
			c.Next()
			return
		}

		// Log request body if configured
		if config.LogRequestBody && c.Request.Body != nil && c.Request.Method != "GET" {
			bodyBytes, _ := io.ReadAll(io.LimitReader(c.Request.Body, config.MaxBodySize))
			c.Request.Body.Close()
			c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			if len(bodyBytes) > 0 {
				logger.Debug("Request body",
					"path", path,
					"body", string(bodyBytes))
			}
		}

		// Log response body if configured
		if config.LogResponseBody {
			writer := &responseBodyCapture{
				ResponseWriter: c.Writer,
				body:          &bytes.Buffer{},
			}
			c.Writer = writer
		}

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start)

		// Determine log level based on status code
		status := c.Writer.Status()
		correlationID := GetCorrelationID(c)

		fields := []interface{}{
			"correlation_id", correlationID,
			"method", c.Request.Method,
			"path", path,
			"query", query,
			"status", status,
			"latency_ms", duration.Milliseconds(),
			"client_ip", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
		}

		// Add forward headers if present
		if forwardedFor := c.GetHeader("X-Forwarded-For"); forwardedFor != "" {
			fields = append(fields, "forwarded_for", forwardedFor)
		}

		// Log at appropriate level
		switch {
		case status >= 500:
			logger.Error("Gateway request: server error", fields...)
		case status >= 400:
			logger.Warn("Gateway request: client error", fields...)
		case status >= 300:
			logger.Info("Gateway request: redirect", fields...)
		default:
			logger.Info("Gateway request: success", fields...)
		}
	}
}

// responseBodyCapture captures response body for logging
type responseBodyCapture struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *responseBodyCapture) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

// LogResponse logs a response with structured fields
func LogResponse(c *gin.Context, statusCode int, body interface{}) {
	logger, ok := c.Get("logger")
	if !ok {
		return
	}

	gwLogger, ok := logger.(gateway.Logger)
	if !ok {
		return
	}

	fields := []interface{}{
		"status", statusCode,
		"correlation_id", GetCorrelationID(c),
		"path", c.Request.URL.Path,
	}

	if body != nil {
		if jsonString, err := json.Marshal(body); err == nil {
			fields = append(fields, "response_body", string(jsonString))
		}
	}

	if statusCode >= 400 {
		gwLogger.Warn("Gateway response", fields...)
	} else {
		gwLogger.Info("Gateway response", fields...)
	}
}

// GetLogger retrieves the logger from the Gin context
func GetLogger(c *gin.Context) (gateway.Logger, bool) {
	logger, exists := c.Get("logger")
	if !exists {
		return nil, false
	}

	l, ok := logger.(gateway.Logger)
	return l, ok
}

// WithLogger returns a logger with additional context fields
// Since gateway.Logger doesn't support With(), we return a wrapper
func WithLogger(logger gateway.Logger, c *gin.Context) gateway.Logger {
	// Create a context-aware logger wrapper
	return &contextLogger{
		logger:       logger,
		correlationID: GetCorrelationID(c),
		path:         c.Request.URL.Path,
	}
}

// contextLogger wraps gateway.Logger with context fields
type contextLogger struct {
	logger       gateway.Logger
	correlationID string
	path         string
}

func (l *contextLogger) Debug(msg string, fields ...interface{}) {
	allFields := append([]interface{}{
		"correlation_id", l.correlationID,
		"path", l.path,
	}, fields...)
	l.logger.Debug(msg, allFields...)
}

func (l *contextLogger) Info(msg string, fields ...interface{}) {
	allFields := append([]interface{}{
		"correlation_id", l.correlationID,
		"path", l.path,
	}, fields...)
	l.logger.Info(msg, allFields...)
}

func (l *contextLogger) Warn(msg string, fields ...interface{}) {
	allFields := append([]interface{}{
		"correlation_id", l.correlationID,
		"path", l.path,
	}, fields...)
	l.logger.Warn(msg, allFields...)
}

func (l *contextLogger) Error(msg string, fields ...interface{}) {
	allFields := append([]interface{}{
		"correlation_id", l.correlationID,
		"path", l.path,
	}, fields...)
	l.logger.Error(msg, allFields...)
}

func (l *contextLogger) Fatal(msg string, fields ...interface{}) {
	allFields := append([]interface{}{
		"correlation_id", l.correlationID,
		"path", l.path,
	}, fields...)
	l.logger.Fatal(msg, allFields...)
}

func (l *contextLogger) Sync() error {
	return l.logger.Sync()
}

// LogRequestEntry logs when a request enters the gateway
func LogRequestEntry(logger gateway.Logger, c *gin.Context) {
	logger.Debug("Gateway request entry",
		"correlation_id", GetCorrelationID(c),
		"method", c.Request.Method,
		"path", c.Request.URL.Path,
		"query", c.Request.URL.RawQuery,
		"client_ip", c.ClientIP(),
	)
}

// LogRequestExit logs when a request exits the gateway
func LogRequestExit(logger gateway.Logger, c *gin.Context, duration time.Duration) {
	status := c.Writer.Status()
	fields := []interface{}{
		"correlation_id", GetCorrelationID(c),
		"method", c.Request.Method,
		"path", c.Request.URL.Path,
		"status", status,
		"duration_ms", duration.Milliseconds(),
	}

	switch {
	case status >= 500:
		logger.Error("Gateway request exit: server error", fields...)
	case status >= 400:
		logger.Warn("Gateway request exit: client error", fields...)
	default:
		logger.Info("Gateway request exit: success", fields...)
	}
}

// LogError logs an error with context
func LogError(c *gin.Context, err error, message string) {
	logger, ok := GetLogger(c)
	if !ok {
		return
	}

	logger.Error(message,
		"correlation_id", GetCorrelationID(c),
		"path", c.Request.URL.Path,
		"error", err.Error(),
	)
}

// LogSecurityEvent logs security-relevant events
func LogSecurityEvent(c *gin.Context, eventType string, details map[string]interface{}) {
	logger, ok := GetLogger(c)
	if !ok {
		return
	}

	fields := []interface{}{
		"correlation_id", GetCorrelationID(c),
		"event_type", eventType,
		"client_ip", c.ClientIP(),
		"path", c.Request.URL.Path,
	}

	for k, v := range details {
		fields = append(fields, k, fmt.Sprintf("%v", v))
	}

	logger.Warn("Security event", fields...)
}

// LogRateLimit logs rate limit events
func LogRateLimit(c *gin.Context, limit int, window time.Duration) {
	logger, ok := GetLogger(c)
	if !ok {
		return
	}

	logger.Warn("Rate limit exceeded",
		"correlation_id", GetCorrelationID(c),
		"client_ip", c.ClientIP(),
		"path", c.Request.URL.Path,
		"limit", limit,
		"window_seconds", window.Seconds(),
	)
}

// LogAuthFailure logs authentication failures
func LogAuthFailure(c *gin.Context, reason string) {
	logger, ok := GetLogger(c)
	if !ok {
		return
	}

	logger.Warn("Authentication failed",
		"correlation_id", GetCorrelationID(c),
		"client_ip", c.ClientIP(),
		"path", c.Request.URL.Path,
		"reason", reason,
	)
}

// LogProxyEvent logs proxy-related events
func LogProxyEvent(c *gin.Context, targetService string, targetURL string) {
	logger, ok := GetLogger(c)
	if !ok {
		return
	}

	logger.Debug("Proxying request",
		"correlation_id", GetCorrelationID(c),
		"target_service", targetService,
		"target_url", targetURL,
		"path", c.Request.URL.Path,
	)
}

// LogUpstreamError logs errors from upstream services
func LogUpstreamError(c *gin.Context, service string, err error) {
	logger, ok := GetLogger(c)
	if !ok {
		return
	}

	logger.Error("Upstream service error",
		"correlation_id", GetCorrelationID(c),
		"service", service,
		"path", c.Request.URL.Path,
		"error", err.Error(),
	)
}

// buildLogFields builds log fields from request context
func buildLogFields(c *gin.Context, status int, duration time.Duration) []interface{} {
	fields := []interface{}{
		"correlation_id", GetCorrelationID(c),
		"method", c.Request.Method,
		"path", c.Request.URL.Path,
		"query", c.Request.URL.RawQuery,
		"status", status,
		"latency_ms", duration.Milliseconds(),
		"client_ip", c.ClientIP(),
		"user_agent", c.Request.UserAgent(),
	}

	// Add X-Forwarded-For if present
	if forwardedFor := c.GetHeader("X-Forwarded-For"); forwardedFor != "" {
		fields = append(fields, "forwarded_for", forwardedFor)
	}

	return fields
}
