// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/openidx/openidx/internal/common/logsafe"
)

// DefaultSanitizedFields is the default LoggingConfig.SanitizeFields value.
//
// It is logsafe.DefaultSensitiveFieldNames, which is where the classification
// now lives: three request loggers in this tree redacted (or did not redact) by
// three different rules, and only one of them was mounted. See
// internal/common/logsafe/redact.go for what the rule is and why.
var DefaultSanitizedFields = logsafe.DefaultSensitiveFieldNames

// redactedMarker is re-exported for the tests in this package that assert on it.
const redactedMarker = logsafe.RedactedMarker

// LoggingConfig holds configuration options for request logging
type LoggingConfig struct {
	// LogBody enables logging of request body for POST/PUT/PATCH requests
	LogBody bool

	// LogQueryParams enables logging of URL query parameters
	LogQueryParams bool

	// SanitizeFields contains field names to redact from logs
	SanitizeFields []string

	// MinDuration specifies minimum request duration to log (only log slow requests)
	// If zero, all requests are logged
	MinDuration time.Duration

	// EnableTracing enables distributed tracing integration
	EnableTracing bool

	// Logger is the zap logger instance
	Logger *zap.Logger
}

// DefaultLoggingConfig returns a LoggingConfig with sensible defaults
func DefaultLoggingConfig(logger *zap.Logger) LoggingConfig {
	return LoggingConfig{
		LogBody:        false,
		LogQueryParams: true,
		SanitizeFields: DefaultSanitizedFields,
		MinDuration:    0,
		EnableTracing:  false,
		Logger:         logger,
	}
}

// RequestLogger returns a middleware that logs HTTP requests with comprehensive information
// including request ID, user ID, duration, status, size, client IP, user-agent,
// sanitized query parameters, and sanitized request body for POST/PUT/PATCH
func RequestLogger(logger *zap.Logger) gin.HandlerFunc {
	return RequestLoggerWithConfig(DefaultLoggingConfig(logger))
}

// RequestLoggerWithConfig returns a middleware with custom logging configuration
func RequestLoggerWithConfig(config LoggingConfig) gin.HandlerFunc {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	// Ensure sanitized fields are lowercased for case-insensitive matching
	sanitizeFields := make(map[string]bool)
	for _, field := range config.SanitizeFields {
		sanitizeFields[strings.ToLower(field)] = true
	}

	return func(c *gin.Context) {
		start := time.Now()

		// Generate or retrieve request ID. An inbound X-Request-ID is honoured so
		// a caller can correlate across services, but it is not trusted: it is
		// echoed back in the response header below and stamped on every log line
		// for the request. logsafe.PlausibleID says what "trusted" means here and
		// why a rejected value is replaced rather than cleaned.
		requestID := c.GetHeader("X-Request-ID")
		if !logsafe.PlausibleID(requestID) {
			requestID = uuid.New().String()
		}

		// Store request ID in context for retrieval in handlers
		c.Set("request_id", requestID)

		// Set response header for tracing
		c.Header("X-Request-ID", requestID)

		// Capture request body for POST/PUT/PATCH if enabled
		var requestBody string
		if config.LogBody && (c.Request.Method == http.MethodPost ||
			c.Request.Method == http.MethodPut ||
			c.Request.Method == http.MethodPatch) {

			// Read body
			bodyBytes, _ := io.ReadAll(c.Request.Body)
			c.Request.Body.Close()

			// Restore body for subsequent handlers
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			// Decompress if gzip encoded
			if strings.Contains(c.Request.Header.Get("Content-Encoding"), "gzip") {
				gzReader, err := gzip.NewReader(bytes.NewReader(bodyBytes))
				if err == nil {
					decompressed, _ := io.ReadAll(gzReader)
					gzReader.Close()
					requestBody = string(decompressed)
				} else {
					requestBody = string(bodyBytes)
				}
			} else {
				requestBody = string(bodyBytes)
			}

			// Sanitize BEFORE truncating. The other order looks equivalent and is
			// not: truncated JSON does not parse, so a body over the limit would
			// reach the sanitiser as an unparseable string and be discarded whole
			// -- every large body reduced to one apologetic line, which is the
			// opposite of what the option is for. Redact first, cut second.
			requestBody = sanitizeJSON(requestBody, sanitizeFields)

			// Truncate body if too large (limit to 10KB)
			const maxBodySize = 10 * 1024
			if len(requestBody) > maxBodySize {
				requestBody = requestBody[:maxBodySize] + "... (truncated)"
			}
		}

		// Prepare log fields before processing. Everything here except request_id
		// (already validated above) came off the wire: the path carries whatever
		// %-encoding the client chose, the user agent is a free-text header, and
		// client_ip is X-Forwarded-For behind a trusted proxy. See
		// internal/common/logsafe for what "cleaned" means and why a zap field
		// still needs it.
		fields := []zapcore.Field{
			logsafe.String("request_id", requestID),
			logsafe.String("method", c.Request.Method),
			logsafe.String("path", c.Request.URL.Path),
			logsafe.String("client_ip", getClientIP(c)),
			logsafe.String("user_agent", c.Request.UserAgent()),
		}

		// Add query parameters if enabled. sanitizeQueryParams redacts the values
		// of sensitive KEYS; it does not touch the rest of the query string, which
		// is entirely the client's.
		if config.LogQueryParams && c.Request.URL.RawQuery != "" {
			sanitizedQuery := sanitizeQueryParams(c.Request.URL.RawQuery, sanitizeFields)
			fields = append(fields, logsafe.String("query_params", sanitizedQuery))
		}

		// Add request body if enabled and present.
		//
		// Deliberately NOT cleaned through logsafe: this field is a payload, not
		// an identifier, and logsafe.MaxLen would cut it to 256 bytes, which
		// defeats the option somebody turned on. Its bound is the 10 KB truncation
		// above, and it is a zap field, so both encoders escape it (see
		// internal/common/logsafe/encoder_test.go). LogBody is off by default and
		// is a debugging tool; turning it on means accepting client bytes in the
		// log by definition.
		if config.LogBody && requestBody != "" {
			fields = append(fields, zap.String("request_body", requestBody))
		}

		// Add user ID from context if authenticated (set by Auth middleware)
		if userID, exists := c.Get("user_id"); exists {
			fields = append(fields, zap.String("user_id", toString(userID)))
		}

		// Add session ID if present
		if sessionID, exists := c.Get("session_id"); exists {
			fields = append(fields, zap.String("session_id", toString(sessionID)))
		}

		// Add service account ID if API key auth
		if saID, exists := c.Get("service_account_id"); exists {
			fields = append(fields, zap.String("service_account_id", toString(saID)))
		}

		// Add organization ID if present
		if orgID, exists := c.Get("org_id"); exists {
			fields = append(fields, zap.String("org_id", toString(orgID)))
		}

		// Add auth method if present
		if authMethod, exists := c.Get("auth_method"); exists {
			fields = append(fields, zap.String("auth_method", toString(authMethod)))
		}

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start)

		// Check minimum duration threshold
		if config.MinDuration > 0 && duration < config.MinDuration {
			return // Skip logging for fast requests
		}

		// Add response fields
		status := c.Writer.Status()
		fields = append(fields,
			zap.Int("status", status),
			zap.Duration("duration", duration),
			zap.Int("response_size", c.Writer.Size()),
		)

		// Add error message if present
		if len(c.Errors) > 0 {
			errors := make([]string, len(c.Errors))
			for i, err := range c.Errors {
				errors[i] = err.Error()
			}
			fields = append(fields, zap.Strings("errors", errors))
		}

		// Determine log level based on status code and duration
		logLevel := determineLogLevel(status, duration, config.MinDuration)

		// Log the request
		msg := formatLogMessage(c, duration)
		config.Logger.Log(logLevel, msg, fields...)
	}
}

// getClientIP returns the real client IP for logging.
//
// SECURITY: this used to read the LEFTMOST X-Forwarded-For entry directly, which
// is entirely attacker-controllable (any client can send an arbitrary
// X-Forwarded-For), letting an attacker forge the client IP in audit/access logs
// and defeating the whole point of recording it. We now delegate to
// c.ClientIP(), which honors the engine's trusted-proxy configuration
// (ConfigureTrustedProxies) and resolves the real client IP the trusted edge saw
// rather than any client-supplied header. Do NOT reintroduce raw header parsing.
func getClientIP(c *gin.Context) string {
	return c.ClientIP()
}

// sanitizeQueryParams redacts sensitive values from query parameters
// sanitizeQueryParams redacts sensitive parameter values. The implementation is
// logsafe.QueryString; this wrapper exists so the callers and tests in this
// package keep reading the way they did.
func sanitizeQueryParams(query string, sensitiveFields map[string]bool) string {
	return logsafe.QueryString(query, sensitiveFields)
}

// sanitizeJSON redacts sensitive fields in a request body. The implementation is
// logsafe.JSONBody.
func sanitizeJSON(jsonStr string, sensitiveFields map[string]bool) string {
	return logsafe.JSONBody(jsonStr, sensitiveFields)
}

// determineLogLevel returns the appropriate log level based on status and duration
func determineLogLevel(status int, duration, minDuration time.Duration) zapcore.Level {
	// Server errors (5xx)
	if status >= 500 {
		return zapcore.ErrorLevel
	}

	// Client errors (4xx)
	if status >= 400 {
		return zapcore.WarnLevel
	}

	// Slow requests (if min duration is set, very slow requests get warning)
	if minDuration > 0 && duration > minDuration*5 {
		return zapcore.WarnLevel
	}

	return zapcore.InfoLevel
}

// formatLogMessage creates a human-readable log message
func formatLogMessage(c *gin.Context, duration time.Duration) string {
	status := c.Writer.Status()

	// Handle errors
	if len(c.Errors) > 0 {
		return "Request completed with errors"
	}

	// Server errors
	if status >= 500 {
		return "Server error"
	}

	// Client errors
	if status >= 400 {
		return "Client error"
	}

	// Redirects
	if status >= 300 {
		return "Redirect"
	}

	// Success with performance indication
	if duration > time.Second {
		return "Request completed (slow)"
	}
	if duration > 500*time.Millisecond {
		return "Request completed (moderate latency)"
	}

	return "Request completed"
}

// toString converts various types to string safely
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case int:
		return string(rune(val))
	case int64:
		return string(rune(val))
	case float64:
		return string(rune(val))
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}
