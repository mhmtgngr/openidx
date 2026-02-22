// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"bytes"
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// RecoveryConfig holds configuration for the recovery middleware
type RecoveryConfig struct {
	// Logger is the zap logger instance for logging panics
	Logger *zap.Logger
	// StackTrace indicates whether to include stack trace in logs
	StackTrace bool
	// ReturnStackTrace indicates whether to include stack trace in error response (development only)
	ReturnStackTrace bool
}

// DefaultRecoveryConfig returns default recovery configuration
func DefaultRecoveryConfig(logger *zap.Logger) RecoveryConfig {
	return RecoveryConfig{
		Logger:           logger,
		StackTrace:       true,
		ReturnStackTrace: false,
	}
}

// ErrorResponse represents the JSON error response returned on panic
type ErrorResponse struct {
	Error          string `json:"error"`
	Message        string `json:"message,omitempty"`
	CorrelationID  string `json:"correlation_id"`
	StackTrace     string `json:"stack_trace,omitempty"`
	Timestamp      string `json:"timestamp"`
}

// Recovery returns a middleware that recovers from panics.
// It logs the stack trace with correlation ID and returns a JSON error response.
func Recovery(logger *zap.Logger) gin.HandlerFunc {
	cfg := DefaultRecoveryConfig(logger)
	return RecoveryWithConfig(cfg)
}

// RecoveryWithConfig returns a recovery middleware with custom configuration
func RecoveryWithConfig(cfg RecoveryConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Get or generate correlation ID
				correlationID := GetRequestID(c)
				if correlationID == "" {
					correlationID = uuid.New().String()
				}

				// Capture stack trace
				stackTrace := ""
				if cfg.StackTrace {
					stackTrace = string(debug.Stack())
				}

				// Log the panic with correlation ID
				logFields := []zap.Field{
					zap.String("correlation_id", correlationID),
					zap.String("panic", fmt.Sprintf("%v", err)),
					zap.String("method", c.Request.Method),
					zap.String("path", c.Request.URL.Path),
					zap.String("query", c.Request.URL.RawQuery),
					zap.String("ip", c.ClientIP()),
					zap.String("user_agent", c.Request.UserAgent()),
				}

				if userID, exists := c.Get("user_id"); exists {
					if uid, ok := userID.(string); ok {
						logFields = append(logFields, zap.String("user_id", uid))
					}
				}

				if cfg.StackTrace && stackTrace != "" {
					logFields = append(logFields, zap.String("stack_trace", stackTrace))
				}

				cfg.Logger.Error("Panic recovered", logFields...)

				// Prepare error response
				errorResp := ErrorResponse{
					Error:         "internal server error",
					CorrelationID: correlationID,
					Timestamp:     time.Now().UTC().Format(time.RFC3339),
				}

				// Include error message (sanitized)
				if errMsg := fmt.Sprintf("%v", err); errMsg != "" {
					errorResp.Message = sanitizeErrorMessage(errMsg)
				}

				// Include stack trace in response only in development
				if cfg.ReturnStackTrace && cfg.StackTrace && stackTrace != "" {
					errorResp.StackTrace = stackTrace
				}

				// Check if client expects JSON
				if wantsJSON(c) {
					c.AbortWithStatusJSON(http.StatusInternalServerError, errorResp)
				} else {
					c.AbortWithStatus(http.StatusInternalServerError)
					c.Header("X-Correlation-ID", correlationID)
				}
			}
		}()

		c.Next()
	}
}

// RecoveryWithWriter returns a recovery middleware that writes to a custom writer
// This is useful for logging to a file or other output
func RecoveryWithWriter(logger *zap.Logger, returnStackTrace bool) gin.HandlerFunc {
	cfg := RecoveryConfig{
		Logger:           logger,
		StackTrace:       true,
		ReturnStackTrace: returnStackTrace,
	}
	return RecoveryWithConfig(cfg)
}

// sanitizeErrorMessage removes potentially sensitive information from error messages
func sanitizeErrorMessage(msg string) string {
	// Truncate very long error messages
	const maxLen = 500
	if len(msg) > maxLen {
		return msg[:maxLen] + "..."
	}
	return msg
}

// wantsJSON checks if the client expects a JSON response
func wantsJSON(c *gin.Context) bool {
	// Check Accept header
	accept := c.Request.Header.Get("Accept")
	if accept == "*/*" || accept == "" {
		// Default to JSON for API paths
		return len(c.Request.URL.Path) > 4 && c.Request.URL.Path[:4] == "/api"
	}

	// Check if client accepts JSON
	return contains(accept, "application/json")
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}

// PanicReport represents detailed information about a panic for reporting
type PanicReport struct {
	CorrelationID  string    `json:"correlation_id"`
	Panic          string    `json:"panic"`
	StackTrace     string    `json:"stack_trace"`
	Method         string    `json:"method"`
	Path           string    `json:"path"`
	Query          string    `json:"query,omitempty"`
	UserID         string    `json:"user_id,omitempty"`
	ClientIP       string    `json:"client_ip"`
	UserAgent      string    `json:"user_agent,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
	Headers        map[string]string `json:"headers,omitempty"`
}

// CapturePanic captures the current panic and returns a report
// This can be used in conjunction with external error tracking services
func CapturePanic(c *gin.Context, err interface{}) *PanicReport {
	report := &PanicReport{
		CorrelationID: GetRequestID(c),
		Panic:         fmt.Sprintf("%v", err),
		StackTrace:    string(debug.Stack()),
		Method:        c.Request.Method,
		Path:          c.Request.URL.Path,
		Query:         c.Request.URL.RawQuery,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
		Timestamp:     time.Now().UTC(),
	}

	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(string); ok {
			report.UserID = uid
		}
	}

	return report
}
