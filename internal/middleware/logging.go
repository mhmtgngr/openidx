// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LoggingConfig holds configuration for the logging middleware
type LoggingConfig struct {
	// Logger is the zap logger instance
	Logger *zap.Logger
	// TimeFormat specifies the format for timestamps in logs
	TimeFormat string
	// UTC indicates whether to use UTC time
	UTC bool
	// SkipPaths is a list of paths to skip logging
	SkipPaths []string
	// QueryParams indicates whether to log query parameters
	QueryParams bool
}

// DefaultLoggingConfig returns default logging configuration
func DefaultLoggingConfig(logger *zap.Logger) LoggingConfig {
	return LoggingConfig{
		Logger:      logger,
		TimeFormat:  time.RFC3339,
		UTC:         true,
		SkipPaths:   []string{"/health", "/metrics", "/ready"},
		QueryParams: true,
	}
}

// responseWriter wraps gin.ResponseWriter to capture status code and response size
type responseWriter struct {
	gin.ResponseWriter
	statusCode int
	size       int
	written    bool
}

// WriteHeader captures the status code
func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

// Write captures the response size
func (rw *responseWriter) Write(data []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(rw.ResponseWriter.Status())
	}
	size, err := rw.ResponseWriter.Write(data)
	rw.size += size
	return size, err
}

// WriteString captures the response size for string writes
func (rw *responseWriter) WriteString(s string) (int, error) {
	if !rw.written {
		rw.WriteHeader(rw.ResponseWriter.Status())
	}
	size, err := rw.ResponseWriter.WriteString(s)
	rw.size += size
	return size, err
}

// responseBodyReader wraps io.Reader to capture request body for logging
type responseBodyReader struct {
	io.ReadCloser
	buf *bytes.Buffer
}

// Read reads from the underlying reader and buffers the data
func (r *responseBodyReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.buf.Write(p[:n])
	}
	return n, err
}

// JSONLogEntry represents a structured log entry
type JSONLogEntry struct {
	Time        string                 `json:"time"`
	Method      string                 `json:"method"`
	Path        string                 `json:"path"`
	Query       string                 `json:"query,omitempty"`
	Protocol    string                 `json:"protocol"`
	Status      int                    `json:"status"`
	Latency     int64                  `json:"duration_ms"`
	ClientIP    string                 `json:"ip"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	RequestID   string                 `json:"request_id"`
	UserID      string                 `json:"user_id,omitempty"`
	Referer     string                 `json:"referer,omitempty"`
	BytesIn     int                    `json:"bytes_in,omitempty"`
	BytesOut    int                    `json:"bytes_out,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

// Logging returns a middleware that logs HTTP requests as structured JSON.
// Logs: method, path, status, duration_ms, request_id, user_id, ip, user_agent.
func Logging(logger *zap.Logger) gin.HandlerFunc {
	cfg := DefaultLoggingConfig(logger)
	return LoggingWithConfig(cfg)
}

// LoggingWithConfig returns a logging middleware with custom configuration
func LoggingWithConfig(cfg LoggingConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip logging for configured paths
		for _, skipPath := range cfg.SkipPaths {
			if c.Request.URL.Path == skipPath {
				c.Next()
				return
			}
		}

		start := time.Now()

		// Get request ID
		requestID := GetRequestID(c)
		if requestID == "" {
			requestID = "unknown"
		}

		// Get user ID if present (set by auth middleware)
		userID := ""
		if uid, exists := c.Get("user_id"); exists {
			if uidStr, ok := uid.(string); ok {
				userID = uidStr
			}
		}

		// Capture request body size
		bytesIn := 0
		if c.Request.Body != nil && c.Request.ContentLength > 0 {
			bytesIn = int(c.Request.ContentLength)
		}

		// Wrap response writer to capture status and size
		w := &responseWriter{
			ResponseWriter: c.Writer,
			statusCode:     http.StatusOK, // Default status
		}
		c.Writer = w

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start)
		if cfg.UTC {
			start = start.UTC()
		}

		// Build log entry
		entry := JSONLogEntry{
			Time:      start.Format(cfg.TimeFormat),
			Method:    c.Request.Method,
			Path:      c.Request.URL.Path,
			Protocol:  c.Request.Proto,
			Status:    w.statusCode,
			Latency:   duration.Milliseconds(),
			ClientIP:  c.ClientIP(),
			RequestID: requestID,
			UserID:    userID,
			BytesIn:   bytesIn,
			BytesOut:  w.size,
		}

		// Add query params if enabled
		if cfg.QueryParams && c.Request.URL.RawQuery != "" {
			entry.Query = c.Request.URL.RawQuery
		}

		// Add user agent
		if ua := c.Request.UserAgent(); ua != "" {
			entry.UserAgent = ua
		}

		// Add referer
		if referer := c.Request.Header.Get("Referer"); referer != "" {
			entry.Referer = referer
		}

		// Log using zap
		logFields := []zap.Field{
			zap.String("method", entry.Method),
			zap.String("path", entry.Path),
			zap.Int("status", entry.Status),
			zap.Int64("duration_ms", entry.Latency),
			zap.String("request_id", entry.RequestID),
			zap.String("ip", entry.ClientIP),
		}

		if entry.Query != "" {
			logFields = append(logFields, zap.String("query", entry.Query))
		}

		if entry.UserAgent != "" {
			logFields = append(logFields, zap.String("user_agent", entry.UserAgent))
		}

		if entry.UserID != "" {
			logFields = append(logFields, zap.String("user_id", entry.UserID))
		}

		if entry.BytesIn > 0 {
			logFields = append(logFields, zap.Int("bytes_in", entry.BytesIn))
		}

		if entry.BytesOut > 0 {
			logFields = append(logFields, zap.Int("bytes_out", entry.BytesOut))
		}

		if entry.Referer != "" {
			logFields = append(logFields, zap.String("referer", entry.Referer))
		}

		// Handle errors
		if len(c.Errors) > 0 {
			err := c.Errors.String()
			entry.Error = err
			logFields = append(logFields, zap.String("error", err))
		}

		// Log at appropriate level based on status code
		switch {
		case w.statusCode >= 500:
			cfg.Logger.Error("HTTP request", logFields...)
		case w.statusCode >= 400:
			cfg.Logger.Warn("HTTP request", logFields...)
		case w.statusCode >= 200:
			cfg.Logger.Info("HTTP request", logFields...)
		default:
			cfg.Logger.Debug("HTTP request", logFields...)
		}
	}
}

// LogFormatter returns a function that formats log entries as JSON
func LogFormatter(entry JSONLogEntry) string {
	data, _ := json.Marshal(entry)
	return string(data)
}

// Custom logger configuration presets
func NewProductionLogger() (*zap.Logger, error) {
	return zap.NewProduction()
}

func NewDevelopmentLogger() (*zap.Logger, error) {
	return zap.NewDevelopment()
}

func NewJSONLogger(encoderConfig zapcore.EncoderConfig) (*zap.Logger, error) {
	encoder := zapcore.NewJSONEncoder(encoderConfig)
	core := zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), zapcore.InfoLevel)
	return zap.New(core), nil
}
