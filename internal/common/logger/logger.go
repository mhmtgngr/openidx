// Package logger provides structured logging utilities for OpenIDX services
package logger

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/openidx/openidx/internal/common/logsafe"
)

// New creates a new zap logger with sensible defaults.
// Falls back to a production-safe default logger if initialization fails.
func New() *zap.Logger {
	env := os.Getenv("APP_ENV")
	level := os.Getenv("LOG_LEVEL")

	var config zap.Config

	if env == "production" || env == "prod" {
		config = zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	} else {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	// Set log level
	switch level {
	case "debug":
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		config.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		config.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		if env == "production" || env == "prod" {
			config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		} else {
			config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		}
	}

	logger, err := config.Build(
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)
	if err != nil {
		// Fall back to a minimal safe logger instead of panicking.
		// Write to stderr and return a no-op logger to avoid crashing.
		// In production, this ensures the service can start even if logging config is invalid.
		logger = zap.NewNop()
		_ = logger.Sync() // Ensure the nop logger is safe
		// Use stderr directly since we can't log
		fmt.Fprintf(os.Stderr, "WARNING: Failed to initialize logger, using no-op logger: %v\n", err)
		// Create a minimal stderr logger as fallback
		logger = zap.New(zapcore.NewCore(
			zapcore.NewJSONEncoder(zapcore.EncoderConfig{
				TimeKey:        "ts",
				LevelKey:       "level",
				NameKey:        "logger",
				CallerKey:      "caller",
				FunctionKey:    zapcore.OmitKey,
				MessageKey:     "msg",
				StacktraceKey:  "stacktrace",
				LineEnding:     zapcore.DefaultLineEnding,
				EncodeLevel:    zapcore.LowercaseLevelEncoder,
				EncodeTime:     zapcore.EpochMillisTimeEncoder,
				EncodeDuration: zapcore.SecondsDurationEncoder,
				EncodeCaller:   zapcore.ShortCallerEncoder,
			}),
			zapcore.AddSync(os.Stderr),
			zap.NewAtomicLevelAt(zap.InfoLevel),
		))
	}

	return logger
}

// GinMiddleware returns a Gin middleware that logs HTTP requests
func GinMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		// Process request
		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		// Everything here that is a string came off the wire: the path carries
		// whatever %-encoding the client chose, the query and user agent are the
		// client's outright, and ip is X-Forwarded-For behind a trusted proxy.
		// See internal/common/logsafe.
		//
		// The query goes through logsafe.QueryField, which REDACTS before it
		// cleans. This is the request logger every service actually mounts --
		// cmd/{identity,oauth,access,admin-api,audit,governance,provisioning,
		// gateway}-service all call GinMiddleware -- and until this line it wrote
		// the raw query string. internal/common/middleware has a request logger
		// that has redacted query parameters for its whole life and is mounted by
		// nothing, which is the only reason the gap was not obvious: the control
		// existed, in the copy that never ran. Five callback routes read the OAuth
		// authorization code from the query string, and one reads a magic-link
		// token; all of them were logged in clear on every request.
		fields := []zap.Field{
			zap.Int("status", status),
			logsafe.String("method", c.Request.Method),
			logsafe.String("path", path),
			logsafe.QueryField("query", query),
			logsafe.String("ip", c.ClientIP()),
			logsafe.String("user-agent", c.Request.UserAgent()),
			zap.Duration("latency", latency),
			zap.Int("body_size", c.Writer.Size()),
		}

		// Add request ID if present. Prefer the one a RequestID middleware already
		// vetted and put on the context; fall back to the header only when it is
		// id-shaped, so a hostile value is dropped rather than logged.
		if requestID, ok := c.Get("request_id"); ok {
			if id, isStr := requestID.(string); isStr && id != "" {
				fields = append(fields, logsafe.String("request_id", id))
			}
		} else if id := c.GetHeader("X-Request-ID"); logsafe.PlausibleID(id) {
			fields = append(fields, zap.String("request_id", id))
		}

		// Add user ID if authenticated
		if userID, exists := c.Get("user_id"); exists {
			fields = append(fields, zap.Any("user_id", userID))
		}

		// Add trace context for log-trace correlation
		span := trace.SpanFromContext(c.Request.Context())
		if span.SpanContext().IsValid() {
			fields = append(fields,
				zap.String("trace_id", span.SpanContext().TraceID().String()),
				zap.String("span_id", span.SpanContext().SpanID().String()),
			)
		}

		// Log at appropriate level based on status code
		switch {
		case status >= 500:
			logger.Error("Server error", fields...)
		case status >= 400:
			logger.Warn("Client error", fields...)
		case status >= 300:
			logger.Info("Redirect", fields...)
		default:
			logger.Info("Request completed", fields...)
		}
	}
}

// WithContext returns a logger with context fields
func WithContext(logger *zap.Logger, fields ...zap.Field) *zap.Logger {
	return logger.With(fields...)
}

// WithService returns a logger with service name
func WithService(logger *zap.Logger, serviceName string) *zap.Logger {
	return logger.With(zap.String("service", serviceName))
}

// WithRequestID returns a logger with request ID
func WithRequestID(logger *zap.Logger, requestID string) *zap.Logger {
	return logger.With(zap.String("request_id", requestID))
}

// WithUserID returns a logger with user ID
func WithUserID(logger *zap.Logger, userID string) *zap.Logger {
	return logger.With(zap.String("user_id", userID))
}

// WithTraceContext returns a logger with OpenTelemetry trace context fields
// for log-trace correlation
func WithTraceContext(logger *zap.Logger, ctx context.Context) *zap.Logger {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return logger
	}
	return logger.With(
		zap.String("trace_id", span.SpanContext().TraceID().String()),
		zap.String("span_id", span.SpanContext().SpanID().String()),
	)
}
