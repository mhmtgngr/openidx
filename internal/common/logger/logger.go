// Package logger provides structured logging utilities for OpenIDX services
package logger

import (
	"context"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New creates a new zap logger with sensible defaults
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
		panic("failed to initialize logger: " + err.Error())
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

		fields := []zap.Field{
			zap.Int("status", status),
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.String("query", query),
			zap.String("ip", c.ClientIP()),
			zap.String("user-agent", c.Request.UserAgent()),
			zap.Duration("latency", latency),
			zap.Int("body_size", c.Writer.Size()),
		}

		// Add request ID if present
		if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
			fields = append(fields, zap.String("request_id", requestID))
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
