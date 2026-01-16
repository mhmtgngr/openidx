// Package logger provides structured logging utilities for OpenIDX services
package logger

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// PerformanceLogger provides performance tracking and logging
type PerformanceLogger struct {
	logger *zap.Logger
}

// NewPerformanceLogger creates a new performance logger
func NewPerformanceLogger(logger *zap.Logger) *PerformanceLogger {
	return &PerformanceLogger{
		logger: logger.With(zap.String("log_type", "performance")),
	}
}

// Timer represents a performance timer
type Timer struct {
	logger    *zap.Logger
	operation string
	startTime time.Time
	fields    []zap.Field
}

// StartTimer starts a new performance timer
func (p *PerformanceLogger) StartTimer(operation string, fields ...zap.Field) *Timer {
	return &Timer{
		logger:    p.logger,
		operation: operation,
		startTime: time.Now(),
		fields:    fields,
	}
}

// Stop stops the timer and logs the duration
func (t *Timer) Stop() time.Duration {
	duration := time.Since(t.startTime)

	fields := append(t.fields,
		zap.String("operation", t.operation),
		zap.Duration("duration", duration),
		zap.Int64("duration_ms", duration.Milliseconds()),
	)

	// Log at different levels based on duration
	switch {
	case duration > 5*time.Second:
		t.logger.Warn("Slow operation", fields...)
	case duration > 1*time.Second:
		t.logger.Info("Operation completed", fields...)
	default:
		t.logger.Debug("Operation completed", fields...)
	}

	return duration
}

// StopWithError stops the timer and logs the duration with error
func (t *Timer) StopWithError(err error) time.Duration {
	duration := time.Since(t.startTime)

	fields := append(t.fields,
		zap.String("operation", t.operation),
		zap.Duration("duration", duration),
		zap.Int64("duration_ms", duration.Milliseconds()),
		zap.Error(err),
	)

	t.logger.Error("Operation failed", fields...)

	return duration
}

// LogDatabaseQuery logs a database query with execution time
func (p *PerformanceLogger) LogDatabaseQuery(query string, duration time.Duration, rowsAffected int64, err error) {
	fields := []zap.Field{
		zap.String("query_type", "database"),
		zap.String("query", truncateString(query, 500)), // Truncate long queries
		zap.Duration("duration", duration),
		zap.Int64("duration_ms", duration.Milliseconds()),
		zap.Int64("rows_affected", rowsAffected),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		p.logger.Error("Database query failed", fields...)
	} else if duration > 100*time.Millisecond {
		p.logger.Warn("Slow database query", fields...)
	} else {
		p.logger.Debug("Database query executed", fields...)
	}
}

// LogAPICall logs an external API call with timing
func (p *PerformanceLogger) LogAPICall(endpoint string, method string, statusCode int, duration time.Duration, err error) {
	fields := []zap.Field{
		zap.String("api_type", "external"),
		zap.String("endpoint", endpoint),
		zap.String("method", method),
		zap.Int("status_code", statusCode),
		zap.Duration("duration", duration),
		zap.Int64("duration_ms", duration.Milliseconds()),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		p.logger.Error("API call failed", fields...)
	} else if statusCode >= 500 {
		p.logger.Error("API call returned server error", fields...)
	} else if statusCode >= 400 {
		p.logger.Warn("API call returned client error", fields...)
	} else if duration > 2*time.Second {
		p.logger.Warn("Slow API call", fields...)
	} else {
		p.logger.Debug("API call completed", fields...)
	}
}

// LogCacheOperation logs a cache operation
func (p *PerformanceLogger) LogCacheOperation(operation string, key string, hit bool, duration time.Duration) {
	fields := []zap.Field{
		zap.String("cache_operation", operation),
		zap.String("key", truncateString(key, 100)),
		zap.Bool("hit", hit),
		zap.Duration("duration", duration),
		zap.Int64("duration_ms", duration.Milliseconds()),
	}

	if hit {
		p.logger.Debug("Cache hit", fields...)
	} else {
		p.logger.Debug("Cache miss", fields...)
	}
}

// LogMemoryUsage logs current memory usage
func (p *PerformanceLogger) LogMemoryUsage(allocMB, totalAllocMB, sysMB, numGC uint32) {
	p.logger.Info("Memory usage",
		zap.Uint32("alloc_mb", allocMB),
		zap.Uint32("total_alloc_mb", totalAllocMB),
		zap.Uint32("sys_mb", sysMB),
		zap.Uint32("num_gc", numGC),
	)
}

// LogRequestThroughput logs request throughput metrics
func (p *PerformanceLogger) LogRequestThroughput(endpoint string, requestsPerSecond float64, avgDuration time.Duration) {
	fields := []zap.Field{
		zap.String("endpoint", endpoint),
		zap.Float64("requests_per_second", requestsPerSecond),
		zap.Duration("avg_duration", avgDuration),
		zap.Int64("avg_duration_ms", avgDuration.Milliseconds()),
	}

	if requestsPerSecond > 1000 {
		p.logger.Warn("High request throughput", fields...)
	} else {
		p.logger.Info("Request throughput", fields...)
	}
}

// ContextTimer is a context-aware timer
type ContextTimer struct {
	ctx       context.Context
	logger    *zap.Logger
	operation string
	startTime time.Time
	fields    []zap.Field
}

// StartContextTimer starts a context-aware timer
func (p *PerformanceLogger) StartContextTimer(ctx context.Context, operation string, fields ...zap.Field) *ContextTimer {
	return &ContextTimer{
		ctx:       ctx,
		logger:    p.logger,
		operation: operation,
		startTime: time.Now(),
		fields:    fields,
	}
}

// Stop stops the context timer and logs the duration
func (ct *ContextTimer) Stop() time.Duration {
	duration := time.Since(ct.startTime)

	fields := append(ct.fields,
		zap.String("operation", ct.operation),
		zap.Duration("duration", duration),
		zap.Int64("duration_ms", duration.Milliseconds()),
	)

	// Check if context was cancelled
	if ct.ctx.Err() != nil {
		fields = append(fields, zap.Error(ct.ctx.Err()))
		ct.logger.Warn("Operation cancelled", fields...)
		return duration
	}

	// Log based on duration
	switch {
	case duration > 5*time.Second:
		ct.logger.Warn("Slow operation", fields...)
	case duration > 1*time.Second:
		ct.logger.Info("Operation completed", fields...)
	default:
		ct.logger.Debug("Operation completed", fields...)
	}

	return duration
}

// Metrics represents performance metrics
type Metrics struct {
	Operation     string        `json:"operation"`
	Count         int64         `json:"count"`
	TotalDuration time.Duration `json:"total_duration"`
	AvgDuration   time.Duration `json:"avg_duration"`
	MinDuration   time.Duration `json:"min_duration"`
	MaxDuration   time.Duration `json:"max_duration"`
	ErrorCount    int64         `json:"error_count"`
}

// LogMetrics logs aggregated performance metrics
func (p *PerformanceLogger) LogMetrics(metrics *Metrics) {
	p.logger.Info("Performance metrics",
		zap.String("operation", metrics.Operation),
		zap.Int64("count", metrics.Count),
		zap.Duration("total_duration", metrics.TotalDuration),
		zap.Duration("avg_duration", metrics.AvgDuration),
		zap.Duration("min_duration", metrics.MinDuration),
		zap.Duration("max_duration", metrics.MaxDuration),
		zap.Int64("error_count", metrics.ErrorCount),
		zap.Float64("error_rate", float64(metrics.ErrorCount)/float64(metrics.Count)*100),
	)
}

// Helper function to truncate strings
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// WarnThreshold logs a warning if duration exceeds threshold
func (p *PerformanceLogger) WarnThreshold(operation string, duration, threshold time.Duration, fields ...zap.Field) {
	if duration > threshold {
		allFields := append(fields,
			zap.String("operation", operation),
			zap.Duration("duration", duration),
			zap.Duration("threshold", threshold),
			zap.Int64("duration_ms", duration.Milliseconds()),
			zap.Int64("threshold_ms", threshold.Milliseconds()),
		)
		p.logger.Warn("Operation exceeded threshold", allFields...)
	}
}

// LogBatchOperation logs a batch operation
func (p *PerformanceLogger) LogBatchOperation(operation string, batchSize int, duration time.Duration, successCount, failureCount int) {
	fields := []zap.Field{
		zap.String("operation", operation),
		zap.Int("batch_size", batchSize),
		zap.Duration("duration", duration),
		zap.Int64("duration_ms", duration.Milliseconds()),
		zap.Int("success_count", successCount),
		zap.Int("failure_count", failureCount),
		zap.Float64("success_rate", float64(successCount)/float64(batchSize)*100),
	}

	if failureCount > 0 {
		p.logger.Warn("Batch operation completed with failures", fields...)
	} else {
		p.logger.Info("Batch operation completed successfully", fields...)
	}
}

// LogConcurrentOperation logs metrics for concurrent operations
func (p *PerformanceLogger) LogConcurrentOperation(operation string, goroutines int, totalDuration time.Duration, itemsProcessed int) {
	avgPerItem := time.Duration(0)
	if itemsProcessed > 0 {
		avgPerItem = totalDuration / time.Duration(itemsProcessed)
	}

	p.logger.Info("Concurrent operation completed",
		zap.String("operation", operation),
		zap.Int("goroutines", goroutines),
		zap.Duration("total_duration", totalDuration),
		zap.Int("items_processed", itemsProcessed),
		zap.Duration("avg_per_item", avgPerItem),
		zap.Int64("items_per_second", int64(float64(itemsProcessed)/totalDuration.Seconds())),
	)
}
