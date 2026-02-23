// Package health provides health check endpoints and dependency monitoring
// This file provides built-in health checkers for common dependencies
package health

import (
	"context"
	"time"

	"github.com/openidx/openidx/internal/common/database"
)

// PostgresChecker checks the health of a PostgreSQL connection
type PostgresChecker struct {
	db       *database.PostgresDB
	critical bool
}

// NewPostgresChecker creates a new PostgresChecker (marked as critical)
func NewPostgresChecker(db *database.PostgresDB) *PostgresChecker {
	return &PostgresChecker{db: db, critical: true}
}

// NewPostgresCheckerOptional creates a non-critical PostgresChecker
func NewPostgresCheckerOptional(db *database.PostgresDB) *PostgresChecker {
	return &PostgresChecker{db: db, critical: false}
}

// Name returns the checker name
func (p *PostgresChecker) Name() string {
	return "database"
}

// IsCritical returns true if this component is critical for readiness
func (p *PostgresChecker) IsCritical() bool {
	return p.critical
}

// Check tests the PostgreSQL connection by running SELECT 1 and measuring latency
func (p *PostgresChecker) Check(ctx context.Context) ComponentStatus {
	start := time.Now()

	var one int
	err := p.db.Pool.QueryRow(ctx, "SELECT 1").Scan(&one)
	latency := time.Since(start)

	if err != nil {
		return ComponentStatus{
			Status:     "down",
			LatencyMS:  float64(latency.Milliseconds()),
			Details:    err.Error(),
			CheckedAt:  time.Now().UTC().Format(time.RFC3339),
		}
	}

	status := "up"
	details := ""
	if latency > 500*time.Millisecond {
		status = "degraded"
		details = "high latency"
	}

	return ComponentStatus{
		Status:     status,
		LatencyMS:  float64(latency.Milliseconds()),
		Details:    details,
		CheckedAt:  time.Now().UTC().Format(time.RFC3339),
	}
}

// RedisChecker checks the health of a Redis connection
type RedisChecker struct {
	redis    *database.RedisClient
	critical bool
}

// NewRedisChecker creates a new RedisChecker (marked as critical)
func NewRedisChecker(redis *database.RedisClient) *RedisChecker {
	return &RedisChecker{redis: redis, critical: true}
}

// NewRedisCheckerOptional creates a non-critical RedisChecker
func NewRedisCheckerOptional(redis *database.RedisClient) *RedisChecker {
	return &RedisChecker{redis: redis, critical: false}
}

// Name returns the checker name
func (r *RedisChecker) Name() string {
	return "redis"
}

// IsCritical returns true if this component is critical for readiness
func (r *RedisChecker) IsCritical() bool {
	return r.critical
}

// Check tests the Redis connection by running PING and measuring latency
func (r *RedisChecker) Check(ctx context.Context) ComponentStatus {
	start := time.Now()

	_, err := r.redis.Client.Ping(ctx).Result()
	latency := time.Since(start)

	if err != nil {
		return ComponentStatus{
			Status:     "down",
			LatencyMS:  float64(latency.Milliseconds()),
			Details:    err.Error(),
			CheckedAt:  time.Now().UTC().Format(time.RFC3339),
		}
	}

	status := "up"
	details := ""
	if latency > 200*time.Millisecond {
		status = "degraded"
		details = "high latency"
	}

	return ComponentStatus{
		Status:     status,
		LatencyMS:  float64(latency.Milliseconds()),
		Details:    details,
		CheckedAt:  time.Now().UTC().Format(time.RFC3339),
	}
}

// StaticChecker allows creating a simple static health checker
type StaticChecker struct {
	name      string
	status    string
	details   string
	critical  bool
}

// NewStaticChecker creates a checker that always returns the same status
func NewStaticChecker(name, status, details string, critical bool) *StaticChecker {
	return &StaticChecker{
		name:     name,
		status:   status,
		details:  details,
		critical: critical,
	}
}

// Name returns the checker name
func (s *StaticChecker) Name() string {
	return s.name
}

// IsCritical returns true if this component is critical for readiness
func (s *StaticChecker) IsCritical() bool {
	return s.critical
}

// Check returns the static status
func (s *StaticChecker) Check(ctx context.Context) ComponentStatus {
	return ComponentStatus{
		Status:     s.status,
		LatencyMS:  0,
		Details:    s.details,
		CheckedAt:  time.Now().UTC().Format(time.RFC3339),
	}
}

// FuncChecker allows creating a health checker from a function
type FuncChecker struct {
	name     string
	check    func(context.Context) ComponentStatus
	critical bool
}

// NewFuncChecker creates a checker from a function
func NewFuncChecker(name string, check func(context.Context) ComponentStatus, critical bool) *FuncChecker {
	return &FuncChecker{
		name:     name,
		check:    check,
		critical: critical,
	}
}

// Name returns the checker name
func (f *FuncChecker) Name() string {
	return f.name
}

// IsCritical returns true if this component is critical for readiness
func (f *FuncChecker) IsCritical() bool {
	return f.critical
}

// Check calls the wrapped function
func (f *FuncChecker) Check(ctx context.Context) ComponentStatus {
	return f.check(ctx)
}
