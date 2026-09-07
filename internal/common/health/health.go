// Package health provides health check endpoints and dependency monitoring
// for OpenIDX services, supporting liveness, readiness, and detailed health probes.
package health

import (
	"context"
	"fmt"
	"time"

	"github.com/openidx/openidx/internal/common/database"
)

// HealthStatus represents the overall health of the service
type HealthStatus struct {
	Status       string                     `json:"status"` // healthy, degraded, unhealthy
	Version      string                     `json:"version,omitempty"`
	Uptime       string                     `json:"uptime"`
	Dependencies map[string]DependencyCheck `json:"dependencies"`
	CheckedAt    time.Time                  `json:"checked_at"`
}

// DependencyCheck represents the health check result for a single dependency
type DependencyCheck struct {
	Status    string    `json:"status"` // up, degraded, down
	Latency   string    `json:"latency"`
	Details   string    `json:"details,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// HealthChecker is the interface that dependency health checks must implement
type HealthChecker interface {
	Name() string
	Check(ctx context.Context) DependencyCheck
}

// A THIRD HealthService used to sit here, after this package's own types: the
// live one is internal/health.HealthService, which every cmd/ binary mounts.
// This one had its own Check/Handler/ReadyHandler/LiveHandler and a
// RegisterStandardRoutes, and nothing constructed it -- the register's "second
// implementation in the same package as the first" shape, one package over.
//
// What survives is what this package is actually for: the DependencyCheck /
// HealthChecker vocabulary the access service's integration health handlers
// speak, the two checkers below, and WaitForDependency in wait.go.

type PostgresChecker struct {
	db *database.PostgresDB
}

// NewPostgresChecker creates a new PostgresChecker
func NewPostgresChecker(db *database.PostgresDB) *PostgresChecker {
	return &PostgresChecker{db: db}
}

// Name returns the checker name
func (p *PostgresChecker) Name() string {
	return "postgres"
}

// Check tests the PostgreSQL connection by running SELECT 1 and measuring latency
func (p *PostgresChecker) Check(ctx context.Context) DependencyCheck {
	start := time.Now()

	var one int
	err := p.db.Pool.QueryRow(ctx, "SELECT 1").Scan(&one)
	latency := time.Since(start)

	if err != nil {
		return DependencyCheck{
			Status:    "down",
			Latency:   latency.String(),
			Details:   fmt.Sprintf("query failed: %v", err),
			CheckedAt: time.Now(),
		}
	}

	status := "up"
	details := ""
	if latency > 500*time.Millisecond {
		status = "degraded"
		details = fmt.Sprintf("high latency: %s", latency.String())
	}

	return DependencyCheck{
		Status:    status,
		Latency:   latency.String(),
		Details:   details,
		CheckedAt: time.Now(),
	}
}

// RedisChecker checks the health of a Redis connection
type RedisChecker struct {
	redis *database.RedisClient
}

// NewRedisChecker creates a new RedisChecker
func NewRedisChecker(redis *database.RedisClient) *RedisChecker {
	return &RedisChecker{redis: redis}
}

// Name returns the checker name
func (r *RedisChecker) Name() string {
	return "redis"
}

// Check tests the Redis connection by running PING and measuring latency
func (r *RedisChecker) Check(ctx context.Context) DependencyCheck {
	start := time.Now()

	_, err := r.redis.Client.Ping(ctx).Result()
	latency := time.Since(start)

	if err != nil {
		return DependencyCheck{
			Status:    "down",
			Latency:   latency.String(),
			Details:   fmt.Sprintf("ping failed: %v", err),
			CheckedAt: time.Now(),
		}
	}

	status := "up"
	details := ""
	if latency > 200*time.Millisecond {
		status = "degraded"
		details = fmt.Sprintf("high latency: %s", latency.String())
	}

	return DependencyCheck{
		Status:    status,
		Latency:   latency.String(),
		Details:   details,
		CheckedAt: time.Now(),
	}
}

// formatDuration produces a human-readable duration string
func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
