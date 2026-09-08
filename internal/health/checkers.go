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
			Status:    "down",
			LatencyMS: float64(latency.Milliseconds()),
			Details:   err.Error(),
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	status := "up"
	details := ""
	if latency > 500*time.Millisecond {
		status = "degraded"
		details = "high latency"
	}

	return ComponentStatus{
		Status:    status,
		LatencyMS: float64(latency.Milliseconds()),
		Details:   details,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// ReadReplicaChecker checks the health of the optional read-replica pool. It is
// NON-critical by design: a replica outage must not fail readiness (traffic
// transparently falls back to the primary via PostgresDB.Reader()), it only
// surfaces the degradation so operators can see when read offload is lost.
type ReadReplicaChecker struct {
	db *database.PostgresDB
}

// NewReadReplicaChecker creates a non-critical read-replica checker.
func NewReadReplicaChecker(db *database.PostgresDB) *ReadReplicaChecker {
	return &ReadReplicaChecker{db: db}
}

// Name returns the checker name.
func (r *ReadReplicaChecker) Name() string { return "database_replica" }

// IsCritical is always false: the replica is an optimization + warm standby.
func (r *ReadReplicaChecker) IsCritical() bool { return false }

// Check pings the replica. When no replica is configured it reports "up" with a
// note (nothing to fail on); a ping failure reports "down" but, being
// non-critical, only degrades overall health rather than failing readiness.
func (r *ReadReplicaChecker) Check(ctx context.Context) ComponentStatus {
	if !r.db.HasReadReplica() {
		return ComponentStatus{
			Status:    "up",
			Details:   "no read replica configured (reads served by primary)",
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}
	start := time.Now()
	err := r.db.PingRead()
	latency := time.Since(start)
	if err != nil {
		return ComponentStatus{
			Status:    "down",
			LatencyMS: float64(latency.Milliseconds()),
			Details:   "replica unreachable; reads fall back to primary: " + err.Error(),
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}
	status := "up"
	details := ""
	if latency > 500*time.Millisecond {
		status = "degraded"
		details = "high latency"
	}
	return ComponentStatus{
		Status:    status,
		LatencyMS: float64(latency.Milliseconds()),
		Details:   details,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
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
			Status:    "down",
			LatencyMS: float64(latency.Milliseconds()),
			Details:   err.Error(),
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	status := "up"
	details := ""
	if latency > 200*time.Millisecond {
		status = "degraded"
		details = "high latency"
	}

	return ComponentStatus{
		Status:    status,
		LatencyMS: float64(latency.Milliseconds()),
		Details:   details,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// StaticChecker and FuncChecker used to follow: a checker with a fixed answer
// and a checker built from a closure, for a caller that wanted an ad-hoc check.
// Nothing ever wanted one -- the checks the services mount are the concrete
// ones above and the certificate check in cert_checker.go, each of which
// measures something. A checker that returns a constant is a health endpoint
// that reports what it was told rather than what is true, which is the shape
// this branch keeps removing.
