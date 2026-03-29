// Package metrics provides database instrumentation for Prometheus metrics
package metrics

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TracedPool wraps pgxpool.Pool to collect metrics
type TracedPool struct {
	*pgxpool.Pool
	serviceName string
}

// NewTracedPool creates a new traced database pool
func NewTracedPool(pool *pgxpool.Pool, serviceName string) *TracedPool {
	return &TracedPool{
		Pool:        pool,
		serviceName: serviceName,
	}
}

// Query executes a query with metrics collection
func (t *TracedPool) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	start := time.Now()
	rows, err := t.Pool.Query(ctx, sql, args...)
	duration := time.Since(start)

	table := extractTableName(sql)
	op := "select"
	RecordDBQuery(t.serviceName, op, table, duration)

	return rows, err
}

// QueryRow executes a query row with metrics collection
func (t *TracedPool) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	start := time.Now()
	row := t.Pool.QueryRow(ctx, sql, args...)
	duration := time.Since(start)

	table := extractTableName(sql)
	RecordDBQuery(t.serviceName, "select", table, duration)

	return row
}

// Exec executes a statement with metrics collection
func (t *TracedPool) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	start := time.Now()
	tag, err := t.Pool.Exec(ctx, sql, args...)
	duration := time.Since(start)

	table := extractTableName(sql)
	op := getOperationType(sql)
	RecordDBQuery(t.serviceName, op, table, duration)

	return tag, err
}

// CollectPoolStats collects database connection pool statistics
func (t *TracedPool) CollectPoolStats() {
	stat := t.Pool.Stat()
	SetDBConnections(t.serviceName, "total", float64(stat.TotalConns()))
	SetDBConnections(t.serviceName, "idle", float64(stat.IdleConns()))
	SetDBConnections(t.serviceName, "acquire_count", float64(stat.AcquireCount()))
	SetDBConnections(t.serviceName, "max", float64(stat.MaxConns()))
}

// StartPoolStatsCollector starts a background goroutine to collect pool stats
func (t *TracedPool) StartPoolStatsCollector(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				t.CollectPoolStats()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// extractTableName attempts to extract table name from SQL query
func extractTableName(sql string) string {
	// Simple extraction - in production, use a SQL parser
	// This is a basic implementation
	return "unknown"
}

// getOperationType determines the operation type from SQL
func getOperationType(sql string) string {
	sqlLower := strings.ToLower(sql)
	switch {
	case strings.HasPrefix(sqlLower, "insert"):
		return "insert"
	case strings.HasPrefix(sqlLower, "update"):
		return "update"
	case strings.HasPrefix(sqlLower, "delete"):
		return "delete"
	case strings.HasPrefix(sqlLower, "create"):
		return "create"
	case strings.HasPrefix(sqlLower, "alter"):
		return "alter"
	case strings.HasPrefix(sqlLower, "drop"):
		return "drop"
	default:
		return "select"
	}
}
