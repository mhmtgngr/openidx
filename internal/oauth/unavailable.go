package oauth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/openidx/openidx/internal/common/cache"
)

// retryAfterSeconds is the backoff hint returned to clients when the issue path
// (login / token / MFA) can't reach a stateful dependency. Short so a real
// client retries promptly once the brief brownout (e.g. a DB failover) clears,
// but long enough to blunt a thundering herd.
const retryAfterSeconds = "5"

// isDependencyUnavailable reports whether err represents a *transient
// infrastructure outage* (Postgres/Redis unreachable, pool exhausted/closed,
// connection reset, context deadline while dialing) as opposed to a genuine
// application error (bad credentials, invalid grant, constraint violation).
//
// This is the classifier that lets the issue path answer "is this a retryable
// brownout, or a real client error?" — the former becomes a 503 +
// temporarily_unavailable + Retry-After (client backs off and the login
// succeeds moments later), the latter stays a 4xx/500. Being conservative here
// is safe: a false negative just preserves today's 500 behavior.
func isDependencyUnavailable(err error) bool {
	if err == nil {
		return false
	}

	// Redis cache layer signals unavailability explicitly.
	if errors.Is(err, cache.ErrRedisUnavailable) {
		return true
	}

	// Context deadline/cancel while talking to a dependency — e.g. a dial that
	// hit DB_CONNECT_TIMEOUT during a failover, or a statement_timeout abort.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}

	// Network-level failures reaching the dependency.
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}

	// pgconn: a connect failure carries the underlying dial errors; a server that
	// is shutting down / not accepting connections uses these SQLSTATE classes.
	var connErr *pgconn.ConnectError
	if errors.As(err, &connErr) {
		return true
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		// Class 57 — operator intervention (57P01 admin shutdown, 57P03 cannot
		// connect now): exactly what a failover/restart looks like.
		case strings.HasPrefix(pgErr.Code, "57"):
			return true
		// Class 08 — connection exception.
		case strings.HasPrefix(pgErr.Code, "08"):
			return true
		// 53300 too_many_connections / 53400 config limit exceeded — the pool
		// or server is saturated; a retry after backoff is the right call.
		case pgErr.Code == "53300" || pgErr.Code == "53400":
			return true
		// 25006 read_only_sql_transaction — writing to a replica/standby that
		// hasn't finished promotion during a failover.
		case pgErr.Code == "25006":
			return true
		}
	}

	// Last-resort string sniff for wrapped dial errors that don't unwrap cleanly.
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "closed pool") ||
		strings.Contains(msg, "server closed the connection")
}

// writeServerOrUnavailable writes the correct OAuth error for a server-side
// failure: a retryable 503 temporarily_unavailable (+ Retry-After) when err is a
// transient dependency outage, otherwise the existing 500 server_error. Use this
// at issue-path call sites that today do `c.JSON(500, {"error":"server_error"})`
// after a DB/Redis operation, so a database brownout degrades gracefully (clients
// back off and retry) instead of surfacing as a hard 500 they hammer.
//
// Returns true if it wrote a 503 (dependency unavailable), false if it wrote the
// 500 — handy for metrics/logging at the call site.
func writeServerOrUnavailable(c *gin.Context, err error) bool {
	if isDependencyUnavailable(err) {
		c.Header("Retry-After", retryAfterSeconds)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             ErrorTemporarilyUnavailable,
			"error_description": "a backend dependency is temporarily unavailable; retry shortly",
		})
		return true
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": ErrorServerError})
	return false
}
