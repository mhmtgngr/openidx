package database

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Runtime fallback from the read replica to the primary (global-scale plan
// task 2.3).
//
// WHAT WAS CLAIMED, AND WHAT WAS TRUE. Three places in this repo said a replica
// outage "transparently falls back to the primary via PostgresDB.Reader()" --
// the Reader() doc, the health checker, and values-prod.yaml. It was true at
// STARTUP only: NewPostgres opens the replica pool, and a failure there leaves
// readPool nil so Reader() returns the primary forever after. Once the pool is
// open, Reader() hands it back unconditionally. A replica that dies at 03:00 --
// a failover, a reboot, a network partition, an RDS maintenance window -- meant
// every read that had been offloaded to it failed, and kept failing until
// someone restarted the process. The replica checker is non-critical by design,
// so readiness stayed green while the ADMIN plane was down.
//
// That is the acceptance criterion of task 2.3 ("on replica loss ADMIN falls
// back to the primary, ISSUE is unaffected"), so it had to become true before
// the replica could be turned on by default rather than after.
//
// HOW. The replica pool carries a reference to the primary and a breaker:
//
//   - An INFRASTRUCTURE error (dial refused, broken pipe, pool exhausted) means
//     the replica is not answering. The call is retried on the primary and the
//     failure is counted. Retrying is safe because Reader() is read-only by
//     contract.
//   - A PgError is the SERVER answering. The query is wrong, or it is a write
//     on a read-only replica (25006); it would fail identically on the primary,
//     so it is returned as-is. That is what keeps "NEVER use Reader() for
//     writes" enforceable instead of silently routing writes to the primary.
//   - After replicaBreakerThreshold consecutive infrastructure failures the
//     breaker opens for replicaBreakerCooldown and calls go straight to the
//     primary, so an outage costs one failed dial per cooldown rather than one
//     per request. It closes on the first success after the cooldown.

const (
	// Three, not one: a single dial can fail for reasons that are gone by the
	// next request, and opening the breaker gives up the offload for a cooldown.
	replicaBreakerThreshold = 3
	// Long enough that an outage is not re-probed on every request, short
	// enough that the offload comes back on its own after a failover.
	replicaBreakerCooldown = 30 * time.Second
)

var (
	replicaFallbackTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "db_replica_fallback_total",
			Help:      "Reads served by the PRIMARY because the read replica did not answer, by reason (retry = the replica failed this call, breaker = the breaker was already open).",
		},
		[]string{"reason"},
	)
	replicaBreakerOpen = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "openidx",
			Name:      "db_replica_breaker_open",
			Help:      "1 while reads are being routed to the primary because the read replica is failing; 0 while the replica is serving. Read offload is lost at 1, but nothing is failing.",
		},
	)
)

// replicaBreaker counts consecutive infrastructure failures and, past the
// threshold, routes reads to the primary for a cooldown.
type replicaBreaker struct {
	consecutive atomic.Int64
	openUntilNS atomic.Int64
}

// isOpen reports whether reads should go straight to the primary. The cooldown
// expiring does not close the breaker: it lets ONE call through to find out,
// and a success closes it.
func (b *replicaBreaker) isOpen(now time.Time) bool {
	until := b.openUntilNS.Load()
	if until == 0 {
		return false
	}
	if now.UnixNano() < until {
		return true
	}
	// Cooldown spent. Let the next call probe the replica.
	if b.openUntilNS.CompareAndSwap(until, 0) {
		b.consecutive.Store(replicaBreakerThreshold - 1)
		replicaBreakerOpen.Set(0)
	}
	return false
}

func (b *replicaBreaker) recordFailure(now time.Time) {
	if b.consecutive.Add(1) >= replicaBreakerThreshold {
		b.openUntilNS.Store(now.Add(replicaBreakerCooldown).UnixNano())
		replicaBreakerOpen.Set(1)
	}
}

func (b *replicaBreaker) recordSuccess() {
	if b.consecutive.Swap(0) != 0 {
		b.openUntilNS.Store(0)
		replicaBreakerOpen.Set(0)
	}
}

// isReplicaInfraError reports whether err means "the replica did not answer",
// as opposed to "the replica answered, and the answer was an error".
//
// The distinction is the whole safety of retrying on the primary. A PgError
// travelled back over a working connection: the statement is at fault and the
// primary would reject it the same way -- including 25006
// (read_only_sql_transaction), which is a write that reached Reader() and must
// stay an error rather than be quietly re-aimed at the primary. A context error
// means the CALLER gave up; retrying would only fail again on an expired
// deadline.
func isReplicaInfraError(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return false
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return true
}

// fallbackTarget returns the primary pool to use instead of this one, or nil
// when this pool is not a replica (so every method below is a no-op cost on
// the primary path, which is every deployment without a replica).
func (p *ScopedPool) fallbackTarget() *ScopedPool {
	if p == nil {
		return nil
	}
	return p.fallback
}

// breakerIsOpen reports that reads should bypass this replica entirely.
func (p *ScopedPool) breakerIsOpen() bool {
	if p == nil || p.fallback == nil {
		return false
	}
	if p.breaker.isOpen(time.Now()) {
		replicaFallbackTotal.WithLabelValues("breaker").Inc()
		return true
	}
	return false
}

// noteReplicaResult records the outcome of a call on the replica and reports
// whether the caller should retry on the primary.
func (p *ScopedPool) noteReplicaResult(err error) (retryOnPrimary bool) {
	if p == nil || p.fallback == nil {
		return false
	}
	if !isReplicaInfraError(err) {
		p.breaker.recordSuccess()
		return false
	}
	p.breaker.recordFailure(time.Now())
	replicaFallbackTotal.WithLabelValues("retry").Inc()
	return true
}

// fallbackRow defers the replica decision to Scan time.
//
// QueryRow returns no error, so at call time there is nothing to classify --
// whether the replica answered is only known once the caller scans. On an
// infrastructure error the whole query is re-run against the primary and that
// result is scanned instead, so the caller sees one Scan and one answer.
//
// Re-running is safe for the same reason retrying Query is: Reader() is
// read-only by contract, and a write that reached it comes back as a PgError
// (25006), which isReplicaInfraError deliberately does not treat as the
// replica being down.
type fallbackRow struct {
	pool *ScopedPool
	ctx  context.Context
	sql  string
	args []any
	row  pgx.Row
}

func (r *fallbackRow) Scan(dest ...any) error {
	err := r.row.Scan(dest...)
	if !r.pool.noteReplicaResult(err) {
		return err
	}
	return r.pool.fallbackTarget().QueryRow(r.ctx, r.sql, r.args...).Scan(dest...)
}
