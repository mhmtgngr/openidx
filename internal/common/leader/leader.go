// Package leader provides a lightweight, Redis-backed guard so that periodic
// background jobs execute on exactly one instance per interval, even when a
// service runs with multiple replicas.
//
// Why: OpenIDX services run several ticker-driven sweeps (session expiry,
// continuous verification, certification campaigns, directory sync, webhook
// retries, JIT/access-request expiry). At 2–3 replicas, an unguarded ticker
// fires on every replica, so each sweep runs N times — duplicate webhook
// deliveries, repeated revocations, N concurrent directory syncs. This package
// gates each tick behind a distributed lock so the work runs once cluster-wide.
//
// Mechanism: a time-bucketed SET NX. Each tick computes a bucket = unix /
// interval and tries to SET a key "leader:<name>:<bucket>" with NX and a TTL of
// 2×interval. Only the first instance into a bucket wins and runs the job; the
// key auto-expires, so there is nothing to release or renew. NTP-level clock
// skew between replicas (sub-second) is immaterial at these intervals.
//
// Degradation:
//   - nil Redis client  → run unconditionally (single-instance / dev: there is
//     no second replica to collide with).
//   - Redis error       → skip this tick (fail to "do not run"): a brief Redis
//     outage must not reintroduce the N× duplication this guard exists to stop.
package leader

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const keyPrefix = "openidx:leader:"

// IsLeaderForTick reports whether this instance should run the job named `name`
// for the current interval bucket. It is the building block behind RunPeriodic;
// call it directly only when you already own the ticker loop.
func IsLeaderForTick(ctx context.Context, rdb *redis.Client, name string, interval time.Duration) bool {
	if rdb == nil {
		// Single-instance / dev: no peer to coordinate with, always run.
		return true
	}
	if interval <= 0 {
		interval = time.Minute
	}
	bucket := time.Now().UnixMilli() / interval.Milliseconds()
	key := keyPrefix + name + ":" + itoa(bucket)
	ok, err := rdb.SetNX(ctx, key, "1", 2*interval).Result()
	if err != nil {
		// Fail closed: do not run on Redis error so replicas can't all run.
		return false
	}
	return ok
}

// RunPeriodic starts a goroutine that runs fn every interval, but only on the
// instance that wins the lock for each interval bucket (see package docs). It
// returns immediately; the goroutine exits when ctx is cancelled. Like a bare
// time.Ticker, the first run happens after one interval (no immediate run).
func RunPeriodic(ctx context.Context, rdb *redis.Client, logger *zap.Logger, name string, interval time.Duration, fn func(context.Context)) {
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !IsLeaderForTick(ctx, rdb, name, interval) {
					if logger != nil {
						logger.Debug("skipping periodic job: not leader for this tick",
							zap.String("job", name))
					}
					continue
				}
				fn(ctx)
			}
		}
	}()
}

// itoa renders a non-negative int64 without importing strconv into hot paths.
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
