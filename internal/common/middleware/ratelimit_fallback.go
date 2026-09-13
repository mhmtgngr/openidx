package middleware

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Local fallback for the auth-path limiter (global-scale plan task 0.7).
//
// The auth tier fails CLOSED when its Redis is unreachable, and that is the
// right default: brute-force protection must not silently vanish with a cache.
// But "unreachable" was binary — the first failed INCR turned every login into
// a 503, so a ten-second Redis restart, a failover, or a rolling upgrade of
// the rate-limit instance became a login outage of exactly that length. The
// defence had a failure mode an attacker did not even have to trigger.
//
// This is the middle: for a bounded window after the FIRST failure, each
// replica enforces the auth tier from a process-local counter with a
// per-replica share of the quota, then fails closed as before. What it buys is
// that a blip costs nothing; what it costs is that during the window the fleet
// admits at most hint× the intended rate (the replicas cannot see each other's
// counters) — which is why the window is short and the share is divided by
// the replica hint rather than assumed to be one.
//
// The counter is bounded. A flood of distinct sources during the window is the
// one way to grow it, and a Redis outage must not also become a memory
// exhaustion: past maxLocalKeys the limiter fails closed for NEW keys rather
// than allocate.

const (
	defaultLocalFallbackMaxKeys = 50_000
)

var (
	rlLocalFallbackTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "rate_limit_local_fallback_total",
			Help:      "Auth-path decisions taken from the process-local fallback counter while the rate-limit Redis was unavailable, by outcome (allowed, limited, expired, overflow).",
		},
		[]string{"outcome"},
	)
	rlLocalFallbackSeconds = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "openidx",
			Name:      "rate_limit_local_fallback_seconds",
			Help:      "Seconds the auth-path limiter has been running on its process-local fallback because the rate-limit Redis is unavailable. 0 while Redis answers. Approaching RATE_LIMIT_LOCAL_FALLBACK_MAX means logins are about to fail closed.",
		},
	)
)

type fallbackOutcome int

const (
	fallbackAllowed fallbackOutcome = iota
	fallbackLimited
	fallbackExpired
	fallbackOverflow
)

func (o fallbackOutcome) String() string {
	switch o {
	case fallbackAllowed:
		return "allowed"
	case fallbackLimited:
		return "limited"
	case fallbackExpired:
		return "expired"
	default:
		return "overflow"
	}
}

type localBucket struct {
	epoch int64
	count int
}

type localFallback struct {
	mu           sync.Mutex
	firstFailure time.Time
	buckets      map[string]*localBucket
	maxKeys      int
	now          func() time.Time
}

func newLocalFallback(maxKeys int) *localFallback {
	if maxKeys <= 0 {
		maxKeys = defaultLocalFallbackMaxKeys
	}
	return &localFallback{buckets: make(map[string]*localBucket), maxKeys: maxKeys, now: time.Now}
}

// recordSuccess is called on every successful Redis round-trip: the outage is
// over, the clock resets, and the local counters are dropped so the next
// outage starts from a clean, bounded state.
func (f *localFallback) recordSuccess() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.firstFailure.IsZero() {
		f.firstFailure = time.Time{}
		f.buckets = make(map[string]*localBucket)
	}
	rlLocalFallbackSeconds.Set(0)
}

// decide answers one auth-path request while Redis is unavailable. key already
// carries the window epoch (it is the same key the Redis path would have
// used), quota is this replica's share, maxAge bounds the fallback window.
func (f *localFallback) decide(key string, epoch int64, quota int, maxAge time.Duration) (fallbackOutcome, int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.now()
	if f.firstFailure.IsZero() {
		f.firstFailure = now
	}
	elapsed := now.Sub(f.firstFailure)
	rlLocalFallbackSeconds.Set(elapsed.Seconds())
	if elapsed > maxAge {
		rlLocalFallbackTotal.WithLabelValues(fallbackExpired.String()).Inc()
		return fallbackExpired, 0
	}

	b, ok := f.buckets[key]
	if !ok {
		if len(f.buckets) >= f.maxKeys {
			f.sweepLocked(epoch)
		}
		if len(f.buckets) >= f.maxKeys {
			rlLocalFallbackTotal.WithLabelValues(fallbackOverflow.String()).Inc()
			return fallbackOverflow, 0
		}
		b = &localBucket{epoch: epoch}
		f.buckets[key] = b
	}
	b.count++
	remaining := quota - b.count
	if remaining < 0 {
		rlLocalFallbackTotal.WithLabelValues(fallbackLimited.String()).Inc()
		return fallbackLimited, 0
	}
	rlLocalFallbackTotal.WithLabelValues(fallbackAllowed.String()).Inc()
	return fallbackAllowed, remaining
}

// sweepLocked drops buckets from past windows. Called only when the map is at
// capacity, so the cost is paid by the flood that filled it.
func (f *localFallback) sweepLocked(currentEpoch int64) {
	for k, b := range f.buckets {
		if b.epoch < currentEpoch {
			delete(f.buckets, k)
		}
	}
}

// perReplicaQuota divides the tier's limit by the replica hint so the fleet's
// aggregate admission during fallback stays near the intended rate. Never
// below one: a share of zero would be fail-closed wearing a different name.
func perReplicaQuota(limit, hint int) int {
	if hint < 1 {
		hint = 1
	}
	q := limit / hint
	if q < 1 {
		q = 1
	}
	return q
}
