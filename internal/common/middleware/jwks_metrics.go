package middleware

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// JWKS cache observability. The verify path (validating an already-issued JWT)
// is the highest-availability workload in OpenIDX: it must survive an outage of
// the OAuth/JWKS endpoint (and therefore of the shared database behind it). When
// a JWKS refresh fails but we still hold a previously-fetched, trusted key set,
// we SERVE STALE rather than reject valid tokens — turning a database blip into
// an invisible brownout instead of an auth outage.
//
// Alert on these:
//   - openidx_jwks_refresh_failures_total rising  → the issuer/JWKS is unreachable
//   - openidx_jwks_serve_stale_total rising       → we are riding the cache; verify
//     is still up, but fix the issuer
//   - openidx_jwks_stale_seconds high             → how far past TTL the served key
//     set is; approaching JWKS_MAX_STALE
//     means verify is about to fail
var (
	jwksRefreshSuccessTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "jwks_refresh_success_total",
			Help:      "Total successful JWKS refreshes from the OAuth signing endpoint.",
		},
	)

	jwksRefreshFailuresTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "jwks_refresh_failures_total",
			Help:      "Total failed JWKS refreshes (issuer/JWKS endpoint unreachable or invalid).",
		},
	)

	jwksServeStaleTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "jwks_serve_stale_total",
			Help:      "Total token verifications served from a stale (past-TTL) JWKS cache because a refresh failed. Availability belt: a nonzero rate means verify is surviving a JWKS/DB outage.",
		},
	)

	jwksStaleSeconds = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "openidx",
			Name:      "jwks_stale_seconds",
			Help:      "Seconds since the last successful JWKS refresh, measured when serving a stale key. 0 while the cache is fresh.",
		},
	)
)
