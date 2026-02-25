// Package metrics provides Prometheus metrics collection for OpenIDX services
package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// HTTP metrics
var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"service", "method", "path", "status"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "openidx",
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request latency in seconds",
			Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"service", "method", "path"},
	)

	httpRequestsInFlight = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "openidx",
			Name:      "http_requests_in_flight",
			Help:      "Number of HTTP requests currently being processed",
		},
		[]string{"service"},
	)

	httpResponseSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "openidx",
			Name:      "http_response_size_bytes",
			Help:      "HTTP response size in bytes",
			Buckets:   prometheus.ExponentialBuckets(100, 10, 7), // 100B to 100MB
		},
		[]string{"service", "method", "path"},
	)
)

// Authentication and security metrics
var (
	// AuthAttemptsTotal is exported for use by middleware package
	AuthAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "auth_attempts_total",
			Help:      "Total number of authentication attempts",
		},
		[]string{"method", "outcome"}, // method: password, mfa, sso, oauth; outcome: success, failure, rate_limited
	)

	// ActiveSessionsGauge tracks active user sessions.
	ActiveSessionsGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "openidx",
			Name:      "active_sessions",
			Help:      "Number of active user sessions",
		},
		[]string{"service"},
	)

	// TokenOperationsTotal records token operations.
	TokenOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "token_operations_total",
			Help:      "Total number of token operations",
		},
		[]string{"operation", "outcome"}, // operation: issue, refresh, revoke, validate; outcome: success, failure
	)
)

// Risk and MFA metrics
var (
	riskScoreHistogram = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "openidx",
			Name:      "risk_score",
			Help:      "Risk score distribution for authentication events",
			Buckets:   []float64{0, 10, 25, 50, 75, 90, 100}, // 0-100 scale
		},
		[]string{"service", "decision"}, // decision: allow, challenge, deny
	)

	mfaVerificationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "mfa_verifications_total",
			Help:      "Total number of MFA verification attempts",
		},
		[]string{"method", "outcome"}, // method: totp, sms, email, push, webauthn; outcome: success, failure
	)

	mfaChallengeDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "openidx",
			Name:      "mfa_challenge_duration_seconds",
			Help:      "Time taken to complete MFA challenge",
			Buckets:   []float64{1, 5, 10, 30, 60, 120, 300}, // 1s to 5 minutes
		},
		[]string{"method"},
	)
)

// Database and cache metrics
var (
	dbQueryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "openidx",
			Name:      "db_query_duration_seconds",
			Help:      "Database query duration in seconds",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
		},
		[]string{"service", "operation", "table"}, // operation: select, insert, update, delete
	)

	dbConnectionsGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "openidx",
			Name:      "db_connections",
			Help:      "Number of database connections",
		},
		[]string{"service", "state"}, // state: idle, in_use, wait
	)

	cacheOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "cache_operations_total",
			Help:      "Total number of cache operations",
		},
		[]string{"service", "operation", "outcome"}, // operation: get, set, delete; outcome: hit, miss, error
	)
)

// Middleware returns a Gin middleware that records HTTP metrics.
// serviceName is used as the "service" label on all metrics.
func Middleware(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.FullPath()
		if path == "" {
			path = "unknown"
		}

		// Skip metrics endpoint itself to avoid recursion
		if path == "/metrics" {
			c.Next()
			return
		}

		httpRequestsInFlight.WithLabelValues(serviceName).Inc()
		start := time.Now()

		c.Next()

		duration := time.Since(start).Seconds()
		status := strconv.Itoa(c.Writer.Status())
		method := c.Request.Method
		size := float64(c.Writer.Size())

		httpRequestsTotal.WithLabelValues(serviceName, method, path, status).Inc()
		httpRequestDuration.WithLabelValues(serviceName, method, path).Observe(duration)
		httpResponseSize.WithLabelValues(serviceName, method, path).Observe(size)
		httpRequestsInFlight.WithLabelValues(serviceName).Dec()
	}
}

// Handler returns a gin.HandlerFunc that serves Prometheus metrics.
// Register this on the "/metrics" route.
func Handler() gin.HandlerFunc {
	h := promhttp.Handler()
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

// RecordAuthAttempt records an authentication attempt
func RecordAuthAttempt(method, outcome string) {
	AuthAttemptsTotal.WithLabelValues(method, outcome).Inc()
}

// RecordMFAVerification records an MFA verification attempt
func RecordMFAVerification(method, outcome string) {
	mfaVerificationsTotal.WithLabelValues(method, outcome).Inc()
}

// RecordMFADuration records the time taken to complete an MFA challenge
func RecordMFADuration(method string, duration time.Duration) {
	mfaChallengeDuration.WithLabelValues(method).Observe(duration.Seconds())
}

// RecordRiskScore records a risk score with the resulting decision
func RecordRiskScore(service, decision string, score float64) {
	riskScoreHistogram.WithLabelValues(service, decision).Observe(score)
}

// RecordTokenOperation records a token operation
func RecordTokenOperation(operation, outcome string) {
	TokenOperationsTotal.WithLabelValues(operation, outcome).Inc()
}

// RecordDBQuery records a database query duration
func RecordDBQuery(service, operation, table string, duration time.Duration) {
	dbQueryDuration.WithLabelValues(service, operation, table).Observe(duration.Seconds())
}

// SetDBConnections sets the current number of database connections
func SetDBConnections(service, state string, count float64) {
	dbConnectionsGauge.WithLabelValues(service, state).Set(count)
}

// RecordCacheOperation records a cache operation
func RecordCacheOperation(service, operation, outcome string) {
	cacheOperationsTotal.WithLabelValues(service, operation, outcome).Inc()
}

// IncActiveSessions increments the active sessions counter
func IncActiveSessions(service string) {
	ActiveSessionsGauge.WithLabelValues(service).Inc()
}

// DecActiveSessions decrements the active sessions counter
func DecActiveSessions(service string) {
	ActiveSessionsGauge.WithLabelValues(service).Dec()
}

// SetActiveSessions sets the absolute number of active sessions
func SetActiveSessions(service string, count float64) {
	ActiveSessionsGauge.WithLabelValues(service).Set(count)
}
