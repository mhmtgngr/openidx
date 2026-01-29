// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

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

	// Auth-specific metrics
	AuthAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "auth_attempts_total",
			Help:      "Total number of authentication attempts",
		},
		[]string{"method", "outcome"},
	)

	ActiveSessionsGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "openidx",
			Name:      "active_sessions",
			Help:      "Number of active user sessions",
		},
		[]string{"service"},
	)

	TokenOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "token_operations_total",
			Help:      "Total number of token operations",
		},
		[]string{"operation", "outcome"},
	)
)

// PrometheusMetrics returns a Gin middleware that records HTTP metrics.
// serviceName is used as the "service" label on all metrics.
func PrometheusMetrics(serviceName string) gin.HandlerFunc {
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

// MetricsHandler returns an http.Handler that serves Prometheus metrics.
// Register this on the "/metrics" route.
func MetricsHandler() gin.HandlerFunc {
	h := promhttp.Handler()
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}
