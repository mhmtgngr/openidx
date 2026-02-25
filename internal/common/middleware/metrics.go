// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/metrics"
)

// PrometheusMetrics returns a Gin middleware that records HTTP metrics.
// It delegates to the centralized metrics package to avoid duplicate
// metric registration.
func PrometheusMetrics(serviceName string) gin.HandlerFunc {
	return metrics.Middleware(serviceName)
}

// MetricsHandler returns a gin.HandlerFunc that serves Prometheus metrics.
// It delegates to the centralized metrics package.
func MetricsHandler() gin.HandlerFunc {
	return metrics.Handler()
}

// Auth-specific metric variables for backward compatibility.
// These are now exported from the metrics package.
var (
	// AuthAttemptsTotal records authentication attempts.
	// Deprecated: Use metrics.RecordAuthAttempt instead.
	AuthAttemptsTotal = metrics.AuthAttemptsTotal

	// ActiveSessionsGauge tracks active user sessions.
	// Deprecated: Use metrics.IncActiveSessions/metrics.DecActiveSessions instead.
	ActiveSessionsGauge = metrics.ActiveSessionsGauge

	// TokenOperationsTotal records token operations.
	// Deprecated: Use metrics.RecordTokenOperation instead.
	TokenOperationsTotal = metrics.TokenOperationsTotal
)
