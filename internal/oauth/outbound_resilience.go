// Package oauth — outbound resilience helpers.
//
// The OAuth service makes outbound HTTP calls to third parties from a handful
// of well-defined places: SAML metadata fetches, social-login token
// exchanges, social-login userinfo fetches, the GitHub primary-email
// follow-up. Every call site used to construct a one-shot `&http.Client{}`
// with a per-call timeout — fine for the happy path, but when a third party
// goes degraded those call sites still queued up the full timeout per
// request and let a slow upstream burn requests on our side until the
// timeout fired.
//
// Wraps each target behind a named circuit breaker so a failing upstream
// trips and fails fast for a short cool-down window. The CB state is also
// exported via the existing Prometheus metrics in
// `internal/common/resilience` so on-call can see "google oauth is open"
// at a glance.
package oauth

import (
	"net/http"
	"sync"
	"time"

	"github.com/openidx/openidx/internal/common/resilience"
	"go.uber.org/zap"
)

var (
	outboundOnce     sync.Once
	outboundRegistry *resilience.Registry
)

// outboundHTTPClient returns a per-target resilient HTTP client. Targets are
// strings like "saml-metadata", "social-google-token", "social-github-email"
// — anything unique enough that on-call can pick out which third party is
// degraded from the Prometheus circuit-breaker metric.
//
// The CB defaults — 5 failures opens the circuit, 30s cool-down, half-open
// probes with a single request — are deliberately conservative; outbound
// calls in this package are rare enough that 5 in a row failing is a real
// signal, not flakiness.
func (s *Service) outboundHTTPClient(target string, timeout time.Duration) *resilience.ResilientHTTPClient {
	outboundOnce.Do(func() {
		outboundRegistry = resilience.NewRegistry()
	})
	cb := outboundRegistry.Get(target)
	if cb == nil {
		cb = resilience.NewCircuitBreaker(resilience.CircuitBreakerConfig{
			Name:         target,
			Threshold:    5,
			ResetTimeout: 30 * time.Second,
			Logger:       s.logger.With(zap.String("component", "oauth-outbound")),
		})
		outboundRegistry.Register(cb)
	}
	raw := &http.Client{Timeout: timeout}
	return resilience.NewResilientHTTPClient(raw, cb)
}
