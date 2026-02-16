// Package resilience provides circuit breaker and resilience patterns for OpenIDX services.
package resilience

import (
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// CircuitState represents the state of a circuit breaker
type CircuitState string

const (
	StateClosed   CircuitState = "closed"
	StateOpen     CircuitState = "open"
	StateHalfOpen CircuitState = "half-open"
)

var (
	cbStateGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "openidx",
			Name:      "circuit_breaker_state",
			Help:      "Current state of circuit breaker (0=closed, 1=half-open, 2=open)",
		},
		[]string{"name"},
	)

	cbTransitionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "circuit_breaker_transitions_total",
			Help:      "Total number of circuit breaker state transitions",
		},
		[]string{"name", "from", "to"},
	)

	cbRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "circuit_breaker_requests_total",
			Help:      "Total requests through circuit breaker",
		},
		[]string{"name", "result"},
	)
)

func stateToFloat(s CircuitState) float64 {
	switch s {
	case StateClosed:
		return 0
	case StateHalfOpen:
		return 1
	case StateOpen:
		return 2
	default:
		return 0
	}
}

// CircuitBreakerConfig configures a CircuitBreaker
type CircuitBreakerConfig struct {
	Name         string
	Threshold    int           // failures before opening
	ResetTimeout time.Duration // how long to wait before half-open
	Logger       *zap.Logger
}

// CircuitBreakerStats holds stats for readiness reporting
type CircuitBreakerStats struct {
	Name        string       `json:"name"`
	State       CircuitState `json:"state"`
	Failures    int          `json:"failures"`
	Threshold   int          `json:"threshold"`
	LastFailure *time.Time   `json:"last_failure,omitempty"`
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	mu           sync.Mutex
	name         string
	failures     int
	threshold    int
	resetTimeout time.Duration
	lastFailure  time.Time
	state        CircuitState
	logger       *zap.Logger
}

// NewCircuitBreaker creates a new CircuitBreaker with the given configuration
func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	cb := &CircuitBreaker{
		name:         cfg.Name,
		threshold:    cfg.Threshold,
		resetTimeout: cfg.ResetTimeout,
		state:        StateClosed,
		logger:       cfg.Logger,
	}
	cbStateGauge.WithLabelValues(cfg.Name).Set(0)
	return cb
}

// Execute runs fn through the circuit breaker. If the circuit is open and the reset
// timeout has not elapsed, it returns an error immediately.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	cb.mu.Lock()

	switch cb.state {
	case StateOpen:
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.transition(StateHalfOpen)
		} else {
			cb.mu.Unlock()
			cbRequestsTotal.WithLabelValues(cb.name, "rejected").Inc()
			return fmt.Errorf("circuit breaker %s is open; requests blocked until %s",
				cb.name, cb.lastFailure.Add(cb.resetTimeout).Format(time.RFC3339))
		}
	case StateHalfOpen:
		// Allow one request through to test recovery
	case StateClosed:
		// Normal operation
	}

	cb.mu.Unlock()

	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failures++
		cb.lastFailure = time.Now()
		cb.logger.Warn("Circuit breaker recorded failure",
			zap.String("name", cb.name),
			zap.Int("failures", cb.failures),
			zap.Int("threshold", cb.threshold),
			zap.String("state", string(cb.state)),
			zap.Error(err))

		if cb.state == StateHalfOpen || cb.failures >= cb.threshold {
			cb.transition(StateOpen)
			cb.logger.Error("Circuit breaker opened",
				zap.String("name", cb.name),
				zap.Int("failures", cb.failures),
				zap.Duration("reset_timeout", cb.resetTimeout))
		}
		cbRequestsTotal.WithLabelValues(cb.name, "failure").Inc()
		return err
	}

	if cb.state == StateHalfOpen {
		cb.logger.Info("Circuit breaker recovered, transitioning to closed",
			zap.String("name", cb.name))
	}
	cb.failures = 0
	cb.transition(StateClosed)
	cbRequestsTotal.WithLabelValues(cb.name, "success").Inc()
	return nil
}

// transition changes state and records metrics (must be called with lock held)
func (cb *CircuitBreaker) transition(to CircuitState) {
	if cb.state == to {
		return
	}
	from := cb.state
	cb.state = to
	cbStateGauge.WithLabelValues(cb.name).Set(stateToFloat(to))
	cbTransitionsTotal.WithLabelValues(cb.name, string(from), string(to)).Inc()
}

// State returns the current state of the circuit breaker
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// Reset resets the circuit breaker to its initial closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.transition(StateClosed)
	cb.lastFailure = time.Time{}
	cb.logger.Info("Circuit breaker reset to closed state", zap.String("name", cb.name))
}

// Stats returns current stats for readiness reporting
func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	stats := CircuitBreakerStats{
		Name:      cb.name,
		State:     cb.state,
		Failures:  cb.failures,
		Threshold: cb.threshold,
	}
	if !cb.lastFailure.IsZero() {
		t := cb.lastFailure
		stats.LastFailure = &t
	}
	return stats
}
