// Package resilience provides circuit breaker and resilience patterns for OpenIDX services.
package resilience

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
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

	cbFallbackTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "circuit_breaker_fallback_total",
			Help:      "Total number of fallback function invocations",
		},
		[]string{"name"},
	)

	cbHalfOpenAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "circuit_breaker_half_open_attempts_total",
			Help:      "Total attempts in half-open state",
		},
		[]string{"name"},
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

// distributedState holds the circuit breaker state for Redis storage
type distributedState struct {
	State       CircuitState `json:"state"`
	Failures    int          `json:"failures"`
	LastFailure int64        `json:"last_failure"`
}

// CircuitBreakerConfig configures a CircuitBreaker
type CircuitBreakerConfig struct {
	Name             string
	Threshold        int           // failures before opening
	ResetTimeout     time.Duration // how long to wait before half-open
	HalfOpenAttempts int           // max attempts in half-open before reopening (0 = unlimited)
	Logger           *zap.Logger
	RedisClient      *redis.Client // optional: for distributed state
}

// CircuitBreakerStats holds stats for readiness reporting
type CircuitBreakerStats struct {
	Name            string       `json:"name"`
	State           CircuitState `json:"state"`
	Failures        int          `json:"failures"`
	Threshold       int          `json:"threshold"`
	LastFailure     *time.Time   `json:"last_failure,omitempty"`
	HalfOpenAttempt int          `json:"half_open_attempt,omitempty"`
}

// FallbackFunc is a function that can be called when the circuit is open or execution fails
type FallbackFunc func(error) (interface{}, error)

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	mu               sync.Mutex
	name             string
	failures         int
	threshold        int
	resetTimeout     time.Duration
	halfOpenAttempts int           // max attempts in half-open
	halfOpenCount    int           // current attempts in half-open
	lastFailure      time.Time
	state            CircuitState
	logger           *zap.Logger
	redis            *redis.Client // optional: for distributed state
	fallback         FallbackFunc  // optional fallback function
}

// NewCircuitBreaker creates a new CircuitBreaker with the given configuration
func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	cb := &CircuitBreaker{
		name:             cfg.Name,
		threshold:        cfg.Threshold,
		resetTimeout:     cfg.ResetTimeout,
		halfOpenAttempts: cfg.HalfOpenAttempts,
		state:            StateClosed,
		logger:           cfg.Logger,
		redis:            cfg.RedisClient,
	}
	if cb.logger == nil {
		cb.logger = zap.NewNop()
	}
	if cb.halfOpenAttempts == 0 {
		cb.halfOpenAttempts = 1 // default: single attempt in half-open
	}
	cbStateGauge.WithLabelValues(cfg.Name).Set(0)

	// Try to load state from Redis if available
	if cb.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		cb.loadDistributedState(ctx)
	}

	return cb
}

// New creates a new CircuitBreaker with a simpler API
// Matches the requested API signature
func New(name string, threshold int, timeout time.Duration) *CircuitBreaker {
	return NewCircuitBreaker(CircuitBreakerConfig{
		Name:         name,
		Threshold:    threshold,
		ResetTimeout: timeout,
		Logger:       zap.NewNop(),
	})
}

// Execute runs fn through the circuit breaker. If the circuit is open and the reset
// timeout has not elapsed, it returns an error immediately.
// Returns the result from fn or an error.
func (cb *CircuitBreaker) Execute(fn func() (interface{}, error)) (interface{}, error) {
	cb.mu.Lock()

	switch cb.state {
	case StateOpen:
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			// Check if we've exceeded half-open attempts before transitioning
			if cb.halfOpenAttempts > 0 && cb.halfOpenCount >= cb.halfOpenAttempts {
				cb.mu.Unlock()
				cbRequestsTotal.WithLabelValues(cb.name, "rejected").Inc()
				if cb.fallback != nil {
					cbFallbackTotal.WithLabelValues(cb.name).Inc()
					return cb.fallback(fmt.Errorf("circuit breaker %s exceeded half-open retry limit", cb.name))
				}
				return nil, fmt.Errorf("circuit breaker %s exceeded half-open retry limit", cb.name)
			}
			cb.transition(StateHalfOpen)
			cb.halfOpenCount++
			cbHalfOpenAttemptsTotal.WithLabelValues(cb.name).Inc()
		} else {
			cb.mu.Unlock()
			cbRequestsTotal.WithLabelValues(cb.name, "rejected").Inc()
			if cb.fallback != nil {
				cbFallbackTotal.WithLabelValues(cb.name).Inc()
				return cb.fallback(fmt.Errorf("circuit breaker %s is open", cb.name))
			}
			return nil, fmt.Errorf("circuit breaker %s is open; requests blocked until %s",
				cb.name, cb.lastFailure.Add(cb.resetTimeout).Format(time.RFC3339))
		}
	case StateHalfOpen:
		// Check if we've exceeded half-open attempts
		if cb.halfOpenAttempts > 0 && cb.halfOpenCount >= cb.halfOpenAttempts {
			cb.mu.Unlock()
			cbRequestsTotal.WithLabelValues(cb.name, "rejected").Inc()
			if cb.fallback != nil {
				cbFallbackTotal.WithLabelValues(cb.name).Inc()
				return cb.fallback(fmt.Errorf("circuit breaker %s exceeded half-open retry limit", cb.name))
			}
			return nil, fmt.Errorf("circuit breaker %s exceeded half-open retry limit", cb.name)
		}
		cb.halfOpenCount++
		cbHalfOpenAttemptsTotal.WithLabelValues(cb.name).Inc()
	case StateClosed:
		// Normal operation
	}

	cb.mu.Unlock()

	result, err := fn()

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
		cb.saveDistributedState(context.Background())

		if cb.fallback != nil {
			cbFallbackTotal.WithLabelValues(cb.name).Inc()
			return cb.fallback(err)
		}
		return nil, err
	}

	if cb.state == StateHalfOpen {
		cb.logger.Info("Circuit breaker recovered, transitioning to closed",
			zap.String("name", cb.name))
	}
	cb.failures = 0
	cb.halfOpenCount = 0
	cb.transition(StateClosed)
	cbRequestsTotal.WithLabelValues(cb.name, "success").Inc()
	cb.saveDistributedState(context.Background())
	return result, nil
}

// ExecuteError runs fn through the circuit breaker for functions that only return error.
// This is a convenience method for backward compatibility.
func (cb *CircuitBreaker) ExecuteError(fn func() error) error {
	_, err := cb.Execute(func() (interface{}, error) {
		return nil, fn()
	})
	return err
}

// WithFallback sets a fallback function that will be called when the circuit is open
// or when execution fails. Returns the circuit breaker for chaining.
func (cb *CircuitBreaker) WithFallback(fn FallbackFunc) *CircuitBreaker {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.fallback = fn
	return cb
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
	cb.halfOpenCount = 0
	cb.transition(StateClosed)
	cb.lastFailure = time.Time{}
	cb.logger.Info("Circuit breaker reset to closed state", zap.String("name", cb.name))
	cb.saveDistributedState(context.Background())
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
	if cb.state == StateHalfOpen {
		stats.HalfOpenAttempt = cb.halfOpenCount
	}
	return stats
}

// saveDistributedState saves the current state to Redis for distributed coordination
func (cb *CircuitBreaker) saveDistributedState(ctx context.Context) {
	if cb.redis == nil {
		return
	}

	key := fmt.Sprintf("circuit_breaker:%s", cb.name)
	state := distributedState{
		State:       cb.state,
		Failures:    cb.failures,
		LastFailure: cb.lastFailure.Unix(),
	}

	data, err := json.Marshal(state)
	if err != nil {
		cb.logger.Error("Failed to marshal circuit breaker state",
			zap.String("name", cb.name),
			zap.Error(err))
		return
	}

	// Set with expiration longer than reset timeout to ensure persistence
	ttl := cb.resetTimeout * 2
	if err := cb.redis.Set(ctx, key, data, ttl).Err(); err != nil {
		cb.logger.Debug("Failed to save circuit breaker state to Redis",
			zap.String("name", cb.name),
			zap.Error(err))
	}
}

// loadDistributedState loads the current state from Redis
func (cb *CircuitBreaker) loadDistributedState(ctx context.Context) {
	if cb.redis == nil {
		return
	}

	key := fmt.Sprintf("circuit_breaker:%s", cb.name)
	data, err := cb.redis.Get(ctx, key).Bytes()
	if err != nil {
		if err != redis.Nil {
			cb.logger.Debug("Failed to load circuit breaker state from Redis",
				zap.String("name", cb.name),
				zap.Error(err))
		}
		return
	}

	var state distributedState
	if err := json.Unmarshal(data, &state); err != nil {
		cb.logger.Error("Failed to unmarshal circuit breaker state",
			zap.String("name", cb.name),
			zap.Error(err))
		return
	}

	// Only restore if the state is still valid
	cb.state = state.State
	cb.failures = state.Failures
	cb.lastFailure = time.Unix(state.LastFailure, 0)

	// Update metrics
	cbStateGauge.WithLabelValues(cb.name).Set(stateToFloat(cb.state))

	cb.logger.Info("Loaded circuit breaker state from Redis",
		zap.String("name", cb.name),
		zap.String("state", string(cb.state)),
		zap.Int("failures", cb.failures))
}
