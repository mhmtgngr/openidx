package resilience

import "sync"

// Registry tracks all circuit breakers in a service for readiness reporting
type Registry struct {
	mu       sync.RWMutex
	breakers map[string]*CircuitBreaker
}

// NewRegistry creates a new circuit breaker registry
func NewRegistry() *Registry {
	return &Registry{
		breakers: make(map[string]*CircuitBreaker),
	}
}

// Register adds a circuit breaker to the registry
func (r *Registry) Register(cb *CircuitBreaker) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.breakers[cb.name] = cb
}

// Get returns a circuit breaker by name
func (r *Registry) Get(name string) *CircuitBreaker {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.breakers[name]
}

// AllStats returns stats for all registered circuit breakers
func (r *Registry) AllStats() []CircuitBreakerStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	stats := make([]CircuitBreakerStats, 0, len(r.breakers))
	for _, cb := range r.breakers {
		stats = append(stats, cb.Stats())
	}
	return stats
}

// IsHealthy returns true if no circuit breakers are in the open state
func (r *Registry) IsHealthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, cb := range r.breakers {
		if cb.State() == StateOpen {
			return false
		}
	}
	return true
}
