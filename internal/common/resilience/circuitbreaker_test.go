package resilience

import (
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"
)

func newTestCB(threshold int, resetTimeout time.Duration) *CircuitBreaker {
	return NewCircuitBreaker(CircuitBreakerConfig{
		Name:         "test-cb",
		Threshold:    threshold,
		ResetTimeout: resetTimeout,
		Logger:       zap.NewNop(),
	})
}

func TestCircuitBreakerInitialState(t *testing.T) {
	cb := newTestCB(3, time.Second)
	if cb.State() != StateClosed {
		t.Errorf("expected initial state 'closed', got %q", cb.State())
	}
}

func TestCircuitBreakerSuccessKeepsClosed(t *testing.T) {
	cb := newTestCB(3, time.Second)

	err := cb.Execute(func() error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cb.State() != StateClosed {
		t.Errorf("expected state 'closed' after success, got %q", cb.State())
	}
}

func TestCircuitBreakerOpensAfterThreshold(t *testing.T) {
	cb := newTestCB(3, time.Second)
	testErr := errors.New("service down")

	for i := 0; i < 3; i++ {
		cb.Execute(func() error { return testErr })
	}

	if cb.State() != StateOpen {
		t.Errorf("expected state 'open' after %d failures, got %q", 3, cb.State())
	}
}

func TestCircuitBreakerRejectsWhenOpen(t *testing.T) {
	cb := newTestCB(2, 10*time.Second)
	testErr := errors.New("fail")

	// Trip the breaker
	cb.Execute(func() error { return testErr })
	cb.Execute(func() error { return testErr })

	// Next call should be rejected without calling fn
	called := false
	err := cb.Execute(func() error {
		called = true
		return nil
	})

	if err == nil {
		t.Error("expected error when circuit is open")
	}
	if called {
		t.Error("function should not be called when circuit is open")
	}
}

func TestCircuitBreakerHalfOpenAfterTimeout(t *testing.T) {
	cb := newTestCB(2, 50*time.Millisecond)
	testErr := errors.New("fail")

	cb.Execute(func() error { return testErr })
	cb.Execute(func() error { return testErr })

	// Wait for reset timeout
	time.Sleep(60 * time.Millisecond)

	// Next call should go through (half-open)
	err := cb.Execute(func() error { return nil })
	if err != nil {
		t.Fatalf("expected no error in half-open state, got: %v", err)
	}

	// Should recover to closed
	if cb.State() != StateClosed {
		t.Errorf("expected state 'closed' after recovery, got %q", cb.State())
	}
}

func TestCircuitBreakerHalfOpenFailureReopens(t *testing.T) {
	cb := newTestCB(2, 50*time.Millisecond)
	testErr := errors.New("fail")

	// Trip the breaker
	cb.Execute(func() error { return testErr })
	cb.Execute(func() error { return testErr })

	// Wait for reset timeout
	time.Sleep(60 * time.Millisecond)

	// Fail again in half-open state
	cb.Execute(func() error { return testErr })

	if cb.State() != StateOpen {
		t.Errorf("expected state 'open' after half-open failure, got %q", cb.State())
	}
}

func TestCircuitBreakerReset(t *testing.T) {
	cb := newTestCB(2, 10*time.Second)
	testErr := errors.New("fail")

	cb.Execute(func() error { return testErr })
	cb.Execute(func() error { return testErr })

	cb.Reset()

	if cb.State() != StateClosed {
		t.Errorf("expected state 'closed' after reset, got %q", cb.State())
	}

	// Should allow calls again
	err := cb.Execute(func() error { return nil })
	if err != nil {
		t.Fatalf("unexpected error after reset: %v", err)
	}
}

func TestCircuitBreakerStats(t *testing.T) {
	cb := newTestCB(5, time.Second)
	testErr := errors.New("fail")

	cb.Execute(func() error { return testErr })
	cb.Execute(func() error { return testErr })

	stats := cb.Stats()
	if stats.Name != "test-cb" {
		t.Errorf("expected name 'test-cb', got %q", stats.Name)
	}
	if stats.Failures != 2 {
		t.Errorf("expected 2 failures, got %d", stats.Failures)
	}
	if stats.Threshold != 5 {
		t.Errorf("expected threshold 5, got %d", stats.Threshold)
	}
	if stats.State != StateClosed {
		t.Errorf("expected state 'closed', got %q", stats.State)
	}
	if stats.LastFailure == nil {
		t.Error("expected non-nil last failure time")
	}
}

func TestStateToFloat(t *testing.T) {
	tests := []struct {
		state CircuitState
		want  float64
	}{
		{StateClosed, 0},
		{StateHalfOpen, 1},
		{StateOpen, 2},
		{CircuitState("unknown"), 0},
	}

	for _, tt := range tests {
		got := stateToFloat(tt.state)
		if got != tt.want {
			t.Errorf("stateToFloat(%q) = %v, want %v", tt.state, got, tt.want)
		}
	}
}
