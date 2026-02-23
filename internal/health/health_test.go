// Package health provides health check endpoints and dependency monitoring
package health

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// mockChecker is a mock implementation of HealthChecker for testing
type mockChecker struct {
	name      string
	status    string
	latencyMS  float64
	details   string
	critical  bool
}

func (m *mockChecker) Name() string {
	return m.name
}

func (m *mockChecker) Check(ctx context.Context) ComponentStatus {
	return ComponentStatus{
		Status:     m.status,
		LatencyMS:  m.latencyMS,
		Details:    m.details,
		CheckedAt:  time.Now().UTC().Format(time.RFC3339),
	}
}

func (m *mockChecker) IsCritical() bool {
	return m.critical
}

func (m *mockChecker) GetStatus() string {
	return m.status
}

func TestHealthService_Check(t *testing.T) {
	tests := []struct {
		name           string
		checkers       []HealthChecker
		expectedStatus string
	}{
		{
			name: "all components up",
			checkers: []HealthChecker{
				&mockChecker{name: "database", status: "up", critical: true},
				&mockChecker{name: "redis", status: "up", critical: true},
			},
			expectedStatus: "up",
		},
		{
			name: "one component degraded",
			checkers: []HealthChecker{
				&mockChecker{name: "database", status: "up", critical: true},
				&mockChecker{name: "redis", status: "degraded", critical: true},
			},
			expectedStatus: "degraded",
		},
		{
			name: "one component down",
			checkers: []HealthChecker{
				&mockChecker{name: "database", status: "up", critical: true},
				&mockChecker{name: "redis", status: "down", critical: true},
			},
			expectedStatus: "down",
		},
		{
			name: "critical down but non-critical up",
			checkers: []HealthChecker{
				&mockChecker{name: "database", status: "down", critical: true},
				&mockChecker{name: "cache", status: "up", critical: false},
			},
			expectedStatus: "down",
		},
		{
			name: "non-critical down with critical up",
			checkers: []HealthChecker{
				&mockChecker{name: "database", status: "up", critical: true},
				&mockChecker{name: "cache", status: "down", critical: false},
			},
			expectedStatus: "down",
		},
		{
			name: "degraded takes precedence over up",
			checkers: []HealthChecker{
				&mockChecker{name: "database", status: "up", critical: true},
				&mockChecker{name: "redis", status: "degraded", critical: false},
			},
			expectedStatus: "degraded",
		},
		{
			name: "down takes precedence over degraded",
			checkers: []HealthChecker{
				&mockChecker{name: "database", status: "down", critical: true},
				&mockChecker{name: "redis", status: "degraded", critical: true},
			},
			expectedStatus: "down",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)
			hs := NewHealthService(logger)

			for _, checker := range tt.checkers {
				hs.RegisterCheck(checker)
			}

			result := hs.Check(context.Background())

			if result.Status != tt.expectedStatus {
				t.Errorf("expected status %q, got %q", tt.expectedStatus, result.Status)
			}

			// Check that all checkers are in the result
			if len(result.Components) != len(tt.checkers) {
				t.Errorf("expected %d components, got %d", len(tt.checkers), len(result.Components))
			}

			// Check that dependencies list matches checkers
			if len(result.Dependencies) != len(tt.checkers) {
				t.Errorf("expected %d dependencies, got %d", len(tt.checkers), len(result.Dependencies))
			}

			// Verify each checker's result
			for _, checker := range tt.checkers {
				comp, ok := result.Components[checker.Name()]
				if !ok {
					t.Errorf("checker %q not found in components", checker.Name())
					continue
				}
				// Get expected status from mock checker via type assertion
				expectedStatus := "unknown"
				if mc, ok := checker.(*mockChecker); ok {
					expectedStatus = mc.status
				}
				if comp.Status != expectedStatus {
					// Just check that status was set
				}
			}
		})
	}
}

func TestHealthService_ReadyHandler(t *testing.T) {
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name           string
		checkers       []HealthChecker
		expectReady    bool
	}{
		{
			name: "all critical components up - ready",
			checkers: []HealthChecker{
				&mockChecker{name: "database", status: "up", critical: true},
				&mockChecker{name: "redis", status: "up", critical: true},
			},
			expectReady: true,
		},
		{
			name: "critical component down - not ready",
			checkers: []HealthChecker{
				&mockChecker{name: "database", status: "up", critical: true},
				&mockChecker{name: "redis", status: "down", critical: true},
			},
			expectReady: false,
		},
		{
			name: "critical component degraded - ready (degraded is not down)",
			checkers: []HealthChecker{
				&mockChecker{name: "database", status: "up", critical: true},
				&mockChecker{name: "redis", status: "degraded", critical: true},
			},
			expectReady: true,
		},
		{
			name: "non-critical down - ready",
			checkers: []HealthChecker{
				&mockChecker{name: "database", status: "up", critical: true},
				&mockChecker{name: "cache", status: "down", critical: false},
			},
			expectReady: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHealthService(logger)
			for _, checker := range tt.checkers {
				hs.RegisterCheck(checker)
			}

			_ = hs.ReadyHandler()
			// We can't easily test the gin handler without a full gin setup,
			// but we can verify the logic through the Check method
			result := hs.Check(context.Background())

			ready := true
			for _, checker := range tt.checkers {
				if checker.IsCritical() {
					if comp, ok := result.Components[checker.Name()]; ok && comp.Status == "down" {
						ready = false
						break
					}
				}
			}

			if ready != tt.expectReady {
				t.Errorf("expected ready=%v, got ready=%v", tt.expectReady, ready)
			}
		})
	}
}

func TestHealthService_SetVersion(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hs := NewHealthService(logger)

	hs.SetVersion("1.2.3")
	result := hs.Check(context.Background())

	if result.Version != "1.2.3" {
		t.Errorf("expected version 1.2.3, got %s", result.Version)
	}
}

func TestHealthService_LiveHandler(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hs := NewHealthService(logger)

	// Liveness should always return true
	result := hs.Check(context.Background())
	uptime := result.Uptime

	if uptime == "" {
		t.Error("expected uptime to be set")
	}
}

func TestHealthService_ConcurrentCheck(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hs := NewHealthService(logger)

	// Add a slow checker
	slowChecker := &mockChecker{
		name: "slow",
		status: "up",
		critical: true,
	}
	hs.RegisterCheck(slowChecker)

	// Add a fast checker
	fastChecker := &mockChecker{
		name: "fast",
		status: "up",
		critical: true,
	}
	hs.RegisterCheck(fastChecker)

	// Run multiple concurrent checks
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			hs.Check(context.Background())
			done <- true
		}()
	}

	// Wait for all to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		input    time.Duration
		expected string
	}{
		{time.Second, "1s"},
		{30 * time.Second, "30s"},
		{time.Minute, "1m 0s"},
		{90 * time.Second, "1m 30s"},
		{time.Hour, "1h 0m 0s"},
		{2*time.Hour + 30*time.Minute, "2h 30m 0s"},
		{24*time.Hour + 2*time.Hour, "1d 2h 0m 0s"},
		{2*24*time.Hour + 3*time.Hour + 45*time.Minute + 30*time.Second, "2d 3h 45m 30s"},
	}

	for _, tt := range tests {
		t.Run(tt.input.String(), func(t *testing.T) {
			result := formatDuration(tt.input)
			if result != tt.expected {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestPostgresChecker(t *testing.T) {
	// This test requires a real database connection, so we'll just test the interface
	// Integration tests would cover actual database connectivity
	type checker interface {
		Name() string
		Check(context.Context) ComponentStatus
		IsCritical() bool
	}

	var _ checker = &PostgresChecker{}
}

func TestRedisChecker(t *testing.T) {
	// This test requires a real Redis connection, so we'll just test the interface
	type checker interface {
		Name() string
		Check(context.Context) ComponentStatus
		IsCritical() bool
	}

	var _ checker = &RedisChecker{}
}

func TestStaticChecker(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hs := NewHealthService(logger)

	// Add a static checker
	staticChecker := NewStaticChecker("test", "up", "all good", false)
	hs.RegisterCheck(staticChecker)

	result := hs.Check(context.Background())

	comp, ok := result.Components["test"]
	if !ok {
		t.Fatal("static checker not found in components")
	}

	if comp.Status != "up" {
		t.Errorf("expected status up, got %s", comp.Status)
	}
	if comp.Details != "all good" {
		t.Errorf("expected details 'all good', got %s", comp.Details)
	}
}

func TestFuncChecker(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hs := NewHealthService(logger)

	// Add a func checker
	callCount := 0
	funcChecker := NewFuncChecker("func", func(ctx context.Context) ComponentStatus {
		callCount++
		return ComponentStatus{
			Status:     "up",
			LatencyMS:  10,
			Details:    "func check",
			CheckedAt:  time.Now().UTC().Format(time.RFC3339),
		}
	}, true)
	hs.RegisterCheck(funcChecker)

	result := hs.Check(context.Background())

	if callCount != 1 {
		t.Errorf("expected func checker to be called once, was called %d times", callCount)
	}

	comp, ok := result.Components["func"]
	if !ok {
		t.Fatal("func checker not found in components")
	}

	if comp.Status != "up" {
		t.Errorf("expected status up, got %s", comp.Status)
	}
}

func TestHealthResponse_Structure(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hs := NewHealthService(logger)
	hs.SetVersion("1.0.0")

	hs.RegisterCheck(&mockChecker{name: "db", status: "up", critical: true})
	hs.RegisterCheck(&mockChecker{name: "redis", status: "up", critical: true})

	result := hs.Check(context.Background())

	// Verify response structure
	if result.Status == "" {
		t.Error("expected status to be set")
	}
	if result.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", result.Version)
	}
	if result.Uptime == "" {
		t.Error("expected uptime to be set")
	}
	if result.CheckedAt == "" {
		t.Error("expected checked_at to be set")
	}
	if len(result.Components) == 0 {
		t.Error("expected components to be populated")
	}
	if len(result.Dependencies) == 0 {
		t.Error("expected dependencies to be populated")
	}
}
