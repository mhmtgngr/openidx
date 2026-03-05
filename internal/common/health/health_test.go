package health

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

// mockChecker is a test health checker
type mockChecker struct {
	name   string
	status string
}

func (m *mockChecker) Name() string { return m.name }
func (m *mockChecker) Check(ctx context.Context) DependencyCheck {
	return DependencyCheck{
		Status:    m.status,
		Latency:   "1ms",
		CheckedAt: time.Now(),
	}
}

func TestNewHealthService(t *testing.T) {
	logger := zap.NewNop()
	svc := NewHealthService(logger)

	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestHealthServiceSetVersion(t *testing.T) {
	svc := NewHealthService(zap.NewNop())
	svc.SetVersion("1.2.3")

	status := svc.Check(context.Background())
	if status.Version != "1.2.3" {
		t.Errorf("expected version '1.2.3', got %q", status.Version)
	}
}

func TestHealthServiceAllHealthy(t *testing.T) {
	svc := NewHealthService(zap.NewNop())
	svc.RegisterCheck(&mockChecker{name: "db", status: "up"})
	svc.RegisterCheck(&mockChecker{name: "redis", status: "up"})

	status := svc.Check(context.Background())
	if status.Status != "healthy" {
		t.Errorf("expected 'healthy', got %q", status.Status)
	}
	if len(status.Dependencies) != 2 {
		t.Errorf("expected 2 dependencies, got %d", len(status.Dependencies))
	}
}

func TestHealthServiceDegraded(t *testing.T) {
	svc := NewHealthService(zap.NewNop())
	svc.RegisterCheck(&mockChecker{name: "db", status: "up"})
	svc.RegisterCheck(&mockChecker{name: "redis", status: "degraded"})

	status := svc.Check(context.Background())
	if status.Status != "degraded" {
		t.Errorf("expected 'degraded', got %q", status.Status)
	}
}

func TestHealthServiceUnhealthy(t *testing.T) {
	svc := NewHealthService(zap.NewNop())
	svc.RegisterCheck(&mockChecker{name: "db", status: "down"})
	svc.RegisterCheck(&mockChecker{name: "redis", status: "up"})

	status := svc.Check(context.Background())
	if status.Status != "unhealthy" {
		t.Errorf("expected 'unhealthy', got %q", status.Status)
	}
}

func TestHealthServiceUnhealthyOverridesDegraded(t *testing.T) {
	svc := NewHealthService(zap.NewNop())
	svc.RegisterCheck(&mockChecker{name: "db", status: "down"})
	svc.RegisterCheck(&mockChecker{name: "redis", status: "degraded"})

	status := svc.Check(context.Background())
	if status.Status != "unhealthy" {
		t.Errorf("expected 'unhealthy' (overrides degraded), got %q", status.Status)
	}
}

func TestHealthServiceNoDependencies(t *testing.T) {
	svc := NewHealthService(zap.NewNop())

	status := svc.Check(context.Background())
	if status.Status != "healthy" {
		t.Errorf("expected 'healthy' with no deps, got %q", status.Status)
	}
	if len(status.Dependencies) != 0 {
		t.Errorf("expected 0 dependencies, got %d", len(status.Dependencies))
	}
}

func TestHealthServiceUptime(t *testing.T) {
	svc := NewHealthService(zap.NewNop())

	status := svc.Check(context.Background())
	if status.Uptime == "" {
		t.Error("expected non-empty uptime")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{5 * time.Second, "5s"},
		{65 * time.Second, "1m 5s"},
		{3661 * time.Second, "1h 1m 1s"},
		{90061 * time.Second, "1d 1h 1m 1s"},
	}

	for _, tt := range tests {
		got := formatDuration(tt.d)
		if got != tt.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}
