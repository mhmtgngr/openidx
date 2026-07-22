package admin

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// HealthStatus represents the health of a single dependency
type HealthStatus struct {
	Name      string `json:"name"`
	Status    string `json:"status"` // "healthy", "degraded", "unhealthy"
	LatencyMs int64  `json:"latency_ms"`
	Details   string `json:"details,omitempty"`
}

// SystemHealthResponse contains overall system health
type SystemHealthResponse struct {
	Status       string         `json:"status"` // "healthy", "degraded", "unhealthy"
	Uptime       string         `json:"uptime"`
	Timestamp    time.Time      `json:"timestamp"`
	Dependencies []HealthStatus `json:"dependencies"`
}

func (s *Service) handleSystemHealth(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	deps := []HealthStatus{}
	overallStatus := "healthy"

	// Check PostgreSQL
	dbHealth := s.checkPostgres(ctx)
	deps = append(deps, dbHealth)
	if dbHealth.Status != "healthy" {
		overallStatus = "degraded"
	}

	// Check Redis
	redisHealth := s.checkRedis(ctx)
	deps = append(deps, redisHealth)
	if redisHealth.Status != "healthy" {
		if overallStatus == "healthy" {
			overallStatus = "degraded"
		}
	}

	// Check inter-service connectivity. Each service's base URL is taken from its
	// *_SERVICE_URL env (the same vars the gateway uses), falling back to
	// http://localhost:<port>. Using the service *name* as a hostname (the old
	// behavior) only resolves under Kubernetes/Docker DNS; on a single-box deploy
	// the services listen on 127.0.0.1:<port>, so name-based probes always read
	// "unreachable" and made this page show a false "degraded"/"Unhealthy".
	services := []struct {
		name   string
		envVar string
		port   string
	}{
		{"identity-service", "IDENTITY_SERVICE_URL", "8001"},
		{"governance-service", "GOVERNANCE_SERVICE_URL", "8002"},
		{"provisioning-service", "PROVISIONING_SERVICE_URL", "8003"},
		{"audit-service", "AUDIT_SERVICE_URL", "8004"},
		{"oauth-service", "OAUTH_SERVICE_URL", "8006"},
	}

	for _, svc := range services {
		base := os.Getenv(svc.envVar)
		if base == "" {
			base = "http://localhost:" + svc.port
		}
		svcHealth := s.checkServiceHealth(ctx, svc.name, base)
		deps = append(deps, svcHealth)
		if svcHealth.Status == "unhealthy" && overallStatus == "healthy" {
			overallStatus = "degraded"
		}
	}

	resp := SystemHealthResponse{
		Status:       overallStatus,
		Timestamp:    time.Now().UTC(),
		Dependencies: deps,
	}

	statusCode := http.StatusOK
	if overallStatus == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	}
	c.JSON(statusCode, resp)
}

func (s *Service) checkPostgres(ctx context.Context) HealthStatus {
	start := time.Now()
	err := s.db.Pool.Ping(ctx)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return HealthStatus{
			Name:      "postgresql",
			Status:    "unhealthy",
			LatencyMs: latency,
			Details:   err.Error(),
		}
	}

	status := "healthy"
	if latency > 500 {
		status = "degraded"
	}

	return HealthStatus{
		Name:      "postgresql",
		Status:    status,
		LatencyMs: latency,
	}
}

func (s *Service) checkRedis(ctx context.Context) HealthStatus {
	if s.redis == nil {
		return HealthStatus{
			Name:    "redis",
			Status:  "unhealthy",
			Details: "not configured",
		}
	}

	start := time.Now()
	err := s.redis.Client.Ping(ctx).Err()
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return HealthStatus{
			Name:      "redis",
			Status:    "unhealthy",
			LatencyMs: latency,
			Details:   err.Error(),
		}
	}

	status := "healthy"
	if latency > 200 {
		status = "degraded"
	}

	return HealthStatus{
		Name:      "redis",
		Status:    status,
		LatencyMs: latency,
	}
}

func (s *Service) checkServiceHealth(ctx context.Context, name, baseURL string) HealthStatus {
	start := time.Now()

	client := &http.Client{Timeout: 3 * time.Second}
	// Probe liveness: /health/live is always 200 while the process is up. We only
	// want to know the peer is reachable here — a peer's own dependency being
	// degraded is reported by that peer, not surfaced as "unhealthy transport".
	url := strings.TrimRight(baseURL, "/") + "/health/live"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return HealthStatus{
			Name:      name,
			Status:    "unhealthy",
			LatencyMs: time.Since(start).Milliseconds(),
			Details:   err.Error(),
		}
	}

	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return HealthStatus{
			Name:      name,
			Status:    "unhealthy",
			LatencyMs: latency,
			Details:   "unreachable",
		}
	}
	defer resp.Body.Close()

	status := "healthy"
	if resp.StatusCode != http.StatusOK {
		status = "unhealthy"
	} else if latency > 1000 {
		status = "degraded"
	}

	return HealthStatus{
		Name:      name,
		Status:    status,
		LatencyMs: latency,
	}
}
