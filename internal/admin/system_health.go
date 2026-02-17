package admin

import (
	"context"
	"net/http"
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

	// Check inter-service connectivity by querying known service ports
	services := []struct {
		name string
		port string
	}{
		{"identity-service", "8001"},
		{"governance-service", "8002"},
		{"provisioning-service", "8003"},
		{"audit-service", "8004"},
		{"oauth-service", "8006"},
	}

	for _, svc := range services {
		svcHealth := s.checkServiceHealth(ctx, svc.name, svc.port)
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

func (s *Service) checkServiceHealth(ctx context.Context, name, port string) HealthStatus {
	start := time.Now()

	client := &http.Client{Timeout: 3 * time.Second}
	url := "http://" + name + ":" + port + "/health"
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
