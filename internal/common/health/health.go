// Package health provides health check endpoints and dependency monitoring
// for OpenIDX services, supporting liveness, readiness, and detailed health probes.
package health

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// HealthStatus represents the overall health of the service
type HealthStatus struct {
	Status       string                     `json:"status"` // healthy, degraded, unhealthy
	Version      string                     `json:"version,omitempty"`
	Uptime       string                     `json:"uptime"`
	Dependencies map[string]DependencyCheck `json:"dependencies"`
	CheckedAt    time.Time                  `json:"checked_at"`
}

// DependencyCheck represents the health check result for a single dependency
type DependencyCheck struct {
	Status    string    `json:"status"` // up, degraded, down
	Latency   string    `json:"latency"`
	Details   string    `json:"details,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// HealthChecker is the interface that dependency health checks must implement
type HealthChecker interface {
	Name() string
	Check(ctx context.Context) DependencyCheck
}

// HealthService orchestrates health checks across all registered dependencies
type HealthService struct {
	checkers  []HealthChecker
	logger    *zap.Logger
	startTime time.Time
	version   string
	mu        sync.RWMutex
}

// NewHealthService creates a new HealthService
func NewHealthService(logger *zap.Logger) *HealthService {
	return &HealthService{
		checkers:  make([]HealthChecker, 0),
		logger:    logger.With(zap.String("component", "health")),
		startTime: time.Now(),
	}
}

// SetVersion sets the application version reported in health responses
func (h *HealthService) SetVersion(version string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.version = version
}

// RegisterCheck adds a new health checker to the service
func (h *HealthService) RegisterCheck(checker HealthChecker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checkers = append(h.checkers, checker)
	h.logger.Info("Registered health checker", zap.String("name", checker.Name()))
}

// Check runs all registered health checkers and aggregates the results
func (h *HealthService) Check(ctx context.Context) *HealthStatus {
	h.mu.RLock()
	checkers := make([]HealthChecker, len(h.checkers))
	copy(checkers, h.checkers)
	version := h.version
	h.mu.RUnlock()

	dependencies := make(map[string]DependencyCheck, len(checkers))

	// Run checks concurrently
	type result struct {
		name  string
		check DependencyCheck
	}
	results := make(chan result, len(checkers))

	for _, checker := range checkers {
		go func(c HealthChecker) {
			checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			results <- result{name: c.Name(), check: c.Check(checkCtx)}
		}(checker)
	}

	for i := 0; i < len(checkers); i++ {
		r := <-results
		dependencies[r.name] = r.check
	}

	// Determine overall status
	overallStatus := "healthy"
	for name, dep := range dependencies {
		switch dep.Status {
		case "down":
			overallStatus = "unhealthy"
			h.logger.Warn("Dependency is down", zap.String("dependency", name))
		case "degraded":
			if overallStatus != "unhealthy" {
				overallStatus = "degraded"
			}
			h.logger.Warn("Dependency is degraded", zap.String("dependency", name))
		}
	}

	uptime := time.Since(h.startTime)

	return &HealthStatus{
		Status:       overallStatus,
		Version:      version,
		Uptime:       formatDuration(uptime),
		Dependencies: dependencies,
		CheckedAt:    time.Now(),
	}
}

// Handler returns a gin.HandlerFunc that provides the full health check endpoint.
// It returns 200 for healthy/degraded and 503 for unhealthy.
func (h *HealthService) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		status := h.Check(c.Request.Context())

		httpStatus := http.StatusOK
		if status.Status == "unhealthy" {
			httpStatus = http.StatusServiceUnavailable
		}

		c.JSON(httpStatus, status)
	}
}

// ReadyHandler returns a gin.HandlerFunc for Kubernetes readiness probes.
// Returns 200 if all dependencies are up, 503 if any dependency is down.
func (h *HealthService) ReadyHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		status := h.Check(c.Request.Context())

		for _, dep := range status.Dependencies {
			if dep.Status == "down" {
				c.JSON(http.StatusServiceUnavailable, gin.H{
					"status": "not ready",
					"reason": "one or more dependencies are down",
					"details": status.Dependencies,
				})
				return
			}
		}

		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	}
}

// LiveHandler returns a gin.HandlerFunc for Kubernetes liveness probes.
// Always returns 200 as long as the process is alive.
func (h *HealthService) LiveHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "alive",
			"uptime": formatDuration(time.Since(h.startTime)),
		})
	}
}

// RegisterStandardRoutes registers the standard /health/live and /health/ready endpoints
// on the given Gin router. This is the recommended way to register health check endpoints.
func (h *HealthService) RegisterStandardRoutes(router *gin.Engine) {
	router.GET("/health/live", h.LiveHandler())
	router.GET("/health/ready", h.ReadyHandler())
	// Keep the full health check endpoint at /health for backward compatibility
	router.GET("/health", h.Handler())
}

// ---------- Built-in checkers ----------

// PostgresChecker checks the health of a PostgreSQL connection
type PostgresChecker struct {
	db *database.PostgresDB
}

// NewPostgresChecker creates a new PostgresChecker
func NewPostgresChecker(db *database.PostgresDB) *PostgresChecker {
	return &PostgresChecker{db: db}
}

// Name returns the checker name
func (p *PostgresChecker) Name() string {
	return "postgres"
}

// Check tests the PostgreSQL connection by running SELECT 1 and measuring latency
func (p *PostgresChecker) Check(ctx context.Context) DependencyCheck {
	start := time.Now()

	var one int
	err := p.db.Pool.QueryRow(ctx, "SELECT 1").Scan(&one)
	latency := time.Since(start)

	if err != nil {
		return DependencyCheck{
			Status:    "down",
			Latency:   latency.String(),
			Details:   fmt.Sprintf("query failed: %v", err),
			CheckedAt: time.Now(),
		}
	}

	status := "up"
	details := ""
	if latency > 500*time.Millisecond {
		status = "degraded"
		details = fmt.Sprintf("high latency: %s", latency.String())
	}

	return DependencyCheck{
		Status:    status,
		Latency:   latency.String(),
		Details:   details,
		CheckedAt: time.Now(),
	}
}

// RedisChecker checks the health of a Redis connection
type RedisChecker struct {
	redis *database.RedisClient
}

// NewRedisChecker creates a new RedisChecker
func NewRedisChecker(redis *database.RedisClient) *RedisChecker {
	return &RedisChecker{redis: redis}
}

// Name returns the checker name
func (r *RedisChecker) Name() string {
	return "redis"
}

// Check tests the Redis connection by running PING and measuring latency
func (r *RedisChecker) Check(ctx context.Context) DependencyCheck {
	start := time.Now()

	_, err := r.redis.Client.Ping(ctx).Result()
	latency := time.Since(start)

	if err != nil {
		return DependencyCheck{
			Status:    "down",
			Latency:   latency.String(),
			Details:   fmt.Sprintf("ping failed: %v", err),
			CheckedAt: time.Now(),
		}
	}

	status := "up"
	details := ""
	if latency > 200*time.Millisecond {
		status = "degraded"
		details = fmt.Sprintf("high latency: %s", latency.String())
	}

	return DependencyCheck{
		Status:    status,
		Latency:   latency.String(),
		Details:   details,
		CheckedAt: time.Now(),
	}
}

// formatDuration produces a human-readable duration string
func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
