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
)

// ComponentStatus represents the health status of a single component
type ComponentStatus struct {
	Status     string  `json:"status"`     // up, degraded, down
	LatencyMS  float64 `json:"latency_ms"` // Latency in milliseconds
	Details    string  `json:"details,omitempty"`
	CheckedAt  string  `json:"checked_at"`
}

// DependencyInfo represents information about an external dependency
type DependencyInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"` // up, degraded, down
}

// HealthResponse is the response structure for health checks
type HealthResponse struct {
	Status       string                       `json:"status"`       // up, degraded, down
	Components   map[string]ComponentStatus   `json:"components"`
	Dependencies []DependencyInfo            `json:"dependencies,omitempty"`
	Version      string                      `json:"version,omitempty"`
	Uptime       string                      `json:"uptime,omitempty"`
	CheckedAt    string                      `json:"checked_at"`
}

// HealthChecker is the interface that dependency health checks must implement
type HealthChecker interface {
	Name() string
	Check(ctx context.Context) ComponentStatus
	IsCritical() bool // Returns true if this component is critical for readiness
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
	h.logger.Info("Registered health checker",
		zap.String("name", checker.Name()),
		zap.Bool("critical", checker.IsCritical()))
}

// Check runs all registered health checkers and aggregates the results
func (h *HealthService) Check(ctx context.Context) *HealthResponse {
	h.mu.RLock()
	checkers := make([]HealthChecker, len(h.checkers))
	copy(checkers, h.checkers)
	version := h.version
	h.mu.RUnlock()

	components := make(map[string]ComponentStatus, len(checkers))
	dependencies := make([]DependencyInfo, 0, len(checkers))

	// Run checks concurrently
	type result struct {
		name  string
		check ComponentStatus
		critical bool
	}
	results := make(chan result, len(checkers))

	for _, checker := range checkers {
		go func(c HealthChecker) {
			checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			results <- result{
				name:     c.Name(),
				check:    c.Check(checkCtx),
				critical: c.IsCritical(),
			}
		}(checker)
	}

	for i := 0; i < len(checkers); i++ {
		r := <-results
		components[r.name] = r.check
		dependencies = append(dependencies, DependencyInfo{
			Name:   r.name,
			Status: r.check.Status,
		})
	}

	// Determine overall status
	overallStatus := "up"
	for name, comp := range components {
		switch comp.Status {
		case "down":
			overallStatus = "down"
			h.logger.Warn("Component is down", zap.String("component", name))
		case "degraded":
			if overallStatus != "down" {
				overallStatus = "degraded"
			}
			h.logger.Warn("Component is degraded", zap.String("component", name))
		}
	}

	uptime := time.Since(h.startTime)

	return &HealthResponse{
		Status:       overallStatus,
		Components:   components,
		Dependencies: dependencies,
		Version:      version,
		Uptime:       formatDuration(uptime),
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	}
}

// Handler returns a gin.HandlerFunc that provides the full health check endpoint.
// It returns 200 for up/degraded and 503 for down.
func (h *HealthService) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		resp := h.Check(c.Request.Context())

		httpStatus := http.StatusOK
		if resp.Status == "down" {
			httpStatus = http.StatusServiceUnavailable
		}

		c.JSON(httpStatus, resp)
	}
}

// ReadyHandler returns a gin.HandlerFunc for Kubernetes readiness probes.
// Returns 503 if any critical component is down.
func (h *HealthService) ReadyHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		resp := h.Check(c.Request.Context())

		h.mu.RLock()
		checkers := make([]HealthChecker, len(h.checkers))
		copy(checkers, h.checkers)
		h.mu.RUnlock()

		// Check if any critical component is down
		for _, checker := range checkers {
			if checker.IsCritical() {
				if comp, ok := resp.Components[checker.Name()]; ok && comp.Status == "down" {
					c.JSON(http.StatusServiceUnavailable, gin.H{
						"status": "not ready",
						"reason": fmt.Sprintf("critical component %s is down", checker.Name()),
					})
					return
				}
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

// RegisterStandardRoutes registers the standard health endpoints on the given router
func (h *HealthService) RegisterStandardRoutes(router *gin.Engine, prefix string) {
	if prefix == "" {
		prefix = "/health"
	}
	router.GET(prefix, h.Handler())
	router.GET(prefix+"/ready", h.ReadyHandler())
	router.GET(prefix+"/live", h.LiveHandler())
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
