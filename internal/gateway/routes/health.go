// Package routes provides health check route registration for the gateway
package routes

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ServiceHealth represents the health status of a service
type ServiceHealth struct {
	Healthy bool   `json:"healthy"`
	URL     string `json:"url,omitempty"`
	Error   string `json:"error,omitempty"`
	Latency string `json:"latency,omitempty"`
}

// HealthResponse represents the aggregated health check response
type HealthResponse struct {
	Status    string                   `json:"status"`
	Timestamp string                   `json:"timestamp"`
	Services  map[string]ServiceHealth `json:"services,omitempty"`
	Gateway   GatewayHealth            `json:"gateway"`
}

// GatewayHealth represents the gateway's health status
type GatewayHealth struct {
	Healthy bool   `json:"healthy"`
	Uptime  string `json:"uptime"`
	Version string `json:"version"`
}

// RegisterHealthRoutes registers health check endpoints
func RegisterHealthRoutes(router *gin.Engine, provider ServiceURLProvider) {
	// Simple health check
	router.GET("/health", healthCheckHandler())

	// Liveness probe
	router.GET("/health/live", livenessHandler())

	// Readiness probe
	router.GET("/health/ready", readinessHandler())

	// Detailed health with all services
	router.GET("/health/detailed", detailedHealthHandler(provider))

	// Legacy /ready endpoint
	router.GET("/ready", readinessHandler())
}

// healthCheckHandler provides a simple health check endpoint
func healthCheckHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "gateway",
		})
	}
}

// livenessHandler returns whether the gateway is alive
func livenessHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "alive",
		})
	}
}

// readinessHandler returns whether the gateway is ready to serve traffic
func readinessHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ready",
		})
	}
}

// detailedHealthHandler provides detailed health information including all services
func detailedHealthHandler(provider ServiceURLProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		response := HealthResponse{
			Timestamp: time.Now().Format(time.RFC3339),
			Services:  make(map[string]ServiceHealth),
			Gateway: GatewayHealth{
				Healthy: true,
				Uptime:  getUptime(),
				Version: "1.0.0",
			},
		}

		// Check each service
		services := []string{"identity", "oauth", "governance", "audit", "admin", "risk"}
		allHealthy := true

		for _, serviceName := range services {
			serviceURL, _ := provider.GetServiceURL(serviceName)
			health := checkServiceHealth(ctx, serviceName, serviceURL)
			response.Services[serviceName] = health

			if !health.Healthy {
				allHealthy = false
			}
		}

		// Set overall status
		if allHealthy {
			response.Status = "healthy"
		} else {
			response.Status = "degraded"
			response.Gateway.Healthy = false
		}

		statusCode := http.StatusOK
		if !allHealthy {
			statusCode = http.StatusServiceUnavailable
		}

		c.JSON(statusCode, response)
	}
}

// checkServiceHealth checks the health of a single service
func checkServiceHealth(ctx context.Context, serviceName, serviceURL string) ServiceHealth {
	start := time.Now()

	healthURL := serviceURL + "/health"

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return ServiceHealth{
			Healthy: false,
			URL:     serviceURL,
			Error:   err.Error(),
		}
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)

	latency := time.Since(start)

	if err != nil {
		return ServiceHealth{
			Healthy: false,
			URL:     serviceURL,
			Error:   err.Error(),
			Latency: latency.String(),
		}
	}
	defer resp.Body.Close()

	healthy := resp.StatusCode == http.StatusOK

	return ServiceHealth{
		Healthy: healthy,
		URL:     serviceURL,
		Latency: latency.String(),
	}
}

// uptime tracks when the service started
var startTime = time.Now()

// getUptime returns the service uptime
func getUptime() string {
	uptime := time.Since(startTime)
	return uptime.String()
}

// AggregateServiceHealth aggregates health from all downstream services
func AggregateServiceHealth(ctx context.Context, provider ServiceURLProvider) map[string]ServiceHealth {
	services := []string{"identity", "oauth", "governance", "audit", "admin", "risk"}
	results := make(map[string]ServiceHealth)

	for _, serviceName := range services {
		serviceURL, _ := provider.GetServiceURL(serviceName)
		health := checkServiceHealth(ctx, serviceName, serviceURL)
		results[serviceName] = health
	}

	return results
}

// HealthCheckHandler returns a handler that performs health checks
func HealthCheckHandler(provider ServiceURLProvider) gin.HandlerFunc {
	return detailedHealthHandler(provider)
}
