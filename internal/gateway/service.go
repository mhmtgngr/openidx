// Package gateway provides API gateway functionality for OpenIDX
package gateway

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Service represents the gateway service
type Service struct {
	config         Config
	router         *gin.Engine
	httpServer     *http.Server
	shutdownMutex  sync.Mutex
	isShuttingDown bool
}

// NewService creates a new gateway service
func NewService(cfg Config) (*Service, error) {
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	svc := &Service{
		config: cfg,
	}

	return svc, nil
}

// RegisterRoutes registers all gateway routes
func (s *Service) RegisterRoutes(router *gin.Engine) {
	s.router = router

	// Apply global middleware
	s.applyGlobalMiddleware()

	// Register utility routes (health, docs)
	s.registerUtilityRoutes()

	// Note: Service routes are registered externally by routes package
	// to avoid import cycle
}

// applyGlobalMiddleware applies global middleware to the router
func (s *Service) applyGlobalMiddleware() {
	// Correlation ID middleware (must be first)
	s.router.Use(s.correlationIDMiddleware())

	// CORS middleware
	s.router.Use(s.corsMiddleware())

	// Logging middleware
	s.router.Use(s.loggingMiddleware())

	// Recovery middleware
	s.router.Use(gin.Recovery())
}

// registerUtilityRoutes registers utility endpoints
func (s *Service) registerUtilityRoutes() {
	// Health check endpoint
	s.router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "gateway",
		})
	})

	// Readiness check
	s.router.GET("/ready", func(c *gin.Context) {
		// Check Redis if rate limiting is enabled
		if s.config.IsRateLimitEnabled() && s.config.Redis != nil {
			ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
			defer cancel()

			// Simple Redis check
			result := s.config.Redis.Get(ctx, "health_check_test")
			if result.Err != nil && result.Err.Error() != "redis: nil" {
				c.JSON(http.StatusServiceUnavailable, gin.H{
					"status": "not_ready",
					"error": "redis unavailable",
				})
				return
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "ready",
		})
	})
}

// Shutdown gracefully shuts down the gateway service
func (s *Service) Shutdown(ctx context.Context) error {
	s.shutdownMutex.Lock()
	defer s.shutdownMutex.Unlock()

	if s.isShuttingDown {
		return nil
	}

	s.isShuttingDown = true

	s.logInfo("Shutting down gateway service")

	if s.httpServer != nil {
		s.logInfo("Shutting down HTTP server")

		shutdownCtx, cancel := context.WithTimeout(ctx, s.config.ShutdownTimeout)
		defer cancel()

		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.logError("Error shutting down HTTP server", zap.Error(err))
			return err
		}
	}

	s.logInfo("Gateway service shutdown complete")
	return nil
}

// Name returns the service name for graceful shutdown
func (s *Service) Name() string {
	return "gateway-service"
}

// GetServiceURL returns the URL for a given service name (implements ServiceURLProvider)
func (s *Service) GetServiceURL(serviceName string) (string, error) {
	return s.config.GetServiceURL(serviceName)
}

// HealthCheck performs a health check on the gateway
func (s *Service) HealthCheck(ctx context.Context) error {
	// Check if we're in shutdown
	s.shutdownMutex.Lock()
	isShuttingDown := s.isShuttingDown
	s.shutdownMutex.Unlock()

	if isShuttingDown {
		return fmt.Errorf("gateway is shutting down")
	}

	// Check Redis connection if rate limiting is enabled
	if s.config.IsRateLimitEnabled() && s.config.Redis != nil {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()

		result := s.config.Redis.Get(ctx, "health_check_test")
		if result.Err != nil && result.Err.Error() != "redis: nil" {
			return fmt.Errorf("redis health check failed: %w", result.Err)
		}
	}

	return nil
}

// AggregateHealth checks health of all downstream services
func (s *Service) AggregateHealth(ctx context.Context) map[string]ServiceHealth {
	healthResults := make(map[string]ServiceHealth)

	services := []string{"identity", "oauth", "governance", "audit", "admin", "risk"}

	for _, serviceName := range services {
		serviceURL, err := s.config.GetServiceURL(serviceName)
		if err != nil {
			healthResults[serviceName] = ServiceHealth{
				Healthy: false,
				URL:     "",
				Error:   err.Error(),
			}
			continue
		}

		health := s.checkServiceHealth(ctx, serviceName, serviceURL)
		healthResults[serviceName] = health
	}

	return healthResults
}

// ServiceHealth represents the health status of a service
type ServiceHealth struct {
	Healthy bool   `json:"healthy"`
	URL     string `json:"url"`
	Error   string `json:"error,omitempty"`
	Latency string `json:"latency,omitempty"`
}

// checkServiceHealth checks the health of a single service
func (s *Service) checkServiceHealth(ctx context.Context, serviceName, serviceURL string) ServiceHealth {
	start := time.Now()

	healthURL := fmt.Sprintf("%s/health", serviceURL)

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return ServiceHealth{
			Healthy: false,
			URL:     serviceURL,
			Error:   err.Error(),
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
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

// Logging helpers - simplified without type assertion
func (s *Service) logInfo(msg string, fields ...zap.Field) {
	// In production, would use proper logger
	// For now, this is a placeholder
}

func (s *Service) logError(msg string, fields ...zap.Field) {
	// In production, would use proper logger
	// For now, this is a placeholder
}

func (s *Service) logWarn(msg string, fields ...zap.Field) {
	// In production, would use proper logger
	// For now, this is a placeholder
}

// Create middleware implementations
func (s *Service) correlationIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		correlationID := c.GetHeader("X-Correlation-ID")
		if correlationID == "" {
			correlationID = generateCorrelationID()
		}
		c.Set("correlation_id", correlationID)
		c.Header("X-Correlation-ID", correlationID)
		c.Next()
	}
}

func (s *Service) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		allowedOrigins := s.config.GetAllowedOrigins()

		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			if len(allowedOrigins) == 1 && allowedOrigins[0] == "*" {
				c.Header("Access-Control-Allow-Origin", "*")
			} else {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Vary", "Origin")
			}
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Correlation-ID, X-Request-ID")
			c.Header("Access-Control-Expose-Headers", "X-Correlation-ID, X-Request-ID, X-RateLimit-Remaining, X-RateLimit-Reset")
			c.Header("Access-Control-Max-Age", "86400")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func (s *Service) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		correlationID, _ := c.Get("correlation_id")

		s.logInfo("Gateway request",
			zap.String("correlation_id", toString(correlationID)),
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.Int("status", status),
			zap.Duration("latency", latency),
			zap.String("client_ip", c.ClientIP()),
		)
	}
}

func (s *Service) rateLimitMiddleware(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Placeholder - implemented in ratelimit.go
		c.Next()
	}
}

func (s *Service) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Placeholder - implemented in auth.go
		c.Next()
	}
}

func (s *Service) proxyHeadersMiddleware(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add service identification
		c.Header("X-Target-Service", serviceName)
		c.Next()
	}
}

func generateCorrelationID() string {
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), randomString(8))
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// PermissionEntry represents a permission entry
type PermissionEntry struct {
	Resource  string `json:"resource"`
	Action    string `json:"action"`
	ScopeType string `json:"scope_type,omitempty"`
	ScopeID   string `json:"scope_id,omitempty"`
}
