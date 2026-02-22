// Package main is the entry point for the Gateway Service
// Gateway Service provides API gateway functionality and request routing
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/health"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/tlsutil"
	"github.com/openidx/openidx/internal/common/tracing"
)

var (
	Version    = "dev"
	BuildTime  = "unknown"
	CommitHash = "unknown"
)

// ServiceConfig holds configuration for upstream services
type ServiceConfig struct {
	Name string
	URL  string
	Path string
}

func main() {
	log := logger.New()
	defer log.Sync()

	log.Info("Starting Gateway Service",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit", CommitHash),
	)

	cfg, err := config.Load("gateway-service")
	if err != nil {
		log.Fatal("Failed to load configuration", zap.Error(err))
	}

	cfg.LogSecurityWarnings(log)

	// Initialize tracing
	tracingCfg := tracing.ConfigFromEnv("gateway-service", cfg.Environment)
	shutdownTracer, err := tracing.Init(context.Background(), tracingCfg, log)
	if err != nil {
		log.Warn("Failed to initialize tracing", zap.Error(err))
	} else {
		defer shutdownTracer(context.Background())
	}

	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(otelgin.Middleware("gateway-service"))
	router.Use(logger.GinMiddleware(log))
	router.Use(middleware.CORS("http://localhost:3000", "http://localhost:5173"))
	router.Use(middleware.RequestID())
	router.Use(middleware.PrometheusMetrics("gateway-service"))

	// Metrics endpoint
	router.GET("/metrics", middleware.MetricsHandler())

	// Initialize health service (no dependencies for gateway)
	healthService := health.NewHealthService(log)
	healthService.SetVersion(Version)

	// Register standard health check endpoints (/health/live, /health/ready, /health)
	healthService.RegisterStandardRoutes(router)

	// Keep legacy /ready endpoint for backward compatibility
	router.GET("/ready", healthService.ReadyHandler())

	// Configure upstream services
	services := []ServiceConfig{
		{Name: "identity", URL: "http://identity-service:8001", Path: "/api/v1/identity"},
		{Name: "governance", URL: "http://governance-service:8002", Path: "/api/v1/governance"},
		{Name: "provisioning", URL: "http://provisioning-service:8003", Path: "/scim/v2"},
		{Name: "audit", URL: "http://audit-service:8004", Path: "/api/v1/audit"},
		{Name: "admin", URL: "http://admin-api:8005", Path: "/api/v1"},
	}

	// Set up reverse proxy for each service
	for _, svc := range services {
		setupProxy(router, svc, log)
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Info("Server listening", zap.Int("port", cfg.Port))
		if err := tlsutil.ListenAndServe(server, cfg.TLS, log); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error("Server forced to shutdown", zap.Error(err))
	}

	log.Info("Server exited")
}

func setupProxy(router *gin.Engine, svc ServiceConfig, log *zap.Logger) {
	target, err := url.Parse(svc.URL)
	if err != nil {
		log.Error("Failed to parse service URL",
			zap.String("service", svc.Name),
			zap.Error(err))
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Custom error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Error("Proxy error",
			zap.String("service", svc.Name),
			zap.Error(err))
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"error": "service unavailable"}`))
	}

	router.Any(svc.Path+"/*path", func(c *gin.Context) {
		proxy.ServeHTTP(c.Writer, c.Request)
	})

	log.Info("Configured proxy",
		zap.String("service", svc.Name),
		zap.String("path", svc.Path),
		zap.String("upstream", svc.URL))
}
