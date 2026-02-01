// Package main is the entry point for the Identity Service
// Identity Service handles authentication, session management, and SSO
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/directory"
	"github.com/openidx/openidx/internal/email"
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/notifications"
	"github.com/openidx/openidx/internal/portal"
	"github.com/openidx/openidx/internal/risk"
	"github.com/openidx/openidx/internal/webhooks"
)

var (
	Version    = "dev"
	BuildTime  = "unknown"
	CommitHash = "unknown"
)

func main() {
	// Initialize logger
	log := logger.New()
	defer log.Sync()

	log.Info("Starting Identity Service",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit", CommitHash),
	)

	// Load configuration
	cfg, err := config.Load("identity-service")
	if err != nil {
		log.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Initialize database connection
	db, err := database.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer db.Close()

	// Initialize Redis connection
	redis, err := database.NewRedis(cfg.RedisURL)
	if err != nil {
		log.Fatal("Failed to connect to Redis", zap.Error(err))
	}
	defer redis.Close()

	// Set Gin mode
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(logger.GinMiddleware(log))
	router.Use(middleware.PrometheusMetrics("identity-service"))

	// Metrics endpoint
	router.GET("/metrics", middleware.MetricsHandler())

	// Initialize directory service for LDAP sync
	dirService := directory.NewService(db, log)
	if err := dirService.Start(context.Background()); err != nil {
		log.Error("Directory service failed to start", zap.Error(err))
	}
	defer dirService.Stop()

	// Initialize email service
	emailService := email.NewService(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom, redis, log)

	// Initialize webhook service
	webhookService := webhooks.NewService(db, redis, log)

	// Initialize risk/anomaly service
	riskService := risk.NewService(db, redis, log)

	// Start background workers
	ctx, cancelWorkers := context.WithCancel(context.Background())
	go emailService.ProcessQueue(ctx)
	go webhookService.ProcessDeliveries(ctx)
	go webhookService.ProcessRetries(ctx)
	defer cancelWorkers()

	// Initialize identity service
	identityService := identity.NewService(db, redis, cfg, log)
	identityService.SetDirectoryService(dirService)
	identityService.SetEmailService(emailService)
	identityService.SetWebhookService(webhookService)
	identityService.SetAnomalyDetector(&anomalyDetectorAdapter{riskService: riskService})

	// Initialize portal service
	portalService := portal.NewService(db, log)

	// Initialize notification service
	notifService := notifications.NewService(db, log)

	// Register routes
	identity.RegisterRoutes(router, identityService)
	portal.RegisterRoutes(router.Group("/api/v1/identity"), portalService)
	notifications.RegisterRoutes(router.Group("/api/v1/identity"), notifService)

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "identity-service",
			"version": Version,
		})
	})

	// Readiness check endpoint
	router.GET("/ready", func(c *gin.Context) {
		if err := db.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not ready", "error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Info("Server listening", zap.Int("port", cfg.Port))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error("Server forced to shutdown", zap.Error(err))
	}

	log.Info("Server exited")
}

// anomalyDetectorAdapter adapts risk.Service to identity.AnomalyDetector interface
type anomalyDetectorAdapter struct {
	riskService *risk.Service
}

func (a *anomalyDetectorAdapter) RunAnomalyCheck(ctx context.Context, userID, ip, userAgent string, lat, lon float64) interface{} {
	return a.riskService.RunAnomalyCheck(ctx, userID, ip, userAgent, lat, lon)
}

func (a *anomalyDetectorAdapter) CheckIPThreatList(ctx context.Context, ip string) (bool, string) {
	return a.riskService.CheckIPThreatList(ctx, ip)
}
