// Package main is the entry point for the OAuth/OIDC Service
// OAuth Service provides OAuth 2.0 and OpenID Connect capabilities
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
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/oauth"
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

	log.Info("Starting OAuth/OIDC Service",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit", CommitHash),
	)

	// Load configuration
	cfg, err := config.Load("oauth-service")
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

	// Enable CORS for OAuth endpoints
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})
	router.Use(middleware.PrometheusMetrics("oauth-service"))

	// Metrics endpoint
	router.GET("/metrics", middleware.MetricsHandler())

	// Initialize Identity service
	identityService := identity.NewService(db, redis, cfg, log)

	// Initialize risk service (conditional access)
	riskService := risk.NewService(db, redis, log)

	// Initialize webhook service
	webhookService := webhooks.NewService(db, redis, log)
	ctx, cancelWorkers := context.WithCancel(context.Background())
	go webhookService.ProcessDeliveries(ctx)
	go webhookService.ProcessRetries(ctx)
	defer cancelWorkers()

	// Initialize OAuth service
	oauthService, err := oauth.NewService(db, redis, cfg, log, identityService)
	if err != nil {
		log.Fatal("Failed to initialize OAuth service", zap.Error(err))
	}
	oauthService.SetRiskService(riskService)
	oauthService.SetWebhookService(webhookService)

	// Register routes (apply auth middleware to client management API in non-development environments)
	if cfg.Environment != "development" {
		oauth.RegisterRoutes(router, oauthService, middleware.Auth(cfg.OAuthJWKSURL))
	} else {
		oauth.RegisterRoutes(router, oauthService)
	}

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "oauth-service",
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
	port := cfg.Port
	if port == 0 {
		port = 8006
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Info("Starting OAuth service", zap.Int("port", port))
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
