// Package main is the entry point for the Governance Service
// Governance Service handles access reviews, certifications, and compliance
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
	"github.com/openidx/openidx/internal/common/opa"
	"github.com/openidx/openidx/internal/governance"
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

	log.Info("Starting Governance Service",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit", CommitHash),
	)

	// Load configuration
	cfg, err := config.Load("governance-service")
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
	router.Use(middleware.SecurityHeaders(cfg.IsProduction()))
	router.Use(logger.GinMiddleware(log))
	if cfg.EnableRateLimit {
		router.Use(middleware.RateLimit(cfg.RateLimitRequests, time.Duration(cfg.RateLimitWindow)*time.Second))
	}
	router.Use(middleware.PrometheusMetrics("governance-service"))

	// Metrics endpoint
	router.GET("/metrics", middleware.MetricsHandler())

	// Initialize governance service
	governanceService := governance.NewService(db, redis, cfg, log)

	// Register routes (with optional OPA authorization)
	var opaMiddleware []gin.HandlerFunc
	if cfg.EnableOPAAuthz {
		opaClient := opa.NewClient(cfg.OPAURL, log)
		opaMiddleware = append(opaMiddleware, middleware.OPAAuthz(opaClient, log, cfg.IsDevelopment()))
	}
	governance.RegisterRoutes(router, governanceService, opaMiddleware...)

	// Start JIT access expiration checker
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()
	governanceService.StartJITExpirationChecker(bgCtx)

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "governance-service",
			"version": Version,
		})
	})

	// Readiness check endpoint
	router.GET("/ready", func(c *gin.Context) {
		status := gin.H{"status": "ready", "postgres": "ok", "redis": "ok"}
		if err := db.Ping(); err != nil {
			status["status"] = "not ready"
			status["postgres"] = err.Error()
			c.JSON(http.StatusServiceUnavailable, status)
			return
		}
		if err := redis.Ping(); err != nil {
			status["redis"] = "unhealthy"
		}
		c.JSON(http.StatusOK, status)
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
