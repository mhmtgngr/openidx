// Package main is the entry point for the Audit Service
// Audit Service handles logging, compliance reporting, and SIEM integration
package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/api"
	"github.com/openidx/openidx/internal/audit"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/common/middleware"
	newhealth "github.com/openidx/openidx/internal/health"
	"github.com/openidx/openidx/internal/common/tlsutil"
	"github.com/openidx/openidx/internal/common/tracing"
	"github.com/openidx/openidx/internal/metrics"
	"github.com/openidx/openidx/internal/server"
)

var (
	Version    = "dev"
	BuildTime  = "unknown"
	CommitHash = "unknown"
)

func main() {
	log := logger.New()
	defer log.Sync()

	log.Info("Starting Audit Service",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit", CommitHash),
	)

	cfg, err := config.Load("audit-service")
	if err != nil {
		log.Fatal("Failed to load configuration", zap.Error(err))
	}

	cfg.LogSecurityWarnings(log)

	// Initialize tracing
	tracingCfg := tracing.ConfigFromEnv("audit-service", cfg.Environment)
	shutdownTracer, err := tracing.Init(context.Background(), tracingCfg, log)
	if err != nil {
		log.Warn("Failed to initialize tracing", zap.Error(err))
	} else {
		defer shutdownTracer(context.Background())
	}

	db, err := database.NewPostgres(cfg.DatabaseURL, database.PostgresTLSConfig{
		SSLMode:     cfg.DatabaseSSLMode,
		SSLRootCert: cfg.DatabaseSSLRootCert,
		SSLCert:     cfg.DatabaseSSLCert,
		SSLKey:      cfg.DatabaseSSLKey,
	})
	if err != nil {
		log.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer db.Close()

	// Initialize Redis connection (used for distributed rate limiting)
	redis, err := database.NewRedisFromConfig(database.RedisConfig{
		URL:                cfg.RedisURL,
		SentinelEnabled:    cfg.RedisSentinelEnabled,
		SentinelMasterName: cfg.RedisSentinelMasterName,
		SentinelAddresses:  cfg.GetRedisSentinelAddresses(),
		SentinelPassword:   cfg.RedisSentinelPassword,
		Password:           cfg.GetRedisPassword(),
		TLSEnabled:         cfg.RedisTLSEnabled,
		TLSCACert:          cfg.RedisTLSCACert,
		TLSCert:            cfg.RedisTLSCert,
		TLSKey:             cfg.RedisTLSKey,
		TLSSkipVerify:      cfg.RedisTLSSkipVerify,
	})
	if err != nil {
		log.Warn("Failed to connect to Redis, rate limiting will fail open", zap.Error(err))
	} else {
		defer redis.Close()
	}

	// Initialize Elasticsearch client (best-effort — audit works without ES)
	var es *database.ElasticsearchClient
	if cfg.ElasticsearchURL != "" {
		es, err = database.NewElasticsearchFromConfig(database.ElasticsearchConfig{
			URL:      cfg.ElasticsearchURL,
			Username: cfg.ElasticsearchUsername,
			Password: cfg.ElasticsearchPassword,
			TLS:      cfg.ElasticsearchTLS,
			CACert:   cfg.ElasticsearchCACert,
		})
		if err != nil {
			log.Warn("Elasticsearch unavailable, full-text search disabled", zap.Error(err))
		}
	}

	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(otelgin.Middleware("audit-service"))
	router.Use(middleware.SecurityHeaders(cfg.IsProduction()))
	router.Use(logger.GinMiddleware(log))
	if cfg.EnableRateLimit {
		var redisClient *goredis.Client
		if redis != nil {
			redisClient = redis.Client
		}
		router.Use(middleware.DistributedRateLimit(redisClient, middleware.RateLimitConfig{
			Requests:     cfg.RateLimitRequests,
			Window:       time.Duration(cfg.RateLimitWindow) * time.Second,
			AuthRequests: cfg.RateLimitAuthRequests,
			AuthWindow:   time.Duration(cfg.RateLimitAuthWindow) * time.Second,
			PerUser:      cfg.RateLimitPerUser,
		}, log))
	}
	router.Use(middleware.PrometheusMetrics("audit-service"))
	router.Use(api.StandardVersionMiddleware())

	// Metrics endpoint
	router.GET("/metrics", metrics.Handler())

	auditService := audit.NewService(db, es, cfg, log)
	if es != nil {
		if err := auditService.InitElasticsearch(); err != nil {
			log.Warn("Failed to initialize ES index, search may not work", zap.Error(err))
		}
	}
	audit.RegisterRoutes(router, auditService)
	audit.RegisterReportRoutes(router.Group("/api/v1/audit"), auditService)

	// Initialize health service with database check
	healthService := newhealth.NewHealthService(log)
	healthService.SetVersion(Version)
	healthService.RegisterCheck(newhealth.NewPostgresChecker(db))

	// Add Elasticsearch check if configured (optional dependency)
	if es != nil {
		healthService.RegisterCheck(&elasticsearchChecker{client: es})
	}

	// Register standard health check endpoints (/health/live, /health/ready, /health)
	healthService.RegisterStandardRoutes(router, "")

	// Keep legacy /ready endpoint for backward compatibility
	router.GET("/ready", healthService.ReadyHandler())

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Build shutdownables list
	var shutdownables []server.Shutdownable
	shutdownables = append(shutdownables, server.CloseDB(db))
	if redis != nil {
		shutdownables = append(shutdownables, server.CloseRedis(redis))
	}
	if shutdownTracer != nil {
		shutdownables = append(shutdownables, server.CloseTracer(shutdownTracer))
	}

	// Create graceful manager
	graceful := server.New(server.Config{
		Server:         httpServer,
		Logger:         log,
		Shutdownables:  shutdownables,
		ShutdownTimeout: 30 * time.Second,
	})

	// Start server in goroutine
	go func() {
		log.Info("Server listening", zap.Int("port", cfg.Port))
		if err := tlsutil.ListenAndServe(httpServer, cfg.TLS, log); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for shutdown signal
	graceful.Start()
}

// elasticsearchChecker implements health.HealthChecker for Elasticsearch
type elasticsearchChecker struct {
	client *database.ElasticsearchClient
}

func (e *elasticsearchChecker) Name() string {
	return "elasticsearch"
}

func (e *elasticsearchChecker) IsCritical() bool {
	return false // Elasticsearch is optional for audit service
}

func (e *elasticsearchChecker) Check(ctx context.Context) newhealth.ComponentStatus {
	start := time.Now()

	err := e.client.Ping()
	latency := time.Since(start)

	if err != nil {
		return newhealth.ComponentStatus{
			Status:     "down",
			LatencyMS:  float64(latency.Milliseconds()),
			Details:    fmt.Sprintf("ping failed: %v", err),
			CheckedAt:  time.Now().UTC().Format(time.RFC3339),
		}
	}

	status := "up"
	details := ""
	if latency > 500*time.Millisecond {
		status = "degraded"
		details = fmt.Sprintf("high latency: %s", latency.String())
	}

	return newhealth.ComponentStatus{
		Status:     status,
		LatencyMS:  float64(latency.Milliseconds()),
		Details:    details,
		CheckedAt:  time.Now().UTC().Format(time.RFC3339),
	}
}
