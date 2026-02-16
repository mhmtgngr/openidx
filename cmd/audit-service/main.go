// Package main is the entry point for the Audit Service
// Audit Service handles logging, compliance reporting, and SIEM integration
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
	goredis "github.com/redis/go-redis/v9"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/audit"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
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

	// Initialize tracing
	tracingCfg := tracing.ConfigFromEnv("audit-service", cfg.Environment)
	shutdownTracer, err := tracing.Init(context.Background(), tracingCfg, log)
	if err != nil {
		log.Warn("Failed to initialize tracing", zap.Error(err))
	} else {
		defer shutdownTracer(context.Background())
	}

	db, err := database.NewPostgres(cfg.DatabaseURL)
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
	})
	if err != nil {
		log.Warn("Failed to connect to Redis, rate limiting will fail open", zap.Error(err))
	} else {
		defer redis.Close()
	}

	// Initialize Elasticsearch client (best-effort — audit works without ES)
	var es *database.ElasticsearchClient
	if cfg.ElasticsearchURL != "" {
		es, err = database.NewElasticsearch(cfg.ElasticsearchURL)
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

	// Metrics endpoint
	router.GET("/metrics", middleware.MetricsHandler())

	auditService := audit.NewService(db, es, cfg, log)
	if es != nil {
		if err := auditService.InitElasticsearch(); err != nil {
			log.Warn("Failed to initialize ES index, search may not work", zap.Error(err))
		}
	}
	audit.RegisterRoutes(router, auditService)
	audit.RegisterReportRoutes(router.Group("/api/v1/audit"), auditService)

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "audit-service",
			"version": Version,
		})
	})

	router.GET("/ready", func(c *gin.Context) {
		if err := db.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not ready", "error": err.Error()})
			return
		}
		esStatus := "not configured"
		if es != nil {
			if err := es.Ping(); err != nil {
				esStatus = "unhealthy"
			} else {
				esStatus = "healthy"
			}
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready", "elasticsearch": esStatus})
	})

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
