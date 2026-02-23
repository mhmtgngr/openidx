// Package main is the entry point for the Gateway Service
// Gateway Service provides unified API gateway functionality with JWT validation,
// rate limiting, request routing, and distributed tracing support.
package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	"github.com/openidx/openidx/internal/api"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/common/tlsutil"
	"github.com/openidx/openidx/internal/common/tracing"
	newhealth "github.com/openidx/openidx/internal/health"
	"github.com/openidx/openidx/internal/metrics"
	"github.com/openidx/openidx/internal/server"
	"github.com/openidx/openidx/internal/gateway"
	"github.com/openidx/openidx/internal/gateway/routes"
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

	log.Info("Starting Gateway Service",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit", CommitHash),
	)

	// Load configuration
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
	}

	// Initialize Redis connection for rate limiting
	redisClient, err := database.NewRedisFromConfig(database.RedisConfig{
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
		log.Fatal("Failed to connect to Redis", zap.Error(err))
	}

	// Set Gin mode
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(otelgin.Middleware("gateway-service"))
	router.Use(logger.GinMiddleware(log))
	router.Use(api.StandardVersionMiddleware())

	// Metrics endpoint
	router.GET("/metrics", metrics.Handler())

	// Create gateway config with wrapper types
	var shutdownTracerWrapper gateway.TracerShutdownFunc
	if shutdownTracer != nil {
		shutdownTracerWrapper = func(ctx interface{}) error {
			var stdctx context.Context
			if c, ok := ctx.(context.Context); ok {
				stdctx = c
			} else {
				stdctx = context.Background()
			}
			return shutdownTracer(stdctx)
		}
	}
	gatewayCfg := createGatewayConfig(cfg, redisClient.Client, log, shutdownTracerWrapper)

	// Initialize gateway service
	gatewayService, err := gateway.NewService(gatewayCfg)
	if err != nil {
		log.Fatal("Failed to initialize gateway service", zap.Error(err))
	}

	// Register gateway utility routes (health, etc)
	gatewayService.RegisterRoutes(router)

	// Create service URL provider
	provider := &serviceURLProvider{}

	// Register service routes through the routes package
	registerServiceRoutes(router, provider)

	// Initialize health service
	healthService := newhealth.NewHealthService(log)
	healthService.SetVersion(Version)
	healthService.RegisterCheck(newhealth.NewRedisChecker(redisClient))
	healthService.RegisterStandardRoutes(router, "")

	// Keep legacy /ready endpoint for backward compatibility
	router.GET("/ready", healthService.ReadyHandler())

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Setup graceful shutdown
	shutdownables := []server.Shutdownable{
		server.CloseRedis(redisClient),
		gatewayService,
	}
	if shutdownTracer != nil {
		shutdownables = append(shutdownables, server.CloseTracer(shutdownTracer))
	}

	graceful := server.New(server.Config{
		Server:          httpServer,
		Logger:          log,
		Shutdownables:   shutdownables,
		ShutdownTimeout: 30 * time.Second,
	})

	// Start server in goroutine
	go func() {
		log.Info("Gateway server listening", zap.Int("port", cfg.Port))
		if err := tlsutil.ListenAndServe(httpServer, cfg.TLS, log); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for shutdown signal
	graceful.Start()

	log.Info("Gateway server exited")
}

// createGatewayConfig creates a gateway config from common config
func createGatewayConfig(cfg *config.Config, redis *redis.Client, log *zap.Logger, shutdownTracer gateway.TracerShutdownFunc) gateway.Config {
	// Default service URLs
	services := map[string]string{
		"identity":   "http://localhost:8501",
		"oauth":      "http://localhost:8502",
		"governance": "http://localhost:8503",
		"audit":      "http://localhost:8504",
		"admin":      "http://localhost:8505",
		"risk":       "http://localhost:8506",
	}

	return gateway.Config{
		Services:            services,
		JWKSURL:             cfg.OAuthJWKSURL,
		EnableRateLimit:     cfg.EnableRateLimit,
		RateLimitConfig:     gateway.RateLimitConfig{
			RequestsPerMinute:     100,
			AuthRequestsPerMinute: 20,
			WindowSeconds:         60,
		},
		AllowedOrigins:      cfg.GetCORSOrigins(),
		RequestTimeout:      30 * time.Second,
		ShutdownTimeout:     30 * time.Second,
		Redis:              &redisClientWrapper{client: redis},
		Logger:             &zapLoggerWrapper{logger: log},
		TracerShutdown:     shutdownTracer,
	}
}

// redisClientWrapper wraps redis.Client to implement gateway.RedisClient
type redisClientWrapper struct {
	client *redis.Client
}

func (w *redisClientWrapper) Get(ctx interface{}, key string) *gateway.RedisStringCmd {
	// Convert context interface to context.Context
	var stdctx context.Context
	if ctx, ok := ctx.(context.Context); ok {
		stdctx = ctx
	} else {
		stdctx = context.Background()
	}

	val, err := w.client.Get(stdctx, key).Result()
	return &gateway.RedisStringCmd{Val: val, Err: err}
}

func (w *redisClientWrapper) Set(ctx interface{}, key string, value interface{}, expiration time.Duration) *gateway.RedisStatusCmd {
	var stdctx context.Context
	if ctx, ok := ctx.(context.Context); ok {
		stdctx = ctx
	} else {
		stdctx = context.Background()
	}

	err := w.client.Set(stdctx, key, value, expiration).Err()
	return &gateway.RedisStatusCmd{Val: "OK", Err: err}
}

func (w *redisClientWrapper) Incr(ctx interface{}, key string) *gateway.RedisIntCmd {
	var stdctx context.Context
	if ctx, ok := ctx.(context.Context); ok {
		stdctx = ctx
	} else {
		stdctx = context.Background()
	}

	val, err := w.client.Incr(stdctx, key).Result()
	return &gateway.RedisIntCmd{Val: val, Err: err}
}

func (w *redisClientWrapper) Expire(ctx interface{}, key string, expiration time.Duration) *gateway.RedisBoolCmd {
	var stdctx context.Context
	if ctx, ok := ctx.(context.Context); ok {
		stdctx = ctx
	} else {
		stdctx = context.Background()
	}

	val, err := w.client.Expire(stdctx, key, expiration).Result()
	return &gateway.RedisBoolCmd{Val: val, Err: err}
}

func (w *redisClientWrapper) Pipeline() gateway.RedisPipeline {
	// Return a wrapper for the pipeline
	return nil
}

func (w *redisClientWrapper) Close() error {
	return w.client.Close()
}

// zapLoggerWrapper wraps zap.Logger to implement gateway.Logger
type zapLoggerWrapper struct {
	logger *zap.Logger
}

func (w *zapLoggerWrapper) Debug(msg string, fields ...interface{}) {
	zapFields := make([]zap.Field, 0, len(fields))
	for _, f := range fields {
		if zf, ok := f.(zap.Field); ok {
			zapFields = append(zapFields, zf)
		}
	}
	w.logger.Debug(msg, zapFields...)
}

func (w *zapLoggerWrapper) Info(msg string, fields ...interface{}) {
	zapFields := make([]zap.Field, 0, len(fields))
	for _, f := range fields {
		if zf, ok := f.(zap.Field); ok {
			zapFields = append(zapFields, zf)
		}
	}
	w.logger.Info(msg, zapFields...)
}

func (w *zapLoggerWrapper) Warn(msg string, fields ...interface{}) {
	zapFields := make([]zap.Field, 0, len(fields))
	for _, f := range fields {
		if zf, ok := f.(zap.Field); ok {
			zapFields = append(zapFields, zf)
		}
	}
	w.logger.Warn(msg, zapFields...)
}

func (w *zapLoggerWrapper) Error(msg string, fields ...interface{}) {
	zapFields := make([]zap.Field, 0, len(fields))
	for _, f := range fields {
		if zf, ok := f.(zap.Field); ok {
			zapFields = append(zapFields, zf)
		}
	}
	w.logger.Error(msg, zapFields...)
}

func (w *zapLoggerWrapper) Fatal(msg string, fields ...interface{}) {
	zapFields := make([]zap.Field, 0, len(fields))
	for _, f := range fields {
		if zf, ok := f.(zap.Field); ok {
			zapFields = append(zapFields, zf)
		}
	}
	w.logger.Fatal(msg, zapFields...)
}

func (w *zapLoggerWrapper) Sync() error {
	return w.logger.Sync()
}

// serviceURLProvider implements routes.ServiceURLProvider
type serviceURLProvider struct{}

func (p *serviceURLProvider) GetServiceURL(serviceName string) (string, error) {
	// Default URLs
	urls := map[string]string{
		"identity":   "http://localhost:8501",
		"oauth":      "http://localhost:8502",
		"governance": "http://localhost:8503",
		"audit":      "http://localhost:8504",
		"admin":      "http://localhost:8505",
		"risk":       "http://localhost:8506",
	}

	if url, ok := urls[serviceName]; ok {
		return url, nil
	}
	return "", fmt.Errorf("unknown service: %s", serviceName)
}

// registerServiceRoutes registers all service routes
func registerServiceRoutes(router *gin.Engine, provider *serviceURLProvider) {
	// Create route groups for each service
	identityGroup := router.Group("/api/v1/identity")
	oauthGroup := router.Group("/api/v1/oauth")
	governanceGroup := router.Group("/api/v1/governance")
	auditGroup := router.Group("/api/v1/audit")
	adminGroup := router.Group("/api/v1/admin")
	riskGroup := router.Group("/api/v1/risk")

	// Register routes for each service
	routes.RegisterIdentityRoutes(identityGroup, provider)
	routes.RegisterOAuthRoutes(oauthGroup, provider)
	routes.RegisterGovernanceRoutes(governanceGroup, provider)
	routes.RegisterAuditRoutes(auditGroup, provider)
	routes.RegisterAdminRoutes(adminGroup, provider)
	routes.RegisterRiskRoutes(riskGroup, provider)

	// Register health and docs routes
	routes.RegisterHealthRoutes(router, provider)
	routes.RegisterDocsRoutes(router, provider)
}
