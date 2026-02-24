// Package main is the entry point for the Admin API
// Admin API provides the REST API for the Admin Console
package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/admin"
	adminhandlers "github.com/openidx/openidx/internal/admin/handlers"
	"github.com/openidx/openidx/internal/api"
	"github.com/openidx/openidx/internal/apikeys"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/opa"
	newhealth "github.com/openidx/openidx/internal/health"
	"github.com/openidx/openidx/internal/common/tlsutil"
	"github.com/openidx/openidx/internal/common/tracing"
	"github.com/openidx/openidx/internal/directory"
	"github.com/openidx/openidx/internal/email"
	"github.com/openidx/openidx/internal/metrics"
	"github.com/openidx/openidx/internal/notifications"
	"github.com/openidx/openidx/internal/organization"
	"github.com/openidx/openidx/internal/risk"
	"github.com/openidx/openidx/internal/server"
	"github.com/openidx/openidx/internal/webhooks"
)

var (
	Version    = "dev"
	BuildTime  = "unknown"
	CommitHash = "unknown"
)

// @title OpenIDX Admin API
// @version 1.0
// @description Admin API for OpenIDX Identity Platform
// @termsOfService https://openidx.io/terms

// @contact.name API Support
// @contact.url https://openidx.io/support
// @contact.email support@openidx.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8005
// @BasePath /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	log := logger.New()
	defer log.Sync()

	log.Info("Starting Admin API",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit", CommitHash),
	)

	cfg, err := config.Load("admin-api")
	if err != nil {
		log.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Validate production security settings (blocking)
	if err := config.ValidateProductionConfig(cfg, log); err != nil {
		log.Fatal("Production security validation failed", zap.Error(err))
	}

	cfg.LogSecurityWarnings(log)

	// Initialize tracing
	tracingCfg := tracing.ConfigFromEnv("admin-api", cfg.Environment)
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
		log.Fatal("Failed to connect to Redis", zap.Error(err))
	}
	defer redis.Close()

	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(otelgin.Middleware("admin-api"))
	router.Use(middleware.SecurityHeaders(cfg.IsProduction()))
	router.Use(logger.GinMiddleware(log))
	if cfg.EnableRateLimit {
		router.Use(middleware.DistributedRateLimit(redis.Client, middleware.RateLimitConfig{
			Requests:     cfg.RateLimitRequests,
			Window:       time.Duration(cfg.RateLimitWindow) * time.Second,
			AuthRequests: cfg.RateLimitAuthRequests,
			AuthWindow:   time.Duration(cfg.RateLimitAuthWindow) * time.Second,
			PerUser:      cfg.RateLimitPerUser,
		}, log))
	}
	router.Use(middleware.CORS("http://localhost:3000", "http://localhost:5173"))
	router.Use(middleware.RequestID())
	router.Use(middleware.PrometheusMetrics("admin-api"))
	router.Use(api.StandardVersionMiddleware())

	// Metrics endpoint
	router.GET("/metrics", metrics.Handler())

	// Initialize health service with database and Redis checks
	healthService := newhealth.NewHealthService(log)
	healthService.SetVersion(Version)
	healthService.RegisterCheck(newhealth.NewPostgresChecker(db))
	healthService.RegisterCheck(newhealth.NewRedisChecker(redis))

	// Register standard health check endpoints (/health/live, /health/ready, /health)
	healthService.RegisterStandardRoutes(router, "")

	// Keep legacy /ready endpoint for backward compatibility
	router.GET("/ready", healthService.ReadyHandler())

	// Initialize directory service
	dirService := directory.NewService(db, log)
	if err := dirService.Start(context.Background()); err != nil {
		log.Error("Directory service failed to start", zap.Error(err))
	}
	defer dirService.Stop()

	// Initialize risk service (conditional access)
	riskService := risk.NewService(db, redis, log)

	// Initialize email service
	emailService := email.NewService(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom, redis, log)

	// Initialize API key service
	apiKeyService := apikeys.NewService(db, redis, log)

	// Initialize webhook service
	webhookService := webhooks.NewService(db, redis, log)

	// Start background workers
	ctx, cancelWorkers := context.WithCancel(context.Background())
	go emailService.ProcessQueue(ctx)
	go webhookService.ProcessDeliveries(ctx)
	go webhookService.ProcessRetries(ctx)
	defer cancelWorkers()

	// Initialize admin service
	adminService := admin.NewService(db, redis, cfg, log)
	adminService.SetDirectoryService(&directorySyncAdapter{dirService: dirService})
	adminService.SetRiskService(&riskServiceAdapter{riskService: riskService})
	adminService.SetAPIKeyService(&apiKeyAdapter{svc: apiKeyService})
	adminService.SetWebhookService(&webhookAdapter{svc: webhookService})
	adminService.SetSecurityService(&securityAdapter{riskService: riskService})

	// Initialize organization service
	orgService := organization.NewService(db, redis, cfg, log)

	// Initialize notification service
	notifService := notifications.NewService(db, log)

	// API v1 routes
	v1 := router.Group("/api/v1")
	if cfg.Environment != "development" {
		v1.Use(middleware.Auth(cfg.OAuthJWKSURL))
	} else {
		// In dev mode, use soft auth to identify caller without blocking
		v1.Use(middleware.SoftAuth(cfg.OAuthJWKSURL))
	}

	// Resolve permissions from roles (cached in Redis)
	v1.Use(middleware.PermissionResolver(db.Pool, redis.Client))

	// OPA authorization (opt-in via ENABLE_OPA_AUTHZ)
	if cfg.EnableOPAAuthz {
		opaClient := opa.NewClient(cfg.OPAURL, log)
		v1.Use(middleware.OPAAuthz(opaClient, log, cfg.IsDevelopment()))
	}

	{
		admin.RegisterRoutes(v1, adminService)
		organization.RegisterRoutes(v1, orgService)
		notifications.RegisterRoutes(v1, notifService)

		// Register admin console handlers (dashboard, settings)
		adminhandlers.RegisterAllRoutes(v1, db.Pool, log)
	}

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
	shutdownables = append(shutdownables, server.CloseRedis(redis))
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

// directorySyncAdapter adapts directory.Service to admin.DirectorySyncer interface
type directorySyncAdapter struct {
	dirService *directory.Service
}

func (a *directorySyncAdapter) TestConnection(ctx context.Context, dirType string, configBytes []byte) error {
	return a.dirService.TestConnection(ctx, dirType, configBytes)
}

func (a *directorySyncAdapter) TriggerSync(ctx context.Context, directoryID string, fullSync bool) error {
	return a.dirService.TriggerSync(ctx, directoryID, fullSync)
}

func (a *directorySyncAdapter) GetSyncLogs(ctx context.Context, directoryID string, limit int) (interface{}, error) {
	return a.dirService.GetSyncLogs(ctx, directoryID, limit)
}

func (a *directorySyncAdapter) GetSyncState(ctx context.Context, directoryID string) (interface{}, error) {
	return a.dirService.GetSyncState(ctx, directoryID)
}

// riskServiceAdapter adapts risk.Service to admin.RiskAssessor interface
type riskServiceAdapter struct {
	riskService *risk.Service
}

func (a *riskServiceAdapter) GetAllDevices(ctx context.Context, limit, offset int) (interface{}, int, error) {
	return a.riskService.GetAllDevices(ctx, limit, offset)
}

func (a *riskServiceAdapter) GetUserDevices(ctx context.Context, userID string) (interface{}, error) {
	return a.riskService.GetUserDevices(ctx, userID)
}

func (a *riskServiceAdapter) TrustDevice(ctx context.Context, deviceID string) error {
	return a.riskService.TrustDevice(ctx, deviceID)
}

func (a *riskServiceAdapter) RevokeDevice(ctx context.Context, deviceID string) error {
	return a.riskService.RevokeDevice(ctx, deviceID)
}

func (a *riskServiceAdapter) GetRiskStats(ctx context.Context) (map[string]interface{}, error) {
	return a.riskService.GetRiskStats(ctx)
}

func (a *riskServiceAdapter) GetLoginHistory(ctx context.Context, userID string, limit int) (interface{}, error) {
	return a.riskService.GetLoginHistory(ctx, userID, limit)
}

// apiKeyAdapter adapts apikeys.Service to admin.APIKeyManager interface
type apiKeyAdapter struct {
	svc *apikeys.Service
}

func (a *apiKeyAdapter) CreateServiceAccount(ctx context.Context, name, description, ownerID string) (interface{}, error) {
	return a.svc.CreateServiceAccount(ctx, name, description, ownerID)
}

func (a *apiKeyAdapter) ListServiceAccounts(ctx context.Context, limit, offset int) (interface{}, int, error) {
	accounts, total, err := a.svc.ListServiceAccounts(ctx, limit, offset)
	return accounts, total, err
}

func (a *apiKeyAdapter) GetServiceAccount(ctx context.Context, id string) (interface{}, error) {
	return a.svc.GetServiceAccount(ctx, id)
}

func (a *apiKeyAdapter) DeleteServiceAccount(ctx context.Context, id string) error {
	return a.svc.DeleteServiceAccount(ctx, id)
}

func (a *apiKeyAdapter) CreateAPIKey(ctx context.Context, name string, userID, serviceAccountID *string, scopes []string, expiresAt *time.Time) (string, interface{}, error) {
	return a.svc.CreateAPIKey(ctx, name, userID, serviceAccountID, scopes, expiresAt)
}

func (a *apiKeyAdapter) ListAPIKeys(ctx context.Context, ownerID string, ownerType string) (interface{}, error) {
	return a.svc.ListAPIKeys(ctx, ownerID, ownerType)
}

func (a *apiKeyAdapter) RevokeAPIKey(ctx context.Context, keyID string) error {
	return a.svc.RevokeAPIKey(ctx, keyID)
}

// webhookAdapter adapts webhooks.Service to admin.WebhookManager interface
type webhookAdapter struct {
	svc *webhooks.Service
}

func (a *webhookAdapter) CreateSubscription(ctx context.Context, name, url, secret string, events []string, createdBy string) (interface{}, error) {
	return a.svc.CreateSubscription(ctx, name, url, secret, events, createdBy)
}

func (a *webhookAdapter) ListSubscriptions(ctx context.Context) (interface{}, error) {
	return a.svc.ListSubscriptions(ctx)
}

func (a *webhookAdapter) GetSubscription(ctx context.Context, id string) (interface{}, error) {
	return a.svc.GetSubscription(ctx, id)
}

func (a *webhookAdapter) DeleteSubscription(ctx context.Context, id string) error {
	return a.svc.DeleteSubscription(ctx, id)
}

func (a *webhookAdapter) GetDeliveryHistory(ctx context.Context, subscriptionID string, limit int) (interface{}, error) {
	return a.svc.GetDeliveryHistory(ctx, subscriptionID, limit)
}

func (a *webhookAdapter) RetryDelivery(ctx context.Context, deliveryID string) error {
	return a.svc.RetryDelivery(ctx, deliveryID)
}

func (a *webhookAdapter) Publish(ctx context.Context, eventType string, payload interface{}) error {
	return a.svc.Publish(ctx, eventType, payload)
}

func (a *webhookAdapter) PingSubscription(ctx context.Context, subscriptionID string) (interface{}, error) {
	return a.svc.PingSubscription(ctx, subscriptionID)
}

func (a *webhookAdapter) GetDeliveryStats(ctx context.Context, subscriptionID string) (interface{}, error) {
	return a.svc.GetDeliveryStats(ctx, subscriptionID)
}

// securityAdapter adapts risk.Service to admin.SecurityService interface
type securityAdapter struct {
	riskService *risk.Service
}

func (a *securityAdapter) ListSecurityAlerts(ctx context.Context, status, severity, alertType string, limit, offset int) (interface{}, int, error) {
	alerts, total, err := a.riskService.ListSecurityAlerts(ctx, status, severity, alertType, limit, offset)
	return alerts, total, err
}

func (a *securityAdapter) GetSecurityAlert(ctx context.Context, id string) (interface{}, error) {
	return a.riskService.GetSecurityAlert(ctx, id)
}

func (a *securityAdapter) UpdateAlertStatus(ctx context.Context, id, status, resolvedBy string) error {
	return a.riskService.UpdateAlertStatus(ctx, id, status, resolvedBy)
}

func (a *securityAdapter) ListIPThreats(ctx context.Context, limit, offset int) (interface{}, int, error) {
	entries, total, err := a.riskService.ListIPThreats(ctx, limit, offset)
	return entries, total, err
}

func (a *securityAdapter) AddToThreatList(ctx context.Context, ip, threatType, reason string, permanent bool, blockedUntil *time.Time) error {
	return a.riskService.AddToThreatList(ctx, ip, threatType, reason, permanent, blockedUntil)
}

func (a *securityAdapter) RemoveFromThreatList(ctx context.Context, id string) error {
	return a.riskService.RemoveFromThreatList(ctx, id)
}
