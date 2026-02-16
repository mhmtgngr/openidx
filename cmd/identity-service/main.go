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
	"github.com/openidx/openidx/internal/common/tlsutil"
	"github.com/openidx/openidx/internal/directory"
	"github.com/openidx/openidx/internal/email"
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/notifications"
	"github.com/openidx/openidx/internal/portal"
	"github.com/openidx/openidx/internal/risk"
	"github.com/openidx/openidx/internal/sms"
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

	// Initialize SMS service
	smsConfig := sms.Config{
		Provider:           cfg.SMS.Provider,
		Enabled:            cfg.SMS.Enabled,
		MessagePrefix:      cfg.SMS.MessagePrefix,
		TwilioSID:          cfg.SMS.TwilioSID,
		TwilioToken:        cfg.SMS.TwilioToken,
		TwilioFrom:         cfg.SMS.TwilioFrom,
		AWSRegion:          cfg.SMS.AWSRegion,
		AWSAccessKey:       cfg.SMS.AWSAccessKey,
		AWSSecretKey:       cfg.SMS.AWSSecretKey,
		WebhookURL:         cfg.SMS.WebhookURL,
		WebhookAPIKey:      cfg.SMS.WebhookAPIKey,
		NetGSMUserCode:     cfg.SMS.NetGSMUserCode,
		NetGSMPassword:     cfg.SMS.NetGSMPassword,
		NetGSMHeader:       cfg.SMS.NetGSMHeader,
		IletiMerkeziKey:    cfg.SMS.IletiMerkeziKey,
		IletiMerkeziSecret: cfg.SMS.IletiMerkeziSecret,
		IletiMerkeziSender: cfg.SMS.IletiMerkeziSender,
		VerimorUsername:     cfg.SMS.VerimorUsername,
		VerimorPassword:     cfg.SMS.VerimorPassword,
		VerimorSourceAddr:   cfg.SMS.VerimorSourceAddr,
		TurkcellUsername:    cfg.SMS.TurkcellUsername,
		TurkcellPassword:    cfg.SMS.TurkcellPassword,
		TurkcellSender:      cfg.SMS.TurkcellSender,
		VodafoneAPIKey:      cfg.SMS.VodafoneAPIKey,
		VodafoneSecret:      cfg.SMS.VodafoneSecret,
		VodafoneSender:      cfg.SMS.VodafoneSender,
		TurkTelekomAPIKey:   cfg.SMS.TurkTelekomAPIKey,
		TurkTelekomSecret:   cfg.SMS.TurkTelekomSecret,
		TurkTelekomSender:   cfg.SMS.TurkTelekomSender,
		MutlucellUsername:   cfg.SMS.MutlucellUsername,
		MutlucellPassword:   cfg.SMS.MutlucellPassword,
		MutlucellAPIKey:     cfg.SMS.MutlucellAPIKey,
		MutlucellSender:     cfg.SMS.MutlucellSender,
	}
	smsService, err := sms.NewService(smsConfig, log)
	if err != nil {
		log.Error("Failed to initialize SMS service, falling back to mock", zap.Error(err))
		smsService, _ = sms.NewService(sms.DefaultConfig(), log)
	}

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
	identityService.SetRiskService(riskService)
	identityService.SetSMSProvider(smsService)

	// Start SMS config watcher (polls DB every 30s for admin console changes)
	go identityService.StartSMSConfigWatcher(ctx, 30*time.Second)

	// Initialize portal service
	portalService := portal.NewService(db, log)

	// Initialize notification service
	notifService := notifications.NewService(db, log)

	// Register routes
	identity.RegisterRoutes(router, identityService)

	// Portal and notification routes need auth middleware to identify the caller
	portalGroup := router.Group("/api/v1/identity")
	portalGroup.Use(middleware.SoftAuth(cfg.OAuthJWKSURL))
	portal.RegisterRoutes(portalGroup, portalService)

	notifGroup := router.Group("/api/v1/identity")
	notifGroup.Use(middleware.SoftAuth(cfg.OAuthJWKSURL))
	notifications.RegisterRoutes(notifGroup, notifService)

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
		if err := tlsutil.ListenAndServe(server, cfg.TLS, log); err != nil && err != http.ErrServerClosed {
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
