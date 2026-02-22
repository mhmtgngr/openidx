// Package main is the entry point for the Zero Trust Access Proxy Service
// Access Service provides identity-aware reverse proxying with policy enforcement
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
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/access"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
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

func main() {
	// Initialize logger
	log := logger.New()
	defer log.Sync()

	log.Info("Starting Zero Trust Access Proxy Service",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit", CommitHash),
	)

	// Load configuration
	cfg, err := config.Load("access-service")
	if err != nil {
		log.Fatal("Failed to load configuration", zap.Error(err))
	}

	cfg.LogSecurityWarnings(log)

	// Initialize tracing
	tracingCfg := tracing.ConfigFromEnv("access-service", cfg.Environment)
	shutdownTracer, err := tracing.Init(context.Background(), tracingCfg, log)
	if err != nil {
		log.Warn("Failed to initialize tracing", zap.Error(err))
	} else {
		defer shutdownTracer(context.Background())
	}

	// Initialize database connection
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

	// Initialize Redis connection
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

	// Set Gin mode
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(otelgin.Middleware("access-service"))
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

	// CSRF protection for cookie-authenticated proxy sessions
	router.Use(middleware.CSRFProtection(middleware.CSRFConfig{
		Enabled:       cfg.CSRFEnabled,
		TrustedDomain: cfg.CSRFTrustedDomain,
	}, log))

	// CORS middleware
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})
	router.Use(middleware.PrometheusMetrics("access-service"))

	// Metrics endpoint
	router.GET("/metrics", middleware.MetricsHandler())

	// Initialize health service with database and Redis checks
	healthService := health.NewHealthService(log)
	healthService.SetVersion(Version)
	healthService.RegisterCheck(health.NewPostgresChecker(db))
	healthService.RegisterCheck(health.NewRedisChecker(redis))

	// Register standard health check endpoints
	healthService.RegisterStandardRoutes(router)

	// Keep legacy /access/health and /access/ready endpoints for backward compatibility
	router.GET("/access/health", healthService.Handler())
	router.GET("/access/ready", healthService.ReadyHandler())

	// Initialize access proxy service
	accessService := access.NewService(db, redis, cfg, log)

	// Background context for long-running goroutines
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()

	// Initialize BrowZer Target Manager for dynamic bootstrapper config
	var browzerTargetManager *access.BrowZerTargetManager
	if cfg.BrowZerTargetsPath != "" {
		browzerTargetManager = access.NewBrowZerTargetManager(db, log, cfg.BrowZerTargetsPath)
		if cfg.BrowZerRouterConfigPath != "" {
			browzerTargetManager.SetRouterConfigPath(cfg.BrowZerRouterConfigPath)
		}
		if cfg.BrowZerCertsPath != "" {
			browzerTargetManager.SetCertsPath(cfg.BrowZerCertsPath)
		}
		// Load configured domain from DB
		if err := browzerTargetManager.LoadDomainFromDB(bgCtx); err != nil {
			log.Warn("Failed to load BrowZer domain config", zap.Error(err))
		}
		accessService.SetBrowZerTargetManager(browzerTargetManager)
		log.Info("BrowZer Target Manager initialized",
			zap.String("targets_path", cfg.BrowZerTargetsPath),
			zap.String("router_config_path", cfg.BrowZerRouterConfigPath),
			zap.String("certs_path", cfg.BrowZerCertsPath),
			zap.String("domain", browzerTargetManager.GetDomain()))
	}

	// Initialize APISIX SSL management
	if cfg.APISIXConfigPath != "" {
		accessService.SetAPISIXConfigPath(cfg.APISIXConfigPath)
		log.Info("APISIX SSL management initialized", zap.String("config_path", cfg.APISIXConfigPath))
	}

	// Initialize Feature Manager for unified service management
	featureManager := access.NewFeatureManager(db, log)
	if browzerTargetManager != nil {
		featureManager.SetBrowZerTargetManager(browzerTargetManager)
	}
	accessService.SetFeatureManager(featureManager)
	log.Info("Feature Manager initialized")

	// Initialize Unified Audit Service
	auditService := access.NewUnifiedAuditService(db, log)
	accessService.SetAuditService(auditService)
	log.Info("Unified Audit Service initialized")

	// Initialize Apache Guacamole client if configured
	if cfg.GuacamoleURL != "" {
		log.Info("Initializing Apache Guacamole integration...", zap.String("url", cfg.GuacamoleURL))
		gc, err := access.NewGuacamoleClient(cfg, db, log)
		if err != nil {
			log.Error("Failed to initialize Guacamole client -- remote access features disabled", zap.Error(err))
		} else {
			accessService.SetGuacamoleClient(gc)
			featureManager.SetGuacamoleClient(gc)
			auditService.SetGuacamoleClient(gc)
			log.Info("Apache Guacamole integration ready")
		}
	}

	// Start continuous session verification if enabled
	if cfg.ContinuousVerifyEnabled {
		log.Info("Starting continuous session verifier", zap.Int("interval_seconds", cfg.ContinuousVerifyInterval))
		accessService.StartContinuousVerification(bgCtx, cfg.ContinuousVerifyInterval)
	}

	// Initialize OpenZiti if enabled
	if cfg.ZitiEnabled {
		log.Info("OpenZiti integration enabled, initializing ZitiManager...")
		zm, err := access.NewZitiManager(cfg, db, log)
		if err != nil {
			log.Error("Failed to initialize ZitiManager -- Ziti features disabled", zap.Error(err))
		} else {
			accessService.SetZitiManager(zm)
			featureManager.SetZitiManager(zm)
			auditService.SetZitiManager(zm)
			defer zm.Close()

			// Start background monitors
			zitiCtx, zitiCancel := context.WithCancel(context.Background())
			defer zitiCancel()
			zm.StartHealthMonitor(zitiCtx)
			zm.StartCertificateMonitor(zitiCtx)
			zm.StartUserSyncPoller(zitiCtx)
			zm.StartPostureResultExpiryChecker(zitiCtx)

			// Host all Ziti-enabled services (creates terminators so Dial works)
			zm.HostAllServices(zitiCtx)

			// Bootstrap BrowZer if enabled
			if cfg.BrowZerEnabled {
				log.Info("Bootstrapping BrowZer configuration...")
				if err := zm.BootstrapBrowZer(zitiCtx, cfg.OAuthIssuer, cfg.OAuthJWKSURL, cfg.BrowZerClientID); err != nil {
					log.Error("BrowZer bootstrap failed -- BrowZer features disabled", zap.Error(err))
				} else {
					log.Info("BrowZer bootstrap complete")
				}
			}

			// Ensure Ziti services exist for seeded routes (e.g., demo-app)
			// Also create the browzer-router-zt service for path-based routing
			// After that completes, generate initial BrowZer targets + router config
			go func() {
				accessService.EnsureZitiServicesForRoutes(zitiCtx, zm)

				// Ensure browzer-router-zt Ziti service exists for path-based routing
				accessService.EnsureBrowZerRouterService(zitiCtx, zm)

				if browzerTargetManager != nil {
					if err := browzerTargetManager.WriteBrowZerTargets(zitiCtx); err != nil {
						log.Warn("Failed to write initial BrowZer targets", zap.Error(err))
					} else {
						log.Info("Initial BrowZer targets file generated")
					}
					if err := browzerTargetManager.WriteBrowZerRouterConfig(zitiCtx); err != nil {
						log.Warn("Failed to write initial BrowZer router config", zap.Error(err))
					} else {
						log.Info("Initial BrowZer router config generated")
					}
				}
			}()

			log.Info("OpenZiti integration ready (health + certificate monitors started, services hosted)")
		}
	} else {
		log.Info("OpenZiti integration disabled (set ZITI_ENABLED=true to enable)")
	}

	// Start background audit event sync (every 5 minutes)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		// Initial sync after 30 seconds
		time.Sleep(30 * time.Second)
		if err := auditService.SyncExternalAuditEvents(bgCtx); err != nil {
			log.Warn("Initial external audit sync failed", zap.Error(err))
		} else {
			log.Info("Initial external audit sync completed")
		}

		for {
			select {
			case <-bgCtx.Done():
				return
			case <-ticker.C:
				if err := auditService.SyncExternalAuditEvents(bgCtx); err != nil {
					log.Warn("External audit sync failed", zap.Error(err))
				}
			}
		}
	}()
	log.Info("Background audit sync scheduled (every 5 minutes)")

	// Register routes (admin API is protected in non-dev environments)
	if cfg.Environment != "development" {
		access.RegisterRoutes(router, accessService, middleware.Auth(cfg.OAuthJWKSURL))
	} else {
		access.RegisterRoutes(router, accessService)
	}

	// Create HTTP server
	port := cfg.Port
	if port == 0 {
		port = 8007
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Info("Starting Access Proxy service", zap.Int("port", port))
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
