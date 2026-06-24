// Package main is the entry point for the Zero Trust Access Proxy Service
// Access Service provides identity-aware reverse proxying with policy enforcement
package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/access"
	"github.com/openidx/openidx/internal/api"
	"github.com/openidx/openidx/internal/audit"
	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/tlsutil"
	"github.com/openidx/openidx/internal/common/tracing"
	newhealth "github.com/openidx/openidx/internal/health"
	"github.com/openidx/openidx/internal/metrics"
	"github.com/openidx/openidx/internal/organization"
	"github.com/openidx/openidx/internal/server"
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

	// Validate production security settings (blocking)
	if err := config.ValidateProductionConfig(cfg, log); err != nil {
		log.Fatal("Production security validation failed", zap.Error(err))
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
	router.Use(middleware.SecurityHeadersForEnv(cfg.IsProduction()))
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
	router.Use(api.StandardVersionMiddleware())

	// Resolve the tenant for every request and attach it to the request
	// context (v1.7.0 #2). Resolution at this point in the chain runs
	// before route-level auth, so it sees the gateway-set X-Org-Slug
	// header or falls back to the default org; the JWT-claim path
	// activates when resolution moves behind auth later in v1.7.0.
	// DefaultOrgFallback keeps single-tenant installs on the default
	// org — the final v1.7.0 PR flips it off.
	orgLookup := organization.NewOrgLookup(organization.NewService(db, redis, cfg, log))
	router.Use(middleware.TenantResolver(orgLookup, middleware.TenantResolverConfig{
		DefaultOrgFallback:     cfg.DefaultOrgFallback,
		DefaultOrgID:           cfg.DefaultOrgID,
		PlatformAdminPredicate: auth.SuperAdminPredicate,
		OnPlatformCrossOrg:     audit.CrossOrgAuditor(db.Pool),
	}))

	// Metrics endpoint
	router.GET("/metrics", metrics.Handler())

	// Initialize health service with database and Redis checks
	healthService := newhealth.NewHealthService(log)
	healthService.SetVersion(Version)
	healthService.RegisterCheck(newhealth.NewPostgresChecker(db))
	healthService.RegisterCheck(newhealth.NewRedisChecker(redis))

	// Register standard health check endpoints
	healthService.RegisterStandardRoutes(router, "")

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
		browzerTargetManager.SetHopConfigPath(cfg.BrowZerHopConfigPath)
		browzerTargetManager.SetHopCert(cfg.BrowZerHopCertPath, cfg.BrowZerHopKeyPath)
		_, hopPort := access.ParseHopAddr(cfg.ZitiBrowZerHopAddr)
		browzerTargetManager.SetHopPort(hopPort)
		// Public per-app vhost generation (front nginx).
		browzerTargetManager.SetVHostConfigPath(cfg.BrowZerVHostConfigPath)
		browzerTargetManager.SetBootstrapperPass(cfg.BrowZerBootstrapperAddr)
		browzerTargetManager.SetVHostSSL(cfg.BrowZerVHostSSLCert, cfg.BrowZerVHostSSLKey)
		browzerTargetManager.SetOIDCCallbacks(access.SplitCSV(cfg.BrowZerOIDCCallbackPaths))
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

	// Shared Ziti provider: the admin panel connects/reconnects/disconnects the
	// OpenZiti controller at runtime by swapping the manager held here. Wired to
	// all three services BEFORE routes are registered so the settings handlers
	// and every read site see the same provider.
	zitiProvider := access.NewZitiProvider()
	accessService.SetZitiProvider(zitiProvider)

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

	// Resolve the OpenZiti connection: persisted admin-panel settings win, else
	// env (cfg.Ziti*). Lets a box that booted disabled be connected later from
	// the panel with no restart, and vice-versa.
	bootCtx := orgctx.WithBypassRLS(context.Background())
	zCtrlURL, zUser, zPwd, zDir, zInsecure, zEnabled, zErr := access.ResolveBootZitiConn(
		bootCtx, db, cfg.EncryptionKey,
		cfg.ZitiCtrlURL, cfg.ZitiAdminUser, cfg.ZitiAdminPassword, cfg.ZitiIdentityDir,
		cfg.ZitiEnabled, cfg.ZitiInsecureSkipVerify)
	if zErr != nil {
		log.Error("Failed to resolve Ziti connection settings", zap.Error(zErr))
	}
	if zEnabled {
		log.Info("OpenZiti integration enabled, initializing ZitiManager...")
		zm, err := access.NewZitiManagerWithConn(cfg, zCtrlURL, zUser, zPwd, zDir, zInsecure, db, log)
		if err != nil {
			log.Error("Failed to initialize ZitiManager -- Ziti features disabled", zap.Error(err))
		} else {
			// Start background monitors on a context owned by the provider slot
			// so a runtime reconnect can cancel them.
			zitiCtx, zitiCancel := context.WithCancel(context.Background())
			zitiProvider.Swap(zm, zitiCancel)
			zm.StartHealthMonitor(zitiCtx)
			zm.StartCertificateMonitor(zitiCtx)
			zm.StartUserSyncPoller(zitiCtx)
			zm.StartPostureResultExpiryChecker(zitiCtx)

			// BrowZer bootstrap + bootstrapper-target/router-config generation are
			// independent of WHO hosts the Ziti services (reconciler vs imperative),
			// so they run in BOTH modes. Only imperative hosting is reconciler-gated.
			if cfg.BrowZerEnabled {
				log.Info("Bootstrapping BrowZer configuration...")
				if err := zm.BootstrapBrowZer(zitiCtx, cfg.OAuthIssuer, cfg.OAuthJWKSURL, cfg.BrowZerClientID); err != nil {
					log.Error("BrowZer bootstrap failed -- BrowZer features disabled", zap.Error(err))
				} else {
					log.Info("BrowZer bootstrap complete")
				}
			}

			writeBrowZerConfigs := func() {
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
					if err := browzerTargetManager.WriteBrowZerHopConfig(zitiCtx); err != nil {
						log.Warn("Failed to write initial BrowZer hop config", zap.Error(err))
					} else {
						log.Info("Initial BrowZer hop config generated")
					}
					if err := browzerTargetManager.WriteBrowZerVHostConfig(zitiCtx); err != nil {
						log.Warn("Failed to write initial BrowZer public vhost config", zap.Error(err))
					} else {
						log.Info("Initial BrowZer public vhost config generated")
					}
				}
			}

			if cfg.ZitiReconcilerEnabled {
				reconciler := access.NewZitiReconciler(db, log, zitiProvider, cfg.ZitiBrowZerHopAddr)
				reconciler.Start(zitiCtx)
				accessService.SetZitiReconciler(reconciler)
				// The admin-console one-click toggle must defer to the reconciler too:
				// only write proxy_routes flags, never imperatively provision Ziti.
				featureManager.SetReconcilerEnabled(true)
				log.Info("Ziti reconciler started (ZITI_RECONCILER=true); imperative hosting skipped")
				// The reconciler creates/hosts the per-app Ziti services; we still
				// (re)generate the bootstrapper targets so the browser dials them.
				go writeBrowZerConfigs()
			} else {
				// Imperative path: the access-proxy SDK hosts the services.
				zm.HostAllServices(zitiCtx)
				go func() {
					accessService.EnsureZitiServicesForRoutes(zitiCtx, zm)
					accessService.EnsureBrowZerRouterService(zitiCtx, zm)
					writeBrowZerConfigs()
				}()
			}

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

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
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
		Server:          httpServer,
		Logger:          log,
		Shutdownables:   shutdownables,
		ShutdownTimeout: 30 * time.Second,
	})

	// Start server in goroutine
	go func() {
		log.Info("Starting Access Proxy service", zap.Int("port", port))
		if err := tlsutil.ListenAndServe(httpServer, cfg.TLS, log); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for shutdown signal
	graceful.Start()
}
