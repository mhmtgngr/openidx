// Package main is the entry point for the Identity Service
// Identity Service handles authentication, session management, and SSO
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	"github.com/openidx/openidx/internal/ai"
	"github.com/openidx/openidx/internal/api"
	"github.com/openidx/openidx/internal/audit"
	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/common/tlsutil"
	"github.com/openidx/openidx/internal/common/tracing"
	"github.com/openidx/openidx/internal/directory"
	"github.com/openidx/openidx/internal/email"
	newhealth "github.com/openidx/openidx/internal/health"
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/metrics"
	"github.com/openidx/openidx/internal/migrations"
	"github.com/openidx/openidx/internal/notifications"
	"github.com/openidx/openidx/internal/organization"
	"github.com/openidx/openidx/internal/portal"
	"github.com/openidx/openidx/internal/profiling"
	"github.com/openidx/openidx/internal/revocation"
	"github.com/openidx/openidx/internal/risk"
	"github.com/openidx/openidx/internal/server"
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

	// The configured level reaches the logger built above, which had to be
	// constructed before the config existed. Without this, `log_level:` in a
	// configuration file is read into a field nothing consults.
	if err := logger.SetLevel(cfg.LogLevel); err != nil {
		log.Fatal("Invalid log level", zap.Error(err))
	}

	// Validate production security settings (blocking)
	if err := config.ValidateProductionConfig(cfg, log); err != nil {
		log.Fatal("Production security validation failed", zap.Error(err))
	}

	// Which availability plane this process serves. A typo is fatal: the flag
	// exists to REMOVE routes, and a process that silently served all of them
	// would hand back the isolation the deployment was split to get.
	serviceProfile, err := identity.ParseProfile(cfg.ServiceProfile)
	if err != nil {
		log.Fatal("Invalid SERVICE_PROFILE", zap.Error(err))
	}

	// Dark-platform: refuse to start on a public bind when a DARK_MODE tier is on
	// (a "dark" service must be reachable only over the OpenZiti overlay).
	if err := cfg.ValidateDarkModeBind(); err != nil {
		log.Fatal("Dark-mode bind validation failed", zap.Error(err))
	}

	cfg.LogSecurityWarnings(log)

	// Initialize tracing
	tracingCfg := tracing.ConfigFromEnv("identity-service", cfg.Environment)
	shutdownTracer, err := tracing.Init(context.Background(), tracingCfg, log)
	if err != nil {
		log.Warn("Failed to initialize tracing", zap.Error(err))
	}

	// Initialize database connection
	// Tenant scope transport (global-scale plan task 2.1): RLS_MODE=local makes
	// the scope transaction-local (SET LOCAL) so a transaction pooler can
	// multiplex safely; the default "session" is today's checkout stamping.
	database.SetRLSMode(database.ParseRLSMode(cfg.RLSMode))

	db, err := database.NewPostgres(cfg.DatabaseURL, database.PostgresTLSConfig{
		SSLMode:     cfg.DatabaseSSLMode,
		SSLRootCert: cfg.DatabaseSSLRootCert,
		SSLCert:     cfg.DatabaseSSLCert,
		SSLKey:      cfg.DatabaseSSLKey,
	})
	if err != nil {
		log.Fatal("Failed to connect to database", zap.Error(err))
	}

	// Run auto-migrations if enabled
	if cfg.AutoMigrate {
		log.Info("Running auto-migrations")
		migrations.MustAutoMigrate(context.Background(), db.Pool.Raw(), log)
	}

	// The seed migration ships admin@openidx.local with a published default
	// password. ValidateProductionConfig cannot see database state, so this
	// runs after migrations: production refuses to serve while it still works.
	if cfg.IsProduction() {
		if err := identity.EnsureDefaultAdminRotated(context.Background(), db, log); err != nil {
			log.Fatal("Default-credential validation failed", zap.Error(err))
		}
	}

	// Initialize Redis connection
	// Export DB pool saturation gauges (openidx_db_connections{state=...}).
	metrics.NewTracedPool(db.Pool.Raw(), "identity-service").StartPoolStatsCollector(context.Background())

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
		RateLimitURL:       cfg.RedisRateLimitURL,
		RevocationURL:      cfg.RedisRevocationURL,
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
	// Restrict which proxy hops gin trusts when resolving the client IP from
	// X-Forwarded-For. Default trusts all proxies, making c.ClientIP() spoofable
	// (bypasses device-trust known-IP auto-approve, geo-block, spoofs audit IPs).
	middleware.ConfigureTrustedProxies(router, log)
	router.Use(gin.Recovery())
	// Both knobs are refused at startup rather than defaulted: a duration that
	// does not parse, or a cost mode spelled "enfroce", must not look like a
	// working configuration.
	admissionQueueTimeout, admissionRetryAfter, admissionErr := middleware.ParseAdmissionDurations(
		cfg.AdmissionQueueTimeout, cfg.AdmissionRetryAfter)
	if admissionErr != nil {
		log.Fatal("Invalid admission control configuration", zap.Error(admissionErr))
	}
	costMode, costModeErr := middleware.ParseCostMode(cfg.RateLimitCostMode)
	if costModeErr != nil {
		log.Fatal("Invalid RATELIMIT_COST_MODE", zap.Error(costModeErr))
	}

	// This is the one service whose plane depends on how it was started: split
	// with SERVICE_PROFILE=auth it is the ISSUE half, and everything else --
	// including the unsplit process, which still serves both -- is ADMIN. It
	// follows values.yaml's assignment for the same reason (identityService:
	// admin, because an unsplit process must not get ISSUE's tighter budgets).
	identityPlane := "admin"
	if serviceProfile == identity.ProfileAuth {
		identityPlane = "issue"
	}

	// Admission control (task 3.5): a bound on how many requests this process
	// carries AT ONCE, which is a different question from how fast they arrive.
	// Mounted this early on purpose -- a request refused here costs one channel
	// send, and everything below it (tracing, access logging, the limiter's
	// Redis round trip) is work a process that is already full cannot afford.
	// The plane name matches the database plane this service connects as
	// (values.yaml database.planeRoles.assignments), so the two halves of the
	// same design read the same in metrics. Off until an operator sizes
	// ADMISSION_MAX_INFLIGHT against the pool behind this service.
	router.Use(middleware.Admission(middleware.AdmissionConfig{
		Plane:        identityPlane,
		MaxInflight:  cfg.AdmissionMaxInflight,
		QueueTimeout: admissionQueueTimeout,
		RetryAfter:   admissionRetryAfter,
	}))
	// Body cap (bulk CSV import is the one large upload; the edge caps at 10m too); oversize is 413 before any handler runs (task 0.3).
	router.Use(middleware.MaxBodySize(10 << 20))
	router.Use(otelgin.Middleware("identity-service"))
	router.Use(middleware.SecurityHeadersForEnv(cfg.IsProduction()))
	router.Use(logger.GinMiddleware(log))
	if cfg.EnableRateLimit {
		router.Use(middleware.DistributedRateLimit(redis.RateLimitDB(), middleware.RateLimitConfig{
			Requests:     cfg.RateLimitRequests,
			Window:       time.Duration(cfg.RateLimitWindow) * time.Second,
			AuthRequests: cfg.RateLimitAuthRequests,
			AuthWindow:   time.Duration(cfg.RateLimitAuthWindow) * time.Second,
			PerUser:      cfg.RateLimitPerUser,
			// Ride out a Redis restart/failover on a bounded local counter
			// before failing closed (task 0.7).
			LocalFallbackMax: time.Duration(cfg.RateLimitLocalFallbackMax) * time.Second,
			ReplicaCountHint: cfg.RateLimitReplicaHint,
		}, log))
	}
	// Use new Prometheus metrics middleware
	router.Use(metrics.Middleware("identity-service"))

	// Metrics endpoint
	router.GET("/metrics", metrics.Handler())

	// Register pprof endpoints in development mode
	profiling.RegisterWithEngine(router, cfg.IsDevelopment())

	// API versioning middleware
	router.Use(api.StandardVersionMiddleware())

	// Resolve the tenant for every request and attach it to the request
	// context (v1.7.0 #2). Mounted globally, this runs BEFORE route-level
	// auth, so it resolves from the gateway-set X-Org-Slug header or the
	// default-org fallback and nothing else: the JWT-claim path and the
	// platform-admin X-Org-ID path both read roles/claims out of the gin
	// context, which auth has not filled in yet.
	//
	// The predicate and the audit hook are still wired, deliberately. They
	// cost nothing while the ordering makes them unreachable, and if this
	// mount ever moves behind auth they are what keeps a cross-org access
	// from happening without the mandatory audit row. Logger reports the
	// mismatch if a caller actually sends X-Org-ID here, so it stops being
	// an invisible no-op — it was one for a full release.
	//
	// cmd/admin-api mounts the same middleware on its authenticated
	// /api/v1 group; that is where the platform-admin path is live, and
	// test/integration/cross_org_test.go asserts both sides.
	//
	// DefaultOrgFallback keeps single-tenant installs on the default
	// org — the final v1.7.0 PR flips it off.
	orgLookup := organization.NewOrgLookup(organization.NewService(db, redis, cfg, log))
	router.Use(middleware.TenantResolver(orgLookup, middleware.TenantResolverConfig{
		DefaultOrgFallback:     cfg.DefaultOrgFallback,
		DefaultOrgID:           cfg.DefaultOrgID,
		PlatformAdminPredicate: auth.SuperAdminPredicate,
		OnPlatformCrossOrg:     audit.CrossOrgAuditor(db.Pool, log),
		Logger:                 log,
	}))

	// Per-tenant request-cost budget (task 3.5). Mounted AFTER the tenant
	// resolver, which is not a matter of taste: the budget is per tenant, and
	// before the resolver every request falls into the unattributed "_" bucket,
	// so one tenant's flood would shed every other tenant's expensive work --
	// the exact failure the budget exists to prevent. Off by default.
	router.Use(middleware.TenantCostLimit(redis.RateLimitDB(), middleware.CostConfig{
		Mode:   costMode,
		Budget: cfg.RateLimitCostBudget,
		Window: time.Duration(cfg.RateLimitCostWindow) * time.Second,
	}, log))

	// Initialize directory service for LDAP sync
	dirService := directory.NewService(db, log)
	if redis != nil {
		dirService.SetRedis(redis.Client) // leader-gate the sync tick across replicas
		// And cut the tokens of anyone a sync deprovisions. The sync engine
		// holds a database handle and a logger; the marker belongs in the
		// REVOCATION Redis, which is why the callback is built here, where the
		// three roles are already distinguished, rather than by handing the
		// engine a client and hoping it picks the right one.
		dirService.SetRevoker(revocation.Revoker(redis.RevocationDB(), log))
	}
	if err := dirService.Start(context.Background()); err != nil {
		log.Error("Directory service failed to start", zap.Error(err))
	}

	// Initialize email service
	emailService := email.NewService(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom, redis, log)

	// Initialize webhook service
	webhookSecretCipher, err := secretcrypt.New(cfg.EncryptionKey)
	if err != nil {
		log.Warn("webhook signing secrets will NOT be encrypted at rest; set a 32-byte ENCRYPTION_KEY to enable", zap.Error(err))
		webhookSecretCipher = secretcrypt.NewNoop()
	}
	webhookService := webhooks.NewService(db, redis, log, webhookSecretCipher)

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
		VerimorUsername:    cfg.SMS.VerimorUsername,
		VerimorPassword:    cfg.SMS.VerimorPassword,
		VerimorSourceAddr:  cfg.SMS.VerimorSourceAddr,
		TurkcellUsername:   cfg.SMS.TurkcellUsername,
		TurkcellPassword:   cfg.SMS.TurkcellPassword,
		TurkcellSender:     cfg.SMS.TurkcellSender,
		VodafoneAPIKey:     cfg.SMS.VodafoneAPIKey,
		VodafoneSecret:     cfg.SMS.VodafoneSecret,
		VodafoneSender:     cfg.SMS.VodafoneSender,
		TurkTelekomAPIKey:  cfg.SMS.TurkTelekomAPIKey,
		TurkTelekomSecret:  cfg.SMS.TurkTelekomSecret,
		TurkTelekomSender:  cfg.SMS.TurkTelekomSender,
		MutlucellUsername:  cfg.SMS.MutlucellUsername,
		MutlucellPassword:  cfg.SMS.MutlucellPassword,
		MutlucellAPIKey:    cfg.SMS.MutlucellAPIKey,
		MutlucellSender:    cfg.SMS.MutlucellSender,
	}
	// The mock provider delivers nothing, so outside development it counts as
	// not configured rather than as a provider — otherwise SMS_ENABLED=true
	// alone yields an enrollable factor that says "code sent" and sends
	// nothing (see sms.ErrMockProviderNotAllowed).
	smsConfig.AllowMock = cfg.IsDevelopment()
	// A broken SMS config (e.g. a typo'd provider name) leaves the factor
	// unwired: the identity service then answers SMS MFA requests with 501
	// "not configured" instead of pretending via a fallback mock.
	smsService, err := sms.NewService(smsConfig, log)
	if err != nil {
		log.Error("Failed to initialize SMS service; SMS MFA will refuse until fixed", zap.Error(err))
		smsService = nil
	}

	// Start background workers
	bgCtx, cancelWorkers := context.WithCancel(context.Background())
	go emailService.ProcessQueue(bgCtx)
	go webhookService.ProcessDeliveries(bgCtx)
	go webhookService.ProcessRetries(bgCtx)

	// Initialize identity service
	identityService := identity.NewService(db, redis, cfg, log)
	identityService.SetDirectoryService(dirService)
	identityService.SetEmailService(emailService)
	identityService.SetWebhookService(webhookService)
	identityService.SetAnomalyDetector(&anomalyDetectorAdapter{riskService: riskService})
	identityService.SetRiskService(riskService)
	// Guarded: assigning a nil *sms.Service through the interface would make
	// the provider non-nil (a nil-wrapping interface) and defeat the
	// not-configured gate.
	if smsService != nil {
		identityService.SetSMSProvider(smsService)
	}

	// THE SMS WATCHER RUNS IN EVERY PROFILE, and that is not an oversight.
	// It reads one system_settings row and writes nothing: the tick swaps THIS
	// process's own SMS provider, so a pod that skipped it would keep sending
	// codes through a provider an admin has already replaced. The auth half is
	// the one sending MFA codes during login, so it is the last pod that should
	// miss the swap. internal/common/leader's sweeps census records it as
	// per-process for the same reason.
	go identityService.StartSMSConfigWatcher(bgCtx, 30*time.Second)

	// THE ROLE-EXPIRY SWEEP IS ADMIN-PLANE WORK, so the ISSUE half does not run
	// it. It deletes expired time-bound assignments across every org and cuts
	// the tokens still carrying them -- nothing about it belongs to a login.
	//
	// It is leader-gated, so the cost was already one replica per minute
	// cluster-wide, and today an auth pod winning that election is harmless:
	// values.yaml assigns BOTH halves the `admin` database role. What this
	// guards is the move that file already names as next -- the auth half to
	// the `issue` role, whose statement_timeout is sized for a login query, not
	// for a DELETE across every org. Elected onto an ISSUE pod after that move,
	// this sweep would start failing every tick it won. Gating it now means the
	// election only ever happens among pods that can do the work.
	//
	// The unsplit process is ProfileAll, which serves ADMIN, so a default
	// install is unchanged.
	if serviceProfile.ServesAdmin() {
		identityService.StartRoleExpirationChecker(bgCtx)
	} else {
		log.Info("role expiration sweep not started: this process serves the ISSUE plane only",
			zap.String("service_profile", string(serviceProfile)),
			zap.String("runs_in", "the SERVICE_PROFILE=admin half"))
	}

	// Initialize portal service (with the optional local AI client for
	// plain-language security insights; template output when disabled)
	portalService := portal.NewService(db, log,
		portal.WithShowAllAppsWhenUnassigned(cfg.ShowAllAppsWhenUnassigned))
	portalService.SetAIClient(ai.NewClient(cfg, log))

	// Initialize notification service
	notifService := notifications.NewService(db, log)
	notifService.SetNtfy(notifications.NtfyConfig{
		BaseURL: cfg.NtfyBaseURL, Token: cfg.NtfyToken, TopicSecret: cfg.NtfyTopicSecret,
	})

	// Register routes for this process's plane. SERVICE_PROFILE=auth serves the
	// ISSUE plane (the login surface and the caller's own authentication
	// factors); SERVICE_PROFILE=admin serves the ADMIN plane, which is the
	// first plane shed under load. Unset is "all" -- every route, exactly as
	// before the split (global-scale plan task 3.4).
	skipped := identity.RegisterRoutesForProfile(router, identityService, serviceProfile)
	log.Info("Identity routes registered",
		zap.String("service_profile", string(serviceProfile)),
		zap.Int("routes_skipped", len(skipped)),
	)

	// The portal and notification groups are console surfaces: they answer a
	// signed-in user, not a login in progress, so they belong to ADMIN.
	if serviceProfile.ServesAdmin() {
		// Portal and notification routes need auth middleware to identify the caller
		portalGroup := router.Group("/api/v1/identity")
		portalGroup.Use(middleware.SoftAuth(cfg.OAuthJWKSURL))
		portal.RegisterRoutes(portalGroup, portalService)

		notifGroup := router.Group("/api/v1/identity")
		notifGroup.Use(middleware.SoftAuth(cfg.OAuthJWKSURL))
		notifications.RegisterRoutes(notifGroup, notifService)
	}

	// Initialize health service with database and Redis checks
	healthService := newhealth.NewHealthService(log)
	healthService.SetVersion(Version)
	healthService.RegisterCheck(newhealth.NewPostgresChecker(db))
	healthService.RegisterCheck(newhealth.NewReadReplicaChecker(db))
	healthService.RegisterCheck(newhealth.NewRedisChecker(redis))
	// An expiring TLS certificate is a scheduled outage; the health endpoint
	// says so weeks ahead when the service serves TLS from a file.
	newhealth.RegisterCertCheck(healthService, cfg.TLS.Enabled, cfg.TLS.CertFile)

	// Register standard health check endpoints (/health, /health/ready, /health/live)
	healthService.RegisterStandardRoutes(router, "")

	// Keep legacy /ready endpoint for backward compatibility
	router.GET("/ready", healthService.ReadyHandler())

	// Create HTTP server
	// Hardened listener: ReadHeaderTimeout 5s, 16 KiB header cap and 100 HTTP/2
	// streams per connection come from server.NewHTTP and cannot be disabled
	// here (global-scale plan task 0.3).
	httpServer := server.NewHTTP(server.HTTPOptions{
		Addr:         cfg.ListenAddr(),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	})

	// Setup graceful shutdown manager with all components
	shutdownables := []server.Shutdownable{
		server.CloseDB(db),
		server.CloseRedis(redis),
		server.CancelContext(cancelWorkers),
		server.NewShutdownFunc("directory", func(ctx context.Context) error {
			dirService.Stop()
			return nil
		}),
	}
	if shutdownTracer != nil {
		shutdownables = append(shutdownables, server.CloseTracer(shutdownTracer))
	}

	graceful := server.New(server.Config{
		Server:          httpServer,
		Logger:          log,
		Shutdownables:   shutdownables,
		ShutdownTimeout: cfg.ShutdownTimeout(),
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
