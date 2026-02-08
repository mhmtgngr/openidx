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
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/access"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/common/middleware"
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

	// Health check endpoint
	router.GET("/access/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "access-service",
			"version": Version,
		})
	})

	// Also respond on /health for Docker healthcheck
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "access-service",
			"version": Version,
		})
	})

	// Readiness check endpoint
	router.GET("/access/ready", func(c *gin.Context) {
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

	// Initialize access proxy service
	accessService := access.NewService(db, redis, cfg, log)

	// Background context for long-running goroutines
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()

	// Initialize BrowZer Target Manager for dynamic bootstrapper config
	var browzerTargetManager *access.BrowZerTargetManager
	if cfg.BrowZerTargetsPath != "" {
		browzerTargetManager = access.NewBrowZerTargetManager(db, log, cfg.BrowZerTargetsPath)
		accessService.SetBrowZerTargetManager(browzerTargetManager)
		log.Info("BrowZer Target Manager initialized", zap.String("path", cfg.BrowZerTargetsPath))
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
			// After that completes, generate initial BrowZer targets file
			go func() {
				accessService.EnsureZitiServicesForRoutes(zitiCtx, zm)
				if browzerTargetManager != nil {
					if err := browzerTargetManager.WriteBrowZerTargets(zitiCtx); err != nil {
						log.Warn("Failed to write initial BrowZer targets", zap.Error(err))
					} else {
						log.Info("Initial BrowZer targets file generated")
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
