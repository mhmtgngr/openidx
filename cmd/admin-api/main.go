// Package main is the entry point for the Admin API
// Admin API provides the REST API for the Admin Console
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/admin"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/directory"
	"github.com/openidx/openidx/internal/risk"
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

	db, err := database.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer db.Close()

	redis, err := database.NewRedis(cfg.RedisURL)
	if err != nil {
		log.Fatal("Failed to connect to Redis", zap.Error(err))
	}
	defer redis.Close()

	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(logger.GinMiddleware(log))
	router.Use(middleware.CORS("http://localhost:3000", "http://localhost:5173"))
	router.Use(middleware.RequestID())
	router.Use(middleware.PrometheusMetrics("admin-api"))

	// Metrics endpoint
	router.GET("/metrics", middleware.MetricsHandler())

	// Public routes
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "admin-api",
			"version": Version,
		})
	})

	router.GET("/ready", func(c *gin.Context) {
		if err := db.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not ready", "error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	// Initialize directory service
	dirService := directory.NewService(db, log)
	if err := dirService.Start(context.Background()); err != nil {
		log.Error("Directory service failed to start", zap.Error(err))
	}
	defer dirService.Stop()

	// Initialize risk service (conditional access)
	riskService := risk.NewService(db, redis, log)

	// Initialize admin service
	adminService := admin.NewService(db, redis, cfg, log)
	adminService.SetDirectoryService(&directorySyncAdapter{dirService: dirService})
	adminService.SetRiskService(&riskServiceAdapter{riskService: riskService})

	// API v1 routes
	v1 := router.Group("/api/v1")
	if cfg.Environment != "development" {
		v1.Use(middleware.Auth(cfg.OAuthJWKSURL))
	}
	{
		admin.RegisterRoutes(v1, adminService)
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Info("Server listening", zap.Int("port", cfg.Port))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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

// directorySyncAdapter adapts directory.Service to admin.DirectorySyncer interface
type directorySyncAdapter struct {
	dirService *directory.Service
}

func (a *directorySyncAdapter) TestConnection(ctx context.Context, cfg interface{}) error {
	// Convert interface{} config to directory.LDAPConfig
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	var ldapCfg directory.LDAPConfig
	if err := json.Unmarshal(cfgBytes, &ldapCfg); err != nil {
		return fmt.Errorf("invalid LDAP config: %w", err)
	}
	return a.dirService.TestConnection(ctx, ldapCfg)
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
