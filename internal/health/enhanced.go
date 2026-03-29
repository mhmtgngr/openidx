// Package health provides enhanced health check endpoints with comprehensive system status monitoring
package health

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// EnhancedHealthResponse provides comprehensive health status with all system checks
type EnhancedHealthResponse struct {
	Status       string                    `json:"status"`       // healthy, degraded, unhealthy
	Timestamp    string                    `json:"timestamp"`
	Version      string                    `json:"version,omitempty"`
	Uptime       string                    `json:"uptime"`
	Checks       map[string]CheckResult    `json:"checks"`
	System       *SystemInfo               `json:"system,omitempty"`
	CheckedAt    string                    `json:"checked_at"`
}

// CheckResult represents the result of a single health check
type CheckResult struct {
	Status      string                 `json:"status"`      // ok, warning, critical
	LatencyMs   float64                `json:"latency_ms"`
	Message     string                 `json:"message,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Critical    bool                   `json:"critical"`
	CheckedAt   string                 `json:"checked_at"`
}

// SystemInfo provides system resource information
type SystemInfo struct {
	Goroutines   int         `json:"goroutines"`
	Memory       *MemInfo    `json:"memory,omitempty"`
	Connections  *ConnInfo   `json:"connections,omitempty"`
	Certificates []*CertInfo `json:"certificates,omitempty"`
}

// MemInfo provides memory usage information
type MemInfo struct {
	AllocMB       uint64  `json:"alloc_mb"`
	TotalAllocMB  uint64  `json:"total_alloc_mb"`
	SysMB         uint64  `json:"sys_mb"`
	NumGC         uint32  `json:"num_gc"`
	HeapObjects   uint64  `json:"heap_objects"`
	StackInUseMB  uint64  `json:"stack_in_use_mb"`
	GCPauseTotalMs uint64 `json:"gc_pause_total_ms"`
}

// ConnInfo provides database connection information
type ConnInfo struct {
	DBTotal      int32   `json:"db_total"`
	DBIdle       int32   `json:"db_idle"`
	DBAcquired   int64   `json:"db_acquired"`
	RedisConnected bool  `json:"redis_connected"`
}

// CertInfo provides certificate expiration information
type CertInfo struct {
	Path          string `json:"path,omitempty"`
	Subject       string `json:"subject,omitempty"`
	Issuer        string `json:"issuer,omitempty"`
	ExpiresAt     string `json:"expires_at"`
	DaysRemaining int    `json:"days_remaining"`
	Status        string `json:"status"` // valid, expiring_soon, expired
}

// EnhancedHealthService provides comprehensive health monitoring
type EnhancedHealthService struct {
	checkers     []HealthChecker
	logger       *zap.Logger
	startTime    time.Time
	version      string
	db           *pgxpool.Pool
	redis        *redis.Client
	elasticsearch *database.ElasticsearchClient
	certPaths    []string
	mu           sync.RWMutex
}

// NewEnhancedHealthService creates a new enhanced health service
func NewEnhancedHealthService(logger *zap.Logger) *EnhancedHealthService {
	return &EnhancedHealthService{
		checkers:  make([]HealthChecker, 0),
		logger:    logger.With(zap.String("component", "enhanced_health")),
		startTime: time.Now(),
	}
}

// SetVersion sets the application version
func (h *EnhancedHealthService) SetVersion(version string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.version = version
}

// SetDatabase sets the PostgreSQL connection for enhanced checks
func (h *EnhancedHealthService) SetDatabase(db *database.PostgresDB) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.db = db.Pool
}

// SetRedis sets the Redis connection for enhanced checks
func (h *EnhancedHealthService) SetRedis(redis *database.RedisClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.redis = redis.Client
}

// SetElasticsearch sets the Elasticsearch connection for enhanced checks
func (h *EnhancedHealthService) SetElasticsearch(es *database.ElasticsearchClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.elasticsearch = es
}

// SetCertPaths sets paths to TLS certificates to monitor for expiration
func (h *EnhancedHealthService) SetCertPaths(paths []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.certPaths = paths
}

// RegisterCheck registers a custom health checker
func (h *EnhancedHealthService) RegisterCheck(checker HealthChecker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checkers = append(h.checkers, checker)
	h.logger.Info("Registered enhanced health checker",
		zap.String("name", checker.Name()),
		zap.Bool("critical", checker.IsCritical()))
}

// Check performs all health checks and returns comprehensive status
func (h *EnhancedHealthService) Check(ctx context.Context) *EnhancedHealthResponse {
	h.mu.RLock()
	checkers := make([]HealthChecker, len(h.checkers))
	copy(checkers, h.checkers)
	db := h.db
	redisClient := h.redis
	es := h.elasticsearch
	certPaths := h.certPaths
	version := h.version
	h.mu.RUnlock()

	checks := make(map[string]CheckResult)
	overallStatus := "ok" // ok, warning, critical

	// Run built-in checks
	if db != nil {
		dbCheck := h.checkDatabase(ctx)
		checks["database"] = dbCheck
		if dbCheck.Status == "critical" {
			overallStatus = "critical"
		} else if dbCheck.Status == "warning" && overallStatus == "ok" {
			overallStatus = "warning"
		}
	}

	if redisClient != nil {
		redisCheck := h.checkRedis(ctx)
		checks["redis"] = redisCheck
		if redisCheck.Status == "critical" && overallStatus != "critical" {
			overallStatus = "warning" // Redis is non-critical (cache)
		} else if redisCheck.Status == "warning" && overallStatus == "ok" {
			overallStatus = "warning"
		}
	}

	if es != nil {
		esCheck := h.checkElasticsearch(ctx)
		checks["elasticsearch"] = esCheck
		if esCheck.Status == "warning" && overallStatus == "ok" {
			overallStatus = "warning"
		}
	}

	// Check system resources
	sysCheck := h.checkSystemResources()
	checks["system"] = sysCheck
	if sysCheck.Status == "critical" {
		overallStatus = "critical"
	} else if sysCheck.Status == "warning" && overallStatus == "ok" {
		overallStatus = "warning"
	}

	// Run registered custom checkers
	type result struct {
		name  string
		check ComponentStatus
		critical bool
	}
	results := make(chan result, len(checkers))

	for _, checker := range checkers {
		go func(c HealthChecker) {
			checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			cStatus := c.Check(checkCtx)
			results <- result{
				name:     c.Name(),
				check:    cStatus,
				critical: c.IsCritical(),
			}
		}(checker)
	}

	for i := 0; i < len(checkers); i++ {
		r := <-results
		// Convert ComponentStatus to CheckResult
		checkResult := CheckResult{
			Status:    r.check.Status,
			LatencyMs: r.check.LatencyMS,
			Message:   r.check.Details,
			Critical:  r.critical,
			CheckedAt: r.check.CheckedAt,
		}
		checks[r.name] = checkResult

		if r.critical && r.check.Status == "down" {
			overallStatus = "critical"
		} else if r.check.Status == "degraded" && overallStatus == "ok" {
			overallStatus = "warning"
		} else if r.check.Status == "down" && overallStatus != "critical" {
			overallStatus = "warning"
		}
	}

	// Gather system info
	systemInfo := h.gatherSystemInfo(db, redisClient, certPaths)

	// Map status to response format
	responseStatus := "healthy"
	if overallStatus == "warning" {
		responseStatus = "degraded"
	} else if overallStatus == "critical" {
		responseStatus = "unhealthy"
	}

	return &EnhancedHealthResponse{
		Status:    responseStatus,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   version,
		Uptime:    formatDuration(time.Since(h.startTime)),
		Checks:    checks,
		System:    systemInfo,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// checkDatabase performs a comprehensive database health check
func (h *EnhancedHealthService) checkDatabase(ctx context.Context) CheckResult {
	start := time.Now()

	// Test basic connectivity with query
	var one int
	err := h.db.QueryRow(ctx, "SELECT 1").Scan(&one)
	latency := time.Since(start)

	if err != nil {
		return CheckResult{
			Status:    "critical",
			LatencyMs: float64(latency.Milliseconds()),
			Message:   fmt.Sprintf("database query failed: %v", err),
			Critical:  true,
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	// Get connection pool stats
	stats := h.db.Stat()
	details := map[string]interface{}{
		"total_connections": int(stats.TotalConns()),
		"idle_connections":  int(stats.IdleConns()),
		"acquire_count":     int(stats.AcquireCount()),
		"acquire_duration_ms": stats.AcquireDuration().Milliseconds(),
		"max_connections":    int(stats.MaxConns()),
	}

	// Check for connection pool exhaustion
	maxConns := stats.MaxConns()
	if maxConns > 0 {
		usagePercent := float64(stats.TotalConns()) / float64(maxConns) * 100
		details["usage_percent"] = fmt.Sprintf("%.1f%%", usagePercent)
	}

	status := "ok"
	message := "database is healthy"

	if latency > 500*time.Millisecond {
		status = "warning"
		message = "high database latency"
		details["latency_warning"] = "true"
	}

	if maxConns > 0 && stats.TotalConns() > 0 {
		usagePercent := float64(stats.TotalConns()) / float64(maxConns) * 100
		if usagePercent > 90 {
			status = "warning"
			message = "connection pool near capacity"
			details["pool_warning"] = "near capacity"
		}
	}

	return CheckResult{
		Status:    status,
		LatencyMs: float64(latency.Milliseconds()),
		Message:   message,
		Details:   details,
		Critical:  true,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// checkRedis performs a comprehensive Redis health check
func (h *EnhancedHealthService) checkRedis(ctx context.Context) CheckResult {
	start := time.Now()

	// Test with PING
	pong, err := h.redis.Ping(ctx).Result()
	latency := time.Since(start)

	if err != nil {
		return CheckResult{
			Status:    "critical",
			LatencyMs: float64(latency.Milliseconds()),
			Message:   fmt.Sprintf("redis ping failed: %v", err),
			Critical:  false, // Redis is often a cache, fail gracefully
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	details := map[string]interface{}{
		"ping_response": pong,
		"connected":     true,
	}

	status := "ok"
	message := "redis is healthy"

	if latency > 200*time.Millisecond {
		status = "warning"
		message = "high redis latency"
	}

	return CheckResult{
		Status:    status,
		LatencyMs: float64(latency.Milliseconds()),
		Message:   message,
		Details:   details,
		Critical:  false,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// checkElasticsearch performs Elasticsearch cluster health check
func (h *EnhancedHealthService) checkElasticsearch(ctx context.Context) CheckResult {
	start := time.Now()

	// Use ES client's Ping
	res, err := h.elasticsearch.Client.Ping(
		h.elasticsearch.Client.Ping.WithContext(ctx),
	)
	latency := time.Since(start)

	if err != nil || res.IsError() {
		status := "warning" // ES is often optional
		msg := "elasticsearch ping failed"
		if err != nil {
			msg = fmt.Sprintf("%s: %v", msg, err)
		} else {
			msg = fmt.Sprintf("%s: %s", msg, res.Status())
		}
		if res != nil {
			res.Body.Close()
		}
		return CheckResult{
			Status:    status,
			LatencyMs: float64(latency.Milliseconds()),
			Message:   msg,
			Critical:  false,
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}
	defer res.Body.Close()

	details := map[string]interface{}{
		"connected": true,
		"url":       h.elasticsearch.URL,
	}

	status := "ok"
	message := "elasticsearch is healthy"

	if latency > 500*time.Millisecond {
		status = "warning"
		message = "high elasticsearch latency"
	}

	return CheckResult{
		Status:    status,
		LatencyMs: float64(latency.Milliseconds()),
		Message:   message,
		Details:   details,
		Critical:  false,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// checkSystemResources performs system resource health checks
func (h *EnhancedHealthService) checkSystemResources() CheckResult {
	start := time.Now()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	details := map[string]interface{}{
		"goroutines": runtime.NumGoroutine(),
		"alloc_mb":   m.Alloc / 1024 / 1024,
		"sys_mb":     m.Sys / 1024 / 1024,
		"num_gc":     m.NumGC,
	}

	status := "ok"
	message := "system resources healthy"

	// Check goroutine count (potential goroutine leak)
	goroutineCount := runtime.NumGoroutine()
	if goroutineCount > 10000 {
		status = "critical"
		message = fmt.Sprintf("excessive goroutine count: %d", goroutineCount)
		details["goroutine_warning"] = "excessive"
	} else if goroutineCount > 5000 {
		status = "warning"
		message = fmt.Sprintf("high goroutine count: %d", goroutineCount)
		details["goroutine_warning"] = "high"
	}

	latency := time.Since(start)

	return CheckResult{
		Status:    status,
		LatencyMs: float64(latency.Milliseconds()),
		Message:   message,
		Details:   details,
		Critical:  false,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// gatherSystemInfo collects comprehensive system information
func (h *EnhancedHealthService) gatherSystemInfo(db *pgxpool.Pool, redisClient *redis.Client, certPaths []string) *SystemInfo {
	sysInfo := &SystemInfo{
		Goroutines: runtime.NumGoroutine(),
		Memory:     gatherMemoryInfo(),
	}

	// Gather connection info
	if db != nil || redisClient != nil {
		sysInfo.Connections = gatherConnectionInfo(db, redisClient)
	}

	// Check certificate expiration if paths provided
	if len(certPaths) > 0 {
		sysInfo.Certificates = checkCerts(certPaths, h.logger)
	}

	return sysInfo
}

// gatherMemoryInfo collects memory usage statistics
func gatherMemoryInfo() *MemInfo {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	info := &MemInfo{
		AllocMB:       m.Alloc / 1024 / 1024,
		TotalAllocMB:  m.TotalAlloc / 1024 / 1024,
		SysMB:         m.Sys / 1024 / 1024,
		NumGC:         m.NumGC,
		HeapObjects:   m.HeapObjects,
		StackInUseMB:  m.StackInuse / 1024 / 1024,
		GCPauseTotalMs: m.PauseTotalNs / 1000000,
	}

	return info
}

// gatherConnectionInfo collects database/redis connection information
func gatherConnectionInfo(db *pgxpool.Pool, redisClient *redis.Client) *ConnInfo {
	info := &ConnInfo{
		RedisConnected: false,
	}

	if db != nil {
		stats := db.Stat()
		info.DBTotal = int32(stats.TotalConns())
		info.DBIdle = int32(stats.IdleConns())
		info.DBAcquired = stats.AcquireCount()
	}

	if redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := redisClient.Ping(ctx).Err()
		info.RedisConnected = (err == nil)
	}

	return info
}

// checkCerts validates certificate expiration
func checkCerts(paths []string, logger *zap.Logger) []*CertInfo {
	certs := make([]*CertInfo, 0, len(paths))

	for _, path := range paths {
		certInfo := checkSingleCert(path, logger)
		if certInfo != nil {
			certs = append(certs, certInfo)
		}
	}

	return certs
}

// checkSingleCert checks a single certificate file for expiration
func checkSingleCert(certPath string, logger *zap.Logger) *CertInfo {
	// Read certificate file
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		logger.Warn("Failed to read certificate file",
			zap.String("path", certPath),
			zap.Error(err))
		return nil
	}

	certInfo, err := parseCertificate(certPEM)
	if err != nil {
		logger.Warn("Failed to parse certificate",
			zap.String("path", certPath),
			zap.Error(err))
		return nil
	}

	certInfo.Path = certPath
	return certInfo
}

// parseCertificate parses a PEM-encoded certificate and returns expiration info
func parseCertificate(certPEM []byte) (*CertInfo, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	now := time.Now()
	daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)

	status := "valid"
	if daysRemaining <= 0 {
		status = "expired"
	} else if daysRemaining <= 30 {
		status = "expiring_soon"
	}

	return &CertInfo{
		Subject:       cert.Subject.CommonName,
		Issuer:        cert.Issuer.CommonName,
		ExpiresAt:     cert.NotAfter.UTC().Format(time.RFC3339),
		DaysRemaining: daysRemaining,
		Status:        status,
	}, nil
}

// Handler returns the full enhanced health check handler for Gin
func (h *EnhancedHealthService) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		resp := h.Check(c.Request.Context())

		if resp.Status == "unhealthy" {
			c.JSON(http.StatusServiceUnavailable, resp)
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

// ReadyHandler returns the readiness probe handler for Kubernetes
func (h *EnhancedHealthService) ReadyHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		resp := h.Check(c.Request.Context())

		// Check if any critical component is critical (down)
		for name, check := range resp.Checks {
			if check.Critical && check.Status == "critical" {
				c.JSON(http.StatusServiceUnavailable, gin.H{
					"status": "not ready",
					"reason": fmt.Sprintf("critical component %s is not healthy", name),
				})
				return
			}
		}

		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	}
}

// LiveHandler returns the liveness probe handler for Kubernetes
func (h *EnhancedHealthService) LiveHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "alive",
			"uptime": formatDuration(time.Since(h.startTime)),
		})
	}
}

// RegisterStandardRoutes registers the standard health endpoints
func (h *EnhancedHealthService) RegisterStandardRoutes(router *gin.Engine, prefix string) {
	if prefix == "" {
		prefix = "/health"
	}
	router.GET(prefix, h.Handler())
	router.GET(prefix+"/ready", h.ReadyHandler())
	router.GET(prefix+"/live", h.LiveHandler())
}
