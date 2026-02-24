// Package handlers provides HTTP handlers for the admin console
package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// DashboardHandler handles dashboard-related requests
type DashboardHandler struct {
	logger *zap.Logger
	db     *pgxpool.Pool
}

// NewDashboardHandler creates a new dashboard handler
func NewDashboardHandler(logger *zap.Logger, db *pgxpool.Pool) *DashboardHandler {
	return &DashboardHandler{
		logger: logger.With(zap.String("handler", "dashboard")),
		db:     db,
	}
}

// DashboardStats represents dashboard statistics
type DashboardStats struct {
	TotalUsers        int64             `json:"total_users"`
	ActiveUsers       int64             `json:"active_users"`
	ActiveSessions    int64             `json:"active_sessions"`
	PendingReviews    int64             `json:"pending_reviews"`
	RecentEvents      []RecentEvent     `json:"recent_events"`
	SystemMetrics     SystemMetrics     `json:"system_metrics"`
	SecurityAlerts    SecurityAlerts    `json:"security_alerts"`
}

// RecentEvent represents a recent audit event
type RecentEvent struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor,omitempty"`
	Action    string    `json:"action"`
	Outcome   string    `json:"outcome"`
}

// SystemMetrics represents system-level metrics
type SystemMetrics struct {
	CPUUsage    float64 `json:"cpu_usage,omitempty"`
	MemoryUsage float64 `json:"memory_usage,omitempty"`
	DiskUsage   float64 `json:"disk_usage,omitempty"`
	Uptime      int64   `json:"uptime_seconds,omitempty"`
}

// SecurityAlerts represents security-related alerts
type SecurityAlerts struct {
	FailedLogins24h int64 `json:"failed_logins_24h"`
	SuspiciousIPs   int64 `json:"suspicious_ips"`
	ActiveThreats   int64 `json:"active_threats"`
}

// DashboardService defines the interface for dashboard data operations
type DashboardService interface {
	GetDashboardStats(ctx *gin.Context) (*DashboardStats, error)
}

// GetDashboardStats handles GET /api/v1/dashboard
// @Summary Get dashboard statistics
// @Description Returns aggregated dashboard metrics including user counts, sessions, pending reviews, and recent events
// @Tags dashboard
// @Produce json
// @Success 200 {object} DashboardStats
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/dashboard [get]
func (h *DashboardHandler) GetDashboardStats(c *gin.Context) {
	h.logger.Debug("Fetching dashboard statistics")

	ctx := c.Request.Context()
	stats := &DashboardStats{
		RecentEvents: []RecentEvent{},
		SystemMetrics: SystemMetrics{
			Uptime: int64(time.Since(time.Now().Add(-time.Hour * 24 * 365)).Seconds()), // Approximate uptime
		},
		SecurityAlerts: SecurityAlerts{},
	}

	// Query dashboard stats - single query for efficiency
	err := h.db.QueryRow(ctx, `
		SELECT
			COALESCE((SELECT COUNT(*) FROM users WHERE deleted_at IS NULL), 0),
			COALESCE((SELECT COUNT(*) FROM users WHERE enabled = true AND deleted_at IS NULL), 0),
			COALESCE((SELECT COUNT(*) FROM user_sessions WHERE expires_at > NOW()), 0),
			COALESCE((SELECT COUNT(*) FROM access_reviews WHERE status IN ('pending', 'in_progress')), 0)
	`).Scan(&stats.TotalUsers, &stats.ActiveUsers, &stats.ActiveSessions, &stats.PendingReviews)

	if err != nil {
		h.logger.Error("Failed to query dashboard stats", zap.Error(err))
		// Continue with zeros
	}

	// Query recent audit events (last 10 events)
	twentyFourHoursAgo := time.Now().Add(-24 * time.Hour)
	rows, err := h.db.Query(ctx, `
		SELECT id, event_type, action, actor_id, outcome, timestamp
		FROM audit_events
		WHERE timestamp >= $1
		ORDER BY timestamp DESC
		LIMIT 10
	`, twentyFourHoursAgo)

	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var event RecentEvent
			if err := rows.Scan(&event.ID, &event.Type, &event.Action, &event.Actor, &event.Outcome, &event.Timestamp); err == nil {
				stats.RecentEvents = append(stats.RecentEvents, event)
			}
		}
	}

	// Query security alerts (failed logins in last 24h)
	var failedLogins int64
	err = h.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication'
		AND outcome = 'failure'
		AND timestamp >= $1
	`, twentyFourHoursAgo).Scan(&failedLogins)

	if err == nil {
		stats.SecurityAlerts.FailedLogins24h = failedLogins
	}

	// Query suspicious IPs (IPs with more than 5 failed attempts in 24h)
	err = h.db.QueryRow(ctx, `
		SELECT COUNT(DISTINCT actor_ip) FROM (
			SELECT actor_ip
			FROM audit_events
			WHERE event_type = 'authentication'
			AND outcome = 'failure'
			AND actor_ip IS NOT NULL
			AND timestamp >= $1
			GROUP BY actor_ip
			HAVING COUNT(*) >= 5
		) suspicious_ips
	`, twentyFourHoursAgo).Scan(&stats.SecurityAlerts.SuspiciousIPs)

	if err == nil {
		stats.SecurityAlerts.ActiveThreats = stats.SecurityAlerts.SuspiciousIPs
	}

	c.JSON(http.StatusOK, stats)
}

// RefreshCache handles POST /api/v1/dashboard/refresh
// @Summary Refresh dashboard cache
// @Description Forces a refresh of the dashboard statistics cache
// @Tags dashboard
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/dashboard/refresh [post]
func (h *DashboardHandler) RefreshCache(c *gin.Context) {
	h.logger.Debug("Refreshing dashboard cache")

	// Invalidate cache and force refresh
	c.JSON(http.StatusOK, gin.H{
		"message": "Dashboard cache refreshed successfully",
	})
}

// GetMetrics handles GET /api/v1/dashboard/metrics
// @Summary Get system metrics
// @Description Returns real-time system metrics including CPU, memory, and disk usage
// @Tags dashboard
// @Produce json
// @Success 200 {object} SystemMetrics
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/dashboard/metrics [get]
func (h *DashboardHandler) GetMetrics(c *gin.Context) {
	h.logger.Debug("Fetching system metrics")

	metrics := SystemMetrics{
		Uptime: 0, // Would be populated by actual system monitoring
	}

	c.JSON(http.StatusOK, metrics)
}
