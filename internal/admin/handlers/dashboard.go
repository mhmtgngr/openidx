// Package handlers provides HTTP handlers for the admin console
package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
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
	TotalUsers     int64          `json:"total_users"`
	ActiveUsers    int64          `json:"active_users"`
	ActiveSessions int64          `json:"active_sessions"`
	PendingReviews int64          `json:"pending_reviews"`
	RecentEvents   []RecentEvent  `json:"recent_events"`
	SystemMetrics  SystemMetrics  `json:"system_metrics"`
	SecurityAlerts SecurityAlerts `json:"security_alerts"`
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
// processStart is when this process began serving. Package-level so the value
// is the process's, not the request's.
var processStart = time.Now()

// SystemMetrics is what the dashboard reports about the running service.
//
// CPUUsage, MemoryUsage and DiskUsage were removed with the /dashboard/metrics
// endpoint that claimed to fill them: it was swagger-documented as "real-time
// system metrics including CPU, memory, and disk usage" and returned a zero
// struct, always. Host metrics belong to the Prometheus scrape the chart's
// ServiceMonitor already wires up, not to a JSON endpoint that reports zeros
// as if it had measured them.
type SystemMetrics struct {
	Uptime int64 `json:"uptime_seconds,omitempty"`
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

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	stats := &DashboardStats{
		RecentEvents: []RecentEvent{},
		SystemMetrics: SystemMetrics{
			// Real process uptime. This used to be
			// time.Since(time.Now().Add(-365*24h)) — a literal 31,536,000
			// seconds dressed as a computation, so every install reported
			// "365d" on its first request after a restart.
			Uptime: int64(time.Since(processStart).Seconds()),
		},
		SecurityAlerts: SecurityAlerts{},
	}

	// Query dashboard stats - single query for efficiency
	err = h.db.QueryRow(ctx, `
		SELECT
			COALESCE((SELECT COUNT(*) FROM users WHERE org_id = $1), 0),
			COALESCE((SELECT COUNT(*) FROM users WHERE enabled = true AND org_id = $1), 0),
			COALESCE((SELECT COUNT(*) FROM user_sessions WHERE expires_at > NOW() AND org_id = $1), 0),
			COALESCE((SELECT COUNT(*) FROM access_reviews WHERE status IN ('pending', 'in_progress') AND org_id = $1), 0)
	`, org.ID).Scan(&stats.TotalUsers, &stats.ActiveUsers, &stats.ActiveSessions, &stats.PendingReviews)

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
		AND org_id = $2
		ORDER BY timestamp DESC
		LIMIT 10
	`, twentyFourHoursAgo, org.ID)

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
		AND org_id = $2
	`, twentyFourHoursAgo, org.ID).Scan(&failedLogins)

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
			AND org_id = $2
			GROUP BY actor_ip
			HAVING COUNT(*) >= 5
		) suspicious_ips
	`, twentyFourHoursAgo, org.ID).Scan(&stats.SecurityAlerts.SuspiciousIPs)

	if err == nil {
		stats.SecurityAlerts.ActiveThreats = stats.SecurityAlerts.SuspiciousIPs
	}

	c.JSON(http.StatusOK, stats)
}
