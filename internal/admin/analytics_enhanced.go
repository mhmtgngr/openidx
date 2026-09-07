package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// handleAuthAnalyticsDashboard returns detailed authentication analytics for a given period.
// GET /api/v1/analytics/auth?period=24h|7d|30d|90d
func (s *Service) handleAuthAnalyticsDashboard(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Parse period
	period := c.DefaultQuery("period", "30d")
	interval := periodToInterval(period)

	result := make(map[string]interface{})

	// Total logins
	var totalLogins int
	q := s.newTileQuery(ctx)
	q.scan("total sign-ins", &totalLogins, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication'
		  AND timestamp > NOW() - $1::interval
		  AND org_id = $2`, interval, org.ID)
	result["total_logins"] = totalLogins

	// Successful logins
	var successLogins int
	q.scan("successful sign-ins", &successLogins, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication' AND outcome = 'success'
		  AND timestamp > NOW() - $1::interval
		  AND org_id = $2`, interval, org.ID)

	// Failed logins
	var failedLogins int
	q.scan("failed sign-ins", &failedLogins, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication' AND outcome = 'failure'
		  AND timestamp > NOW() - $1::interval
		  AND org_id = $2`, interval, org.ID)

	// Rates
	if totalLogins > 0 {
		result["success_rate"] = float64(successLogins) / float64(totalLogins) * 100
		result["failure_rate"] = float64(failedLogins) / float64(totalLogins) * 100
	} else {
		result["success_rate"] = 0.0
		result["failure_rate"] = 0.0
	}

	// MFA usage rate
	var mfaLogins int
	q.scan("MFA sign-ins", &mfaLogins, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'mfa_verification' AND outcome = 'success'
		  AND timestamp > NOW() - $1::interval
		  AND org_id = $2`, interval, org.ID)
	if q.failed(c) {
		return
	}

	if successLogins > 0 {
		result["mfa_usage_rate"] = float64(mfaLogins) / float64(successLogins) * 100
	} else {
		result["mfa_usage_rate"] = 0.0
	}

	// Method breakdown
	methodBreakdown := make(map[string]int)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT COALESCE(action, 'unknown'), COUNT(*)
		FROM audit_events
		WHERE event_type = 'authentication' AND outcome = 'success'
		  AND timestamp > NOW() - $1::interval
		  AND org_id = $2
		GROUP BY action
		ORDER BY COUNT(*) DESC
	`, interval, org.ID)
	if err == nil {
		for rows.Next() {
			var method string
			var cnt int
			if rows.Scan(&method, &cnt) == nil {
				methodBreakdown[method] = cnt
			}
		}
		rows.Close()
	}
	result["method_breakdown"] = methodBreakdown

	// Peak hour
	var peakHour *int
	var peakCount int
	s.db.Pool.QueryRow(ctx, `
		SELECT EXTRACT(HOUR FROM timestamp)::int AS hour, COUNT(*) AS cnt
		FROM audit_events
		WHERE event_type = 'authentication'
		  AND timestamp > NOW() - $1::interval
		  AND org_id = $2
		GROUP BY hour
		ORDER BY cnt DESC
		LIMIT 1
	`, interval, org.ID).Scan(&peakHour, &peakCount)
	if peakHour != nil {
		result["peak_hour"] = *peakHour
	} else {
		result["peak_hour"] = 0
	}

	// Geo top 5 countries from login_history
	geoTop5 := []map[string]interface{}{}
	geoRows, err := s.db.Pool.Query(ctx, `
		SELECT COALESCE(location, 'Unknown'), COUNT(*) AS cnt
		FROM login_history
		WHERE created_at > NOW() - $1::interval
		  AND org_id = $2
		GROUP BY location
		ORDER BY cnt DESC
		LIMIT 5
	`, interval, org.ID)
	if err == nil {
		for geoRows.Next() {
			var loc string
			var cnt int
			if geoRows.Scan(&loc, &cnt) == nil {
				geoTop5 = append(geoTop5, map[string]interface{}{
					"country": loc,
					"count":   cnt,
				})
			}
		}
		geoRows.Close()
	}
	result["geo_top_5"] = geoTop5
	result["period"] = period

	c.JSON(http.StatusOK, result)
}

// handleUsageAnalytics returns platform usage metrics: DAU, WAU, MAU, entity counts.
// GET /api/v1/analytics/usage
func (s *Service) handleUsageAnalytics(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	result := make(map[string]interface{})

	// DAU: distinct actors who authenticated today
	var dau int
	q := s.newTileQuery(ctx)
	q.scan("daily active users", &dau, `
		SELECT COUNT(DISTINCT actor_id) FROM audit_events
		WHERE event_type = 'authentication' AND outcome = 'success'
		  AND timestamp > CURRENT_DATE
		  AND org_id = $1
	`, org.ID)
	result["dau"] = dau

	// WAU: distinct actors who authenticated in last 7 days
	var wau int
	q.scan("weekly active users", &wau, `
		SELECT COUNT(DISTINCT actor_id) FROM audit_events
		WHERE event_type = 'authentication' AND outcome = 'success'
		  AND timestamp > NOW() - INTERVAL '7 days'
		  AND org_id = $1
	`, org.ID)
	result["wau"] = wau

	// MAU: distinct actors who authenticated in last 30 days
	var mau int
	q.scan("monthly active users", &mau, `
		SELECT COUNT(DISTINCT actor_id) FROM audit_events
		WHERE event_type = 'authentication' AND outcome = 'success'
		  AND timestamp > NOW() - INTERVAL '30 days'
		  AND org_id = $1
	`, org.ID)
	result["mau"] = mau

	// New users today
	var newUsersToday int
	q.scan("users created today", &newUsersToday, `
		SELECT COUNT(*) FROM users
		WHERE created_at > CURRENT_DATE
		  AND org_id = $1
	`, org.ID)
	result["new_users_today"] = newUsersToday

	// Total counts
	var totalUsers int
	q.scan("total users", &totalUsers, `SELECT COUNT(*) FROM users WHERE org_id = $1`, org.ID)
	result["total_users"] = totalUsers

	var totalGroups int
	q.scan("total groups", &totalGroups, `SELECT COUNT(*) FROM groups WHERE org_id = $1`, org.ID)
	result["total_groups"] = totalGroups

	var totalApplications int
	q.scan("total applications", &totalApplications, `SELECT COUNT(*) FROM applications WHERE org_id = $1`, org.ID)
	result["total_applications"] = totalApplications

	// Active sessions
	var activeSessions int
	q.scan("active sessions", &activeSessions, `
		SELECT COUNT(*) FROM sessions
		WHERE expires_at > NOW()
		  AND org_id = $1
	`, org.ID)
	if q.failed(c) {
		return
	}
	result["active_sessions_count"] = activeSessions

	// Frontend (usage-analytics page) and its unit test read {usage: {...}};
	// returning the flat object left the whole page blank.
	c.JSON(http.StatusOK, gin.H{"usage": result})
}

// handleAPIUsageMetrics is gone with the api_usage_metrics table (migration
// v176). It read total requests, top endpoints, error rate and average latency
// from a table nothing has ever written a row to, and it read them with column
// names -- request_count, error_count, recorded_at -- the table never had, so
// every one of its four statements failed to plan and every value it returned
// was the Go zero beside it. The console card that displayed them is removed in
// the same commit.
//
// Request volume, latency and status codes ARE measured, by the Prometheus
// middleware every service mounts (internal/metrics.Middleware), and are
// exported on /metrics for the Prometheus and Grafana that ship in
// deployments/docker. That is where this measurement lives; a second copy
// aggregated into Postgres was never written.

// handleFeatureAdoption returns feature adoption metrics, computed live from
// the tables that record each feature's use.
//
// It used to read a stored `feature_adoption` table first and fall back to this
// computation "if no rows exist". The read was
//
//	SELECT feature_name, total_users, trend FROM feature_adoption ...
//
// and v54 created that table as (id, feature_name, user_id, first_used_at,
// last_used_at, usage_count) -- no total_users column, no trend column, and no
// migration ever added either. So the query returned `column "total_users"
// does not exist` every time, the handler's `if err == nil` swallowed it, and
// the "fallback" was in fact the only path the endpoint had ever taken.
// Nothing in the tree wrote to the table either, so migration v163 drops it and
// this computation is the whole handler.
//
// GET /api/v1/analytics/features
func (s *Service) handleFeatureAdoption(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Total enabled users for computing adoption rates
	var totalUsers int
	q := s.newTileQuery(ctx)
	q.scan("total users", &totalUsers, `SELECT COUNT(*) FROM users WHERE enabled = true AND org_id = $1`, org.ID)
	if q.failed(c) {
		return
	}

	features := []map[string]interface{}{}

	// Each query is scoped to the caller's org.
	featureSources := []struct {
		Name  string
		Query string
		Args  []interface{}
	}{
		{"mfa_totp", "SELECT COUNT(DISTINCT user_id) FROM mfa_totp WHERE enabled = true AND org_id = $1", []interface{}{org.ID}},
		{"mfa_webauthn", "SELECT COUNT(DISTINCT user_id) FROM mfa_webauthn WHERE org_id = $1", []interface{}{org.ID}},
		{"passkey_login", "SELECT COUNT(DISTINCT actor_id) FROM audit_events WHERE action = 'passkey_login' AND timestamp > NOW() - INTERVAL '30 days' AND org_id = $1", []interface{}{org.ID}},
		{"magic_link", "SELECT COUNT(DISTINCT actor_id) FROM audit_events WHERE action = 'magic_link_login' AND timestamp > NOW() - INTERVAL '30 days' AND org_id = $1", []interface{}{org.ID}},
		// api_keys records revocation in `status`; there is no revoked_at, so
		// this source failed to plan and the adoption figure read 0.
		{"api_keys", "SELECT COUNT(DISTINCT COALESCE(user_id, service_account_id)) FROM api_keys WHERE status = 'active' AND org_id = $1", []interface{}{org.ID}},
		{"social_login", "SELECT COUNT(DISTINCT actor_id) FROM audit_events WHERE action = 'social_login' AND timestamp > NOW() - INTERVAL '30 days' AND org_id = $1", []interface{}{org.ID}},
	}

	for _, fs := range featureSources {
		var count int
		if err := s.db.Pool.QueryRow(ctx, fs.Query, fs.Args...).Scan(&count); err != nil {
			s.logger.Warn("feature adoption source failed",
				zap.String("feature", fs.Name), zap.Error(err))
		}
		var adoptionRate float64
		if totalUsers > 0 {
			adoptionRate = float64(count) / float64(totalUsers) * 100
		}
		features = append(features, map[string]interface{}{
			"name":          fs.Name,
			"total_users":   count,
			"adoption_rate": adoptionRate,
			"trend":         "stable",
		})
	}

	c.JSON(http.StatusOK, gin.H{
		// Frontend reads {adoption: {features: [...]}}.
		"adoption": gin.H{
			"total_users": totalUsers,
			"features":    features,
		},
	})
}

// handleRiskScoreTimeline returns daily risk score trends.
// GET /api/v1/analytics/risk-timeline?days=30
func (s *Service) handleRiskScoreTimeline(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	if s.riskService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "risk service not available"})
		return
	}

	days := 30
	if d := c.Query("days"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 && parsed <= 365 {
			days = parsed
		}
	}

	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT DATE(created_at) AS day,
		       AVG(risk_score) AS avg_score,
		       MAX(risk_score) AS max_score,
		       COUNT(*) AS login_count
		FROM login_history
		WHERE created_at > NOW() - make_interval(days => $1)
		  AND org_id = $2
		GROUP BY day
		ORDER BY day
	`, days, org.ID)
	if err != nil {
		s.logger.Error("Failed to query risk timeline", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query risk timeline"})
		return
	}
	defer rows.Close()

	var timeline []map[string]interface{}
	for rows.Next() {
		var day time.Time
		var avgScore float64
		var maxScore, loginCount int
		if err := rows.Scan(&day, &avgScore, &maxScore, &loginCount); err != nil {
			s.logger.Warn("Failed to scan risk timeline row", zap.Error(err))
			continue
		}
		timeline = append(timeline, map[string]interface{}{
			"date":        day.Format("2006-01-02"),
			"avg_score":   int(avgScore),
			"max_score":   maxScore,
			"login_count": loginCount,
		})
	}

	if timeline == nil {
		timeline = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"days":     days,
		"timeline": timeline,
	})
}

// handleUserActivityHeatmap returns a 24x7 heatmap of login activity (hour x day of week).
// GET /api/v1/analytics/activity-heatmap?period=30d
func (s *Service) handleUserActivityHeatmap(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	period := c.DefaultQuery("period", "30d")
	interval := periodToInterval(period)

	// Query: hour of day (0-23) x day of week (0=Sunday through 6=Saturday)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT EXTRACT(DOW FROM timestamp)::int AS dow,
		       EXTRACT(HOUR FROM timestamp)::int AS hour,
		       COUNT(*) AS cnt
		FROM audit_events
		WHERE event_type = 'authentication'
		  AND timestamp > NOW() - $1::interval
		  AND org_id = $2
		GROUP BY dow, hour
		ORDER BY dow, hour
	`, interval, org.ID)
	if err != nil {
		s.logger.Error("Failed to query activity heatmap", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query activity heatmap"})
		return
	}
	defer rows.Close()

	// Build a 7x24 matrix
	dayNames := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	heatmap := make([]map[string]interface{}, 0)

	for rows.Next() {
		var dow, hour, cnt int
		if rows.Scan(&dow, &hour, &cnt) == nil {
			dayName := "Unknown"
			if dow >= 0 && dow < len(dayNames) {
				dayName = dayNames[dow]
			}
			heatmap = append(heatmap, map[string]interface{}{
				"day_of_week": dow,
				"day_name":    dayName,
				"hour":        hour,
				"count":       cnt,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"period":  period,
		"heatmap": heatmap,
	})
}

// periodToInterval converts a period string like "24h", "7d", "30d", "90d"
// to a plain interval string safe for use as a parameterized query value
// with PostgreSQL's $N::interval cast.
func periodToInterval(period string) string {
	switch period {
	case "24h":
		return "24 hours"
	case "7d":
		return "7 days"
	case "90d":
		return "90 days"
	case "30d":
		return "30 days"
	default:
		return "30 days"
	}
}
