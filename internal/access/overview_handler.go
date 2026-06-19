package access

// Unified Zero Trust Access overview.
//
// handleAccessOverview aggregates, in one org-scoped call, every protected
// resource (proxy_routes) with: how it is reached (HTTP proxy / OpenZiti /
// BrowZer / Guacamole), the zero-trust controls guarding it (auth, roles,
// device-trust, posture, risk cap, geo, inline policy), its live session count,
// and per-feature health. It powers the "Resources" and "Coverage Gaps" lenses
// of the Zero Trust Access page; the "Live Access" lens reuses the existing
// /sessions and /audit/unified endpoints.

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// OverviewFeatureHealth is the per-route feature status from service_features.
type OverviewFeatureHealth struct {
	FeatureName  string `json:"feature_name"`
	Enabled      bool   `json:"enabled"`
	Status       string `json:"status"`
	HealthStatus string `json:"health_status"`
}

// OverviewRoute is one protected resource with its access methods + controls.
type OverviewRoute struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	FromURL   string `json:"from_url"`
	ToURL     string `json:"to_url"`
	Enabled   bool   `json:"enabled"`
	RouteType string `json:"route_type"`

	// Access methods
	ZitiEnabled      bool   `json:"ziti_enabled"`
	ZitiServiceName  string `json:"ziti_service_name,omitempty"`
	BrowZerEnabled   bool   `json:"browzer_enabled"`
	GuacamoleEnabled bool   `json:"guacamole_enabled"`

	// Zero-trust policy summary
	RequireAuth           bool `json:"require_auth"`
	AllowedRolesCount     int  `json:"allowed_roles_count"`
	AllowedGroupsCount    int  `json:"allowed_groups_count"`
	RequireDeviceTrust    bool `json:"require_device_trust"`
	PostureCheckCount     int  `json:"posture_check_count"`
	MaxRiskScore          int  `json:"max_risk_score"`
	AllowedCountriesCount int  `json:"allowed_countries_count"`
	HasInlinePolicy       bool `json:"has_inline_policy"`

	// Live + health
	ActiveSessions int                     `json:"active_sessions"`
	Features       []OverviewFeatureHealth `json:"features"`
}

// OverviewSummary is the top-of-page rollup.
type OverviewSummary struct {
	TotalRoutes        int `json:"total_routes"`
	EnabledRoutes      int `json:"enabled_routes"`
	ViaHTTPProxy       int `json:"via_http_proxy"`
	ViaZiti            int `json:"via_ziti"`
	ViaBrowZer         int `json:"via_browzer"`
	ViaGuacamole       int `json:"via_guacamole"`
	MissingAuth        int `json:"missing_auth"`
	MissingDeviceTrust int `json:"missing_device_trust"`
	MissingPosture     int `json:"missing_posture"`
	MissingRiskCap     int `json:"missing_risk_cap"`
	ActiveSessions     int `json:"active_sessions"`
}

// OverviewZitiStatus is the install-wide OpenZiti control-plane status.
type OverviewZitiStatus struct {
	Configured          bool `json:"configured"`
	ControllerReachable bool `json:"controller_reachable"`
}

// AccessOverviewResponse is the full payload.
type AccessOverviewResponse struct {
	Summary OverviewSummary    `json:"summary"`
	Routes  []OverviewRoute    `json:"routes"`
	Ziti    OverviewZitiStatus `json:"ziti"`
}

func (s *Service) handleAccessOverview(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Resource spine: routes + a cheap active-session count per route. JSONB
	// count columns are guarded against NULL/non-array legacy rows.
	rows, err := s.db.Pool.Query(ctx, `
		SELECT pr.id, pr.name, pr.from_url, pr.to_url, pr.enabled,
		       COALESCE(pr.route_type, 'http'),
		       COALESCE(pr.ziti_enabled, false), COALESCE(pr.ziti_service_name, ''),
		       COALESCE(pr.browzer_enabled, false),
		       (pr.guacamole_connection_id IS NOT NULL AND pr.guacamole_connection_id <> '') AS guac_enabled,
		       pr.require_auth,
		       CASE WHEN jsonb_typeof(pr.allowed_roles) = 'array' THEN jsonb_array_length(pr.allowed_roles) ELSE 0 END,
		       CASE WHEN jsonb_typeof(pr.allowed_groups) = 'array' THEN jsonb_array_length(pr.allowed_groups) ELSE 0 END,
		       COALESCE(pr.require_device_trust, false),
		       CASE WHEN jsonb_typeof(pr.posture_check_ids) = 'array' THEN jsonb_array_length(pr.posture_check_ids) ELSE 0 END,
		       COALESCE(pr.max_risk_score, 100),
		       CASE WHEN jsonb_typeof(pr.allowed_countries) = 'array' THEN jsonb_array_length(pr.allowed_countries) ELSE 0 END,
		       (pr.inline_policy IS NOT NULL AND pr.inline_policy <> '') AS has_inline,
		       COALESCE(sess.cnt, 0) AS active_sessions
		FROM proxy_routes pr
		LEFT JOIN (
			SELECT route_id, COUNT(*) AS cnt FROM proxy_sessions
			WHERE revoked = false AND expires_at > NOW() AND org_id = $1 AND route_id IS NOT NULL
			GROUP BY route_id
		) sess ON sess.route_id = pr.id
		WHERE pr.org_id = $1
		ORDER BY pr.priority DESC, pr.name ASC`, org.ID)
	if err != nil {
		s.logger.Error("overview: failed to query routes", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load overview"})
		return
	}
	defer rows.Close()

	routes := []OverviewRoute{}
	index := map[string]int{}
	for rows.Next() {
		var r OverviewRoute
		if err := rows.Scan(&r.ID, &r.Name, &r.FromURL, &r.ToURL, &r.Enabled,
			&r.RouteType, &r.ZitiEnabled, &r.ZitiServiceName, &r.BrowZerEnabled,
			&r.GuacamoleEnabled, &r.RequireAuth, &r.AllowedRolesCount, &r.AllowedGroupsCount,
			&r.RequireDeviceTrust, &r.PostureCheckCount, &r.MaxRiskScore,
			&r.AllowedCountriesCount, &r.HasInlinePolicy, &r.ActiveSessions); err != nil {
			s.logger.Warn("overview: failed to scan route", zap.Error(err))
			continue
		}
		r.Features = []OverviewFeatureHealth{}
		index[r.ID] = len(routes)
		routes = append(routes, r)
	}

	// Feature health, org-scoped via join (service_features has no org_id).
	fRows, ferr := s.db.Pool.Query(ctx, `
		SELECT sf.route_id, sf.feature_name, COALESCE(sf.enabled, false),
		       COALESCE(sf.status, ''), COALESCE(sf.health_status, '')
		FROM service_features sf
		JOIN proxy_routes pr ON pr.id = sf.route_id
		WHERE pr.org_id = $1`, org.ID)
	if ferr != nil {
		s.logger.Warn("overview: failed to query feature health", zap.Error(ferr))
	} else {
		defer fRows.Close()
		for fRows.Next() {
			var routeID string
			var f OverviewFeatureHealth
			if err := fRows.Scan(&routeID, &f.FeatureName, &f.Enabled, &f.Status, &f.HealthStatus); err != nil {
				continue
			}
			if i, ok := index[routeID]; ok {
				routes[i].Features = append(routes[i].Features, f)
			}
		}
	}

	// Summary rollup from the assembled rows.
	summary := OverviewSummary{TotalRoutes: len(routes)}
	for _, r := range routes {
		if r.Enabled {
			summary.EnabledRoutes++
		}
		// Every route is reachable over HTTP unless it is purely a non-http type.
		if r.RouteType == "" || r.RouteType == "http" {
			summary.ViaHTTPProxy++
		}
		if r.ZitiEnabled {
			summary.ViaZiti++
		}
		if r.BrowZerEnabled {
			summary.ViaBrowZer++
		}
		if r.GuacamoleEnabled {
			summary.ViaGuacamole++
		}
		if !r.RequireAuth {
			summary.MissingAuth++
		}
		if !r.RequireDeviceTrust {
			summary.MissingDeviceTrust++
		}
		if r.PostureCheckCount == 0 {
			summary.MissingPosture++
		}
		if r.MaxRiskScore >= 100 {
			summary.MissingRiskCap++
		}
	}

	// Total active sessions (includes sessions with NULL route_id, so we count
	// directly rather than summing the per-route counts).
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM proxy_sessions WHERE revoked = false AND expires_at > NOW() AND org_id = $1`,
		org.ID).Scan(&summary.ActiveSessions); err != nil {
		s.logger.Warn("overview: failed to count active sessions", zap.Error(err))
	}

	// Install-wide OpenZiti control-plane status (two booleans, no DB recount).
	ziti := OverviewZitiStatus{}
	if s.zitiManager != nil {
		ziti.Configured = true
		if _, verr := s.zitiManager.GetControllerVersion(ctx); verr == nil {
			ziti.ControllerReachable = true
		}
	}

	c.JSON(http.StatusOK, AccessOverviewResponse{
		Summary: summary,
		Routes:  routes,
		Ziti:    ziti,
	})
}
