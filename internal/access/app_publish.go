// Package access provides app publishing: register, discover, classify, and publish web app paths as proxy routes.
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// ---- Data structures ----

// PublishedApp represents a registered application for path discovery.
type PublishedApp struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	Description          string    `json:"description,omitempty"`
	TargetURL            string    `json:"target_url"`
	SpecURL              string    `json:"spec_url,omitempty"`
	Status               string    `json:"status"`
	DiscoveryStartedAt   *string   `json:"discovery_started_at,omitempty"`
	DiscoveryCompletedAt *string   `json:"discovery_completed_at,omitempty"`
	DiscoveryError       *string   `json:"discovery_error,omitempty"`
	DiscoveryStrategies  []string  `json:"discovery_strategies"`
	TotalPathsDiscovered int       `json:"total_paths_discovered"`
	TotalPathsPublished  int       `json:"total_paths_published"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// DiscoveredPath represents a single discovered endpoint.
type DiscoveredPath struct {
	ID                   string                 `json:"id"`
	AppID                string                 `json:"app_id"`
	Path                 string                 `json:"path"`
	HTTPMethods          []string               `json:"http_methods"`
	Classification       string                 `json:"classification"`
	ClassificationSource string                 `json:"classification_source"`
	DiscoveryStrategy    string                 `json:"discovery_strategy"`
	SuggestedPolicy      string                 `json:"suggested_policy,omitempty"`
	RequireAuth          bool                   `json:"require_auth"`
	AllowedRoles         []string               `json:"allowed_roles"`
	RequireDeviceTrust   bool                   `json:"require_device_trust"`
	Published            bool                   `json:"published"`
	RouteID              *string                `json:"route_id,omitempty"`
	Metadata             map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
}

// Classification constants.
const (
	ClassCritical  = "critical"
	ClassSensitive = "sensitive"
	ClassProtected = "protected"
	ClassPublic    = "public"
)

// ---- Request / Response types ----

type RegisterAppRequest struct {
	Name        string `json:"name" binding:"required"`
	TargetURL   string `json:"target_url" binding:"required"`
	Description string `json:"description"`
	SpecURL     string `json:"spec_url"`
}

type UpdatePathClassificationRequest struct {
	Classification     string   `json:"classification"`
	AllowedRoles       []string `json:"allowed_roles"`
	RequireAuth        *bool    `json:"require_auth"`
	RequireDeviceTrust *bool    `json:"require_device_trust"`
	SuggestedPolicy    string   `json:"suggested_policy"`
}

type PublishPathsRequest struct {
	PathIDs       []string `json:"path_ids" binding:"required"`
	EnableZiti    bool     `json:"enable_ziti"`
	EnableBrowzer bool     `json:"enable_browzer"`
	FromURLPrefix string   `json:"from_url_prefix"`
}

type PublishResult struct {
	TotalRequested int                  `json:"total_requested"`
	TotalPublished int                  `json:"total_published"`
	TotalFailed    int                  `json:"total_failed"`
	Published      []PublishedPathRoute `json:"published"`
	Errors         []string             `json:"errors,omitempty"`
}

type PublishedPathRoute struct {
	PathID  string `json:"path_id"`
	RouteID string `json:"route_id"`
	Path    string `json:"path"`
	Name    string `json:"name"`
}

// ---- Handlers ----

func (s *Service) handleListApps(c *gin.Context) {
	offset := 0
	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil {
			offset = v
		}
	}
	limit := 20
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}

	ctx := c.Request.Context()

	var total int
	s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM published_apps`).Scan(&total)
	c.Header("x-total-count", strconv.Itoa(total))

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, COALESCE(description,''), target_url, COALESCE(spec_url,''),
		       status, discovery_started_at, discovery_completed_at, discovery_error,
		       discovery_strategies, total_paths_discovered, total_paths_published,
		       created_at, updated_at
		FROM published_apps ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	apps := []PublishedApp{}
	for rows.Next() {
		var a PublishedApp
		var strategiesJSON []byte
		var startedAt, completedAt *time.Time
		var discErr *string
		if err := rows.Scan(&a.ID, &a.Name, &a.Description, &a.TargetURL, &a.SpecURL,
			&a.Status, &startedAt, &completedAt, &discErr,
			&strategiesJSON, &a.TotalPathsDiscovered, &a.TotalPathsPublished,
			&a.CreatedAt, &a.UpdatedAt); err != nil {
			continue
		}
		json.Unmarshal(strategiesJSON, &a.DiscoveryStrategies)
		if a.DiscoveryStrategies == nil {
			a.DiscoveryStrategies = []string{}
		}
		if startedAt != nil {
			t := startedAt.Format(time.RFC3339)
			a.DiscoveryStartedAt = &t
		}
		if completedAt != nil {
			t := completedAt.Format(time.RFC3339)
			a.DiscoveryCompletedAt = &t
		}
		a.DiscoveryError = discErr
		apps = append(apps, a)
	}

	c.JSON(http.StatusOK, gin.H{"apps": apps, "total": total})
}

func (s *Service) handleRegisterApp(c *gin.Context) {
	var req RegisterAppRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if _, err := url.ParseRequestURI(req.TargetURL); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target_url"})
		return
	}

	id := uuid.New().String()
	ctx := c.Request.Context()

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO published_apps (id, name, description, target_url, spec_url, status)
		VALUES ($1, $2, $3, $4, $5, 'pending')`,
		id, req.Name, req.Description, req.TargetURL, req.SpecURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.logAuditEvent(c, "app_registered", id, "published_app", map[string]interface{}{
		"name": req.Name, "target_url": req.TargetURL,
	})

	c.JSON(http.StatusCreated, gin.H{"id": id, "name": req.Name, "status": "pending"})
}

func (s *Service) handleGetApp(c *gin.Context) {
	appID := c.Param("appId")
	ctx := c.Request.Context()

	var a PublishedApp
	var strategiesJSON []byte
	var startedAt, completedAt *time.Time
	var discErr *string

	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, COALESCE(description,''), target_url, COALESCE(spec_url,''),
		       status, discovery_started_at, discovery_completed_at, discovery_error,
		       discovery_strategies, total_paths_discovered, total_paths_published,
		       created_at, updated_at
		FROM published_apps WHERE id=$1`, appID).
		Scan(&a.ID, &a.Name, &a.Description, &a.TargetURL, &a.SpecURL,
			&a.Status, &startedAt, &completedAt, &discErr,
			&strategiesJSON, &a.TotalPathsDiscovered, &a.TotalPathsPublished,
			&a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "app not found"})
		return
	}
	json.Unmarshal(strategiesJSON, &a.DiscoveryStrategies)
	if a.DiscoveryStrategies == nil {
		a.DiscoveryStrategies = []string{}
	}
	if startedAt != nil {
		t := startedAt.Format(time.RFC3339)
		a.DiscoveryStartedAt = &t
	}
	if completedAt != nil {
		t := completedAt.Format(time.RFC3339)
		a.DiscoveryCompletedAt = &t
	}
	a.DiscoveryError = discErr

	c.JSON(http.StatusOK, a)
}

func (s *Service) handleDeleteApp(c *gin.Context) {
	appID := c.Param("appId")
	ctx := c.Request.Context()

	tag, err := s.db.Pool.Exec(ctx, `DELETE FROM published_apps WHERE id=$1`, appID)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "app not found"})
		return
	}

	s.logAuditEvent(c, "app_deleted", appID, "published_app", nil)
	c.JSON(http.StatusOK, gin.H{"message": "app deleted"})
}

func (s *Service) handleStartDiscovery(c *gin.Context) {
	appID := c.Param("appId")
	ctx := c.Request.Context()

	var status string
	err := s.db.Pool.QueryRow(ctx, `SELECT status FROM published_apps WHERE id=$1`, appID).Scan(&status)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "app not found"})
		return
	}
	if status == "discovering" {
		c.JSON(http.StatusConflict, gin.H{"error": "discovery already in progress"})
		return
	}

	s.db.Pool.Exec(ctx, `UPDATE published_apps SET status='discovering', discovery_started_at=NOW(), discovery_error=NULL, updated_at=NOW() WHERE id=$1`, appID)

	// Run app discovery in background with timeout
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		s.runAppDiscovery(ctx, appID)
	}()

	s.logAuditEvent(c, "app_discovery_started", appID, "published_app", nil)
	c.JSON(http.StatusAccepted, gin.H{"message": "discovery started", "app_id": appID})
}

func (s *Service) handleListDiscoveredPaths(c *gin.Context) {
	appID := c.Param("appId")
	ctx := c.Request.Context()
	classification := c.Query("classification")

	query := `SELECT id, app_id, path, http_methods, classification, classification_source,
	          COALESCE(discovery_strategy,''), COALESCE(suggested_policy,''),
	          require_auth, allowed_roles, require_device_trust, published, route_id,
	          metadata, created_at, updated_at
	          FROM discovered_paths WHERE app_id=$1`
	args := []interface{}{appID}

	if classification != "" {
		query += ` AND classification=$2`
		args = append(args, classification)
	}
	query += ` ORDER BY CASE classification WHEN 'critical' THEN 1 WHEN 'sensitive' THEN 2 WHEN 'protected' THEN 3 WHEN 'public' THEN 4 END, path`

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	paths := []DiscoveredPath{}
	for rows.Next() {
		var p DiscoveredPath
		var methodsJSON, rolesJSON, metadataJSON []byte
		if err := rows.Scan(&p.ID, &p.AppID, &p.Path, &methodsJSON, &p.Classification,
			&p.ClassificationSource, &p.DiscoveryStrategy, &p.SuggestedPolicy,
			&p.RequireAuth, &rolesJSON, &p.RequireDeviceTrust, &p.Published, &p.RouteID,
			&metadataJSON, &p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		json.Unmarshal(methodsJSON, &p.HTTPMethods)
		json.Unmarshal(rolesJSON, &p.AllowedRoles)
		json.Unmarshal(metadataJSON, &p.Metadata)
		if p.HTTPMethods == nil {
			p.HTTPMethods = []string{}
		}
		if p.AllowedRoles == nil {
			p.AllowedRoles = []string{}
		}
		paths = append(paths, p)
	}

	c.JSON(http.StatusOK, gin.H{"paths": paths, "total": len(paths)})
}

func (s *Service) handleUpdatePathClassification(c *gin.Context) {
	pathID := c.Param("pathId")
	ctx := c.Request.Context()

	var req UpdatePathClassificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Classification != "" {
		valid := map[string]bool{ClassCritical: true, ClassSensitive: true, ClassProtected: true, ClassPublic: true}
		if !valid[req.Classification] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid classification; use critical, sensitive, protected, or public"})
			return
		}
	}

	// Single source of truth for the (column → value, set?) mapping. By
	// pulling every column literal into one slice we kill the previous
	// pattern of scattered `fmt.Sprintf("col=$%d", argIdx)` calls in
	// if-blocks. Any new column has to be added here, declared in
	// discoveredPathsUpdatableColumns, AND pass the runtime allow-list
	// check in buildUpdateClause.
	rolesJSON, _ := json.Marshal(req.AllowedRoles)
	fields := []sqlUpdateField{
		{col: "classification", val: req.Classification, set: req.Classification != ""},
		{col: "allowed_roles", val: rolesJSON, set: req.AllowedRoles != nil},
		{col: "require_auth", val: derefBool(req.RequireAuth), set: req.RequireAuth != nil},
		{col: "require_device_trust", val: derefBool(req.RequireDeviceTrust), set: req.RequireDeviceTrust != nil},
		{col: "suggested_policy", val: req.SuggestedPolicy, set: req.SuggestedPolicy != ""},
	}

	setClauses, args, buildErr := buildUpdateClause(
		fields, discoveredPathsUpdatableColumns, discoveredPathsColumnRE,
	)
	if buildErr != nil {
		s.logger.Error("discovered_paths update builder rejected a column",
			zap.Error(buildErr))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	// classification_source and updated_at are always written when there
	// is at least one user-driven column to update.
	setClauses = append(setClauses,
		"classification_source = 'manual'",
		"updated_at = NOW()",
	)
	args = append(args, pathID)

	// Table name + WHERE column are package-literal strings. The SET
	// clause comes from setClauses, every entry of which has been
	// allow-listed by buildUpdateClause.
	query := "UPDATE discovered_paths SET " + strings.Join(setClauses, ", ") +
		" WHERE id = $" + strconv.Itoa(len(args))

	tag, err := s.db.Pool.Exec(ctx, query, args...)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "path not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "classification updated"})
}

// resolveAppPublicHost picks the public host for an app: an explicit value
// (scheme stripped) wins, else the slug of the app name + ACCESS_APPS_DOMAIN.
func (s *Service) resolveAppPublicHost(explicit, appName string) (string, error) {
	h := strings.TrimSpace(explicit)
	if h == "" {
		if s.config == nil || s.config.AccessAppsDomain == "" {
			return "", fmt.Errorf("no public host provided and ACCESS_APPS_DOMAIN is not configured")
		}
		h = sanitizeName(appName) + "." + strings.TrimPrefix(s.config.AccessAppsDomain, ".")
	}
	h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
	return strings.Trim(h, "/"), nil
}

// ensureHostRoute upserts the single host-level proxy route for an app
// (delete-then-insert keyed by from_url, so re-publishing the same host is
// idempotent). from_url is always a bare host (no path) — Ziti/BrowZer and the
// data-plane route match are per-host. Returns the route id.
func (s *Service) ensureHostRoute(ctx context.Context, orgID, appName, fromURL, targetURL string, preserveHost bool) (string, error) {
	//orgscope:ignore publish host route upsert; scoped by org_id in the statements
	s.db.Pool.Exec(ctx, `DELETE FROM proxy_routes WHERE from_url=$1 AND org_id=$2`, fromURL, orgID)
	routeID := uuid.New().String()
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO proxy_routes (id, name, description, from_url, to_url,
			preserve_host, require_auth, allowed_roles, enabled, priority, route_type,
			inline_policy, require_device_trust, max_risk_score,
			allowed_groups, policy_ids, cors_allowed_origins, custom_headers,
			posture_check_ids, allowed_countries, idle_timeout, absolute_timeout, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, true, '[]', true, 50, 'http',
			'', false, 100,
			'[]', '[]', '[]', '{}', '[]', '[]', 900, 43200, $7)`,
		routeID, appName, fmt.Sprintf("Published app %q", appName),
		fromURL, strings.TrimSuffix(targetURL, "/"), preserveHost, orgID)
	if err != nil {
		return "", err
	}
	return routeID, nil
}

// upsertAppLauncherTile keeps the My Apps launcher tile in sync for a published
// app (client_id "proxy-app-<appID>" is deterministic, so this is idempotent).
func (s *Service) upsertAppLauncherTile(ctx context.Context, orgID, appID, appName, appDesc, publicURL string) {
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO applications (id, client_id, name, description, type, protocol, base_url, redirect_uris, enabled, org_id)
		VALUES ($1, $2, $3, $4, 'proxy', 'proxy', $5, '{}', true, $6)
		ON CONFLICT (client_id) DO UPDATE SET
			name = EXCLUDED.name, description = EXCLUDED.description,
			base_url = EXCLUDED.base_url, enabled = true, updated_at = NOW()`,
		uuid.New().String(), "proxy-app-"+appID, appName, appDesc, publicURL, orgID); err != nil {
		s.logger.Warn("publish: failed to upsert launcher tile", zap.Error(err))
	}
}

// registerAccessProxyCallback adds the per-host forward-auth callback to the
// shared access-proxy OAuth client (for the authenticated access-proxy path).
func (s *Service) registerAccessProxyCallback(ctx context.Context, publicHost string) {
	callback := fmt.Sprintf(`["https://%s/access/.auth/callback"]`, publicHost)
	//orgscope:ignore access-proxy is a single install-wide OAuth client shared across all tenants
	if _, err := s.db.Pool.Exec(ctx, `
		UPDATE oauth_clients SET redirect_uris = redirect_uris || $1::jsonb
		WHERE client_id='access-proxy' AND NOT (redirect_uris @> $1::jsonb)`, callback); err != nil {
		s.logger.Warn("publish: failed to register access-proxy callback", zap.Error(err))
	}
}

// handlePublishPaths publishes an app as a SINGLE host-level route. Path
// discovery is advisory: selected paths are linked to the one app route for
// display, but each path is NOT turned into its own proxy_route (that exploded a
// single app into dozens of routes that collided with the per-host Ziti/BrowZer
// model). Ziti/BrowZer is a per-app toggle. Per-path authz is not enforced
// (per-app authz only; BrowZer authz is the overlay — Ziti dial policy + OIDC).
func (s *Service) handlePublishPaths(c *gin.Context) {
	appID := c.Param("appId")
	ctx := c.Request.Context()

	var req PublishPathsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Load app (incl. previously-resolved public host / landing path).
	var appName, appDesc, targetURL, publicHostCol, landingPathCol string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT name, COALESCE(description,''), target_url, COALESCE(public_host,''), COALESCE(landing_path,'/')
		 FROM published_apps WHERE id=$1`, appID).
		Scan(&appName, &appDesc, &targetURL, &publicHostCol, &landingPathCol)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "app not found"})
		return
	}

	userID := ""
	if uid, exists := c.Get("user_id"); exists {
		userID = uid.(string)
	}

	// Resolve the single public host: explicit request prefix > stored public_host
	// > slug + ACCESS_APPS_DOMAIN.
	explicit := req.FromURLPrefix
	if explicit == "" {
		explicit = publicHostCol
	}
	publicHost, herr := s.resolveAppPublicHost(explicit, appName)
	if herr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": herr.Error()})
		return
	}
	landingPath := landingPathCol
	if landingPath == "" {
		landingPath = "/"
	}
	fromURL := "https://" + publicHost

	// ONE host route for the whole app.
	appRouteID, err := s.ensureHostRoute(ctx, org.ID, appName, fromURL, targetURL, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create app route: " + err.Error()})
		return
	}

	// Link selected discovered paths to the single app route (advisory metadata;
	// NOT separate routes, NOT per-path authz).
	result := &PublishResult{TotalRequested: len(req.PathIDs)}
	for _, pathID := range req.PathIDs {
		var pth string
		if e := s.db.Pool.QueryRow(ctx,
			`SELECT path FROM discovered_paths WHERE id=$1 AND app_id=$2`, pathID, appID).Scan(&pth); e != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("path %s: not found", pathID))
			result.TotalFailed++
			continue
		}
		s.db.Pool.Exec(ctx,
			`UPDATE discovered_paths SET published=true, route_id=$1, updated_at=NOW() WHERE id=$2`, appRouteID, pathID)
		result.Published = append(result.Published, PublishedPathRoute{
			PathID: pathID, RouteID: appRouteID, Path: pth, Name: appName,
		})
		result.TotalPublished++
	}

	// Ziti/BrowZer as a PER-APP toggle (once, clean service name — no path suffix).
	if req.EnableZiti && s.featureManager != nil {
		host, port := parseTargetHostPort(targetURL)
		cfgJSON, _ := json.Marshal(map[string]interface{}{
			"ziti_service_name": "openidx-" + sanitizeName(appName),
			"ziti_host":         host,
			"ziti_port":         port,
		})
		var fc FeatureConfig
		json.Unmarshal(cfgJSON, &fc)
		if err := s.featureManager.EnableFeature(ctx, appRouteID, FeatureZiti, &fc, userID); err != nil {
			s.logger.Warn("Failed to enable Ziti on app route", zap.Error(err))
		} else if req.EnableBrowzer {
			s.featureManager.EnableFeature(ctx, appRouteID, FeatureBrowZer, &FeatureConfig{}, userID)
		}
	}

	// Launcher tile + access-proxy callback + app record.
	s.upsertAppLauncherTile(ctx, org.ID, appID, appName, appDesc, fromURL+landingPath)
	s.registerAccessProxyCallback(ctx, publicHost)
	s.db.Pool.Exec(ctx, `
		UPDATE published_apps SET public_host=$1, landing_path=$2, status='published',
			total_paths_published = (SELECT COUNT(*) FROM discovered_paths WHERE app_id=$3 AND published=true),
			updated_at=NOW() WHERE id=$3`, publicHost, landingPath, appID)

	s.logAuditEvent(c, "app_paths_published", appID, "published_app", map[string]interface{}{
		"route_id":        appRouteID,
		"total_published": result.TotalPublished,
		"total_failed":    result.TotalFailed,
	})

	s.healthEngine.HealRoute(ctx, appRouteID)

	c.JSON(http.StatusOK, result)
}

// PublishAppRequest is the body for the one-click publish endpoint: expose the
// whole app at a public host behind SSO, and surface it as a launcher tile.
type PublishAppRequest struct {
	// PublicHost is the externally reachable host, e.g. "netgraph.apps.tdv.org".
	// If empty, it is derived as "<slug(app.name)>.<ACCESS_APPS_DOMAIN>".
	PublicHost string `json:"public_host"`
	// PreserveHost controls whether the upstream sees the public Host header
	// (defaults true — required when the upstream emits absolute redirects).
	PreserveHost *bool `json:"preserve_host"`
	// LandingPath is where the launcher tile opens (e.g. "/ui/") for apps whose
	// UI is not at the site root. Defaults to "/".
	LandingPath string `json:"landing_path"`
}

type PublishAppResult struct {
	PublicHost string `json:"public_host"`
	PublicURL  string `json:"public_url"`
	RouteID    string `json:"route_id"`
	TileID     string `json:"tile_id"`
	Message    string `json:"message"`
}

// handlePublishApp publishes a whole registered app as a single host-level
// proxy route, auto-creates a "My Apps" launcher tile pointing at the gated
// public URL, and registers the per-host OAuth callback so SSO works without a
// manual OAuth-client edit. This is the "one-click open internal app" path;
// handlePublishPaths remains for fine-grained per-path publishing.
func (s *Service) handlePublishApp(c *gin.Context) {
	appID := c.Param("appId")
	ctx := c.Request.Context()

	var req PublishAppRequest
	// Body is optional; ignore decode errors on empty bodies.
	_ = c.ShouldBindJSON(&req)

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var appName, appDesc, targetURL string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT name, COALESCE(description,''), target_url FROM published_apps WHERE id=$1`, appID).
		Scan(&appName, &appDesc, &targetURL)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "app not found"})
		return
	}

	// Resolve the public host: explicit request value, else slug + base domain.
	publicHost, herr := s.resolveAppPublicHost(req.PublicHost, appName)
	if herr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": herr.Error()})
		return
	}

	preserveHost := true
	if req.PreserveHost != nil {
		preserveHost = *req.PreserveHost
	}

	// Landing path the tile opens at — "/" unless the app's UI lives elsewhere.
	landingPath := strings.TrimSpace(req.LandingPath)
	if landingPath == "" {
		landingPath = "/"
	}
	if !strings.HasPrefix(landingPath, "/") {
		landingPath = "/" + landingPath
	}

	fromURL := "https://" + publicHost
	publicURL := fromURL + landingPath

	routeID, err := s.ensureHostRoute(ctx, org.ID, appName, fromURL, targetURL, preserveHost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create route: " + err.Error()})
		return
	}

	s.upsertAppLauncherTile(ctx, org.ID, appID, appName, appDesc, publicURL)
	s.registerAccessProxyCallback(ctx, publicHost)

	// Record the public host / landing path on the app for display + idempotency.
	s.db.Pool.Exec(ctx,
		`UPDATE published_apps SET public_host=$1, landing_path=$2, status='published', updated_at=NOW() WHERE id=$3`,
		publicHost, landingPath, appID)

	s.logAuditEvent(c, "app_published_oneclick", appID, "published_app", map[string]interface{}{
		"public_host": publicHost, "route_id": routeID,
	})

	c.JSON(http.StatusOK, PublishAppResult{
		PublicHost: publicHost,
		PublicURL:  publicURL,
		RouteID:    routeID,
		TileID:     "proxy-app-" + appID,
		Message:    "App published. It now appears in My Apps.",
	})
}

// ---- Discovery engine ----

func (s *Service) runAppDiscovery(ctx context.Context, appID string) {
	var targetURL, specURL string
	err := s.db.Pool.QueryRow(ctx, `SELECT target_url, COALESCE(spec_url,'') FROM published_apps WHERE id=$1`, appID).
		Scan(&targetURL, &specURL)
	if err != nil {
		s.db.Pool.Exec(ctx, `UPDATE published_apps SET status='error', discovery_error=$1, updated_at=NOW() WHERE id=$2`,
			err.Error(), appID)
		return
	}

	var allPaths []DiscoveredPath
	var strategies []string

	// Strategy 1: OpenAPI / Swagger spec
	if paths, err := s.discoverFromOpenAPI(ctx, targetURL, specURL); err == nil && len(paths) > 0 {
		allPaths = append(allPaths, paths...)
		strategies = append(strategies, "openapi")
	}

	// Strategy 2: Common path probing
	if paths, err := s.discoverFromProbing(ctx, targetURL); err == nil && len(paths) > 0 {
		allPaths = append(allPaths, paths...)
		strategies = append(strategies, "probe")
	}

	// Strategy 3: Sitemap / robots.txt
	if paths, err := s.discoverFromSitemap(ctx, targetURL); err == nil && len(paths) > 0 {
		allPaths = append(allPaths, paths...)
		strategies = append(strategies, "sitemap")
	}

	// Strategy 4: HTML link extraction
	if paths, err := s.discoverFromHTMLCrawl(ctx, targetURL); err == nil && len(paths) > 0 {
		allPaths = append(allPaths, paths...)
		strategies = append(strategies, "html_crawl")
	}

	// Deduplicate
	unique := deduplicatePaths(allPaths)

	// Classify each path
	for i := range unique {
		classifyPath(&unique[i])
	}

	// Clear old auto-classified unpublished paths (allow re-discovery)
	s.db.Pool.Exec(ctx, `DELETE FROM discovered_paths WHERE app_id=$1 AND published=false`, appID)

	// Insert discovered paths
	for _, p := range unique {
		methodsJSON, _ := json.Marshal(p.HTTPMethods)
		rolesJSON, _ := json.Marshal(p.AllowedRoles)
		metadataJSON, _ := json.Marshal(p.Metadata)

		s.db.Pool.Exec(ctx, `
			INSERT INTO discovered_paths (id, app_id, path, http_methods, classification,
				classification_source, discovery_strategy, suggested_policy,
				require_auth, allowed_roles, require_device_trust, metadata)
			VALUES ($1, $2, $3, $4, $5, 'auto', $6, $7, $8, $9, $10, $11)
			ON CONFLICT (app_id, path) DO UPDATE SET
				http_methods = EXCLUDED.http_methods,
				classification = CASE WHEN discovered_paths.classification_source = 'manual'
					THEN discovered_paths.classification ELSE EXCLUDED.classification END,
				updated_at = NOW()`,
			uuid.New().String(), appID, p.Path, methodsJSON, p.Classification,
			p.DiscoveryStrategy, p.SuggestedPolicy, p.RequireAuth, rolesJSON,
			p.RequireDeviceTrust, metadataJSON)
	}

	// Update app
	strategiesJSON, _ := json.Marshal(strategies)
	finalStatus := "discovered"
	if len(unique) == 0 {
		finalStatus = "error"
		s.db.Pool.Exec(ctx, `UPDATE published_apps SET status=$1, discovery_completed_at=NOW(),
			discovery_strategies=$2, total_paths_discovered=0, discovery_error='no paths discovered',
			updated_at=NOW() WHERE id=$3`, finalStatus, strategiesJSON, appID)
		return
	}
	s.db.Pool.Exec(ctx, `UPDATE published_apps SET status=$1, discovery_completed_at=NOW(),
		discovery_strategies=$2, total_paths_discovered=$3, updated_at=NOW() WHERE id=$4`,
		finalStatus, strategiesJSON, len(unique), appID)

	s.logger.Info("App discovery completed",
		zap.String("app_id", appID),
		zap.Int("paths_found", len(unique)),
		zap.Strings("strategies", strategies))
}

// ---- Discovery strategies ----

var openAPISpecPaths = []string{
	"/openapi.json", "/swagger.json", "/api-docs", "/.well-known/openapi.json",
	"/v2/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json",
}

func (s *Service) discoverFromOpenAPI(ctx context.Context, targetURL, specURL string) ([]DiscoveredPath, error) {
	urls := []string{}
	if specURL != "" {
		urls = append(urls, specURL)
	}
	base := strings.TrimSuffix(targetURL, "/")
	for _, p := range openAPISpecPaths {
		urls = append(urls, base+p)
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		resp.Body.Close()

		var spec map[string]interface{}
		if err := json.Unmarshal(body, &spec); err != nil {
			continue
		}

		pathsObj, ok := spec["paths"].(map[string]interface{})
		if !ok {
			continue
		}

		var discovered []DiscoveredPath
		for path, methodsRaw := range pathsObj {
			methods := []string{}
			metadata := map[string]interface{}{}
			if methodMap, ok := methodsRaw.(map[string]interface{}); ok {
				for method, opRaw := range methodMap {
					m := strings.ToUpper(method)
					if m == "GET" || m == "POST" || m == "PUT" || m == "DELETE" || m == "PATCH" {
						methods = append(methods, m)
					}
					if opMap, ok := opRaw.(map[string]interface{}); ok {
						if summary, ok := opMap["summary"].(string); ok {
							metadata["summary"] = summary
						}
						if tags, ok := opMap["tags"].([]interface{}); ok && len(tags) > 0 {
							tagStrs := make([]string, 0, len(tags))
							for _, t := range tags {
								if ts, ok := t.(string); ok {
									tagStrs = append(tagStrs, ts)
								}
							}
							metadata["tags"] = tagStrs
						}
					}
				}
			}
			if len(methods) == 0 {
				methods = []string{"GET"}
			}
			discovered = append(discovered, DiscoveredPath{
				Path:              path,
				HTTPMethods:       methods,
				DiscoveryStrategy: "openapi",
				Metadata:          metadata,
			})
		}
		if len(discovered) > 0 {
			return discovered, nil
		}
	}
	return nil, fmt.Errorf("no OpenAPI spec found")
}

var commonProbePaths = []string{
	"/", "/admin", "/api", "/api/v1", "/health", "/healthz", "/ready",
	"/login", "/logout", "/register", "/signup",
	"/settings", "/config", "/configuration",
	"/dashboard", "/home",
	"/docs", "/documentation", "/swagger-ui", "/redoc",
	"/static", "/assets", "/public",
	"/metrics", "/prometheus", "/status",
	"/graphql", "/graphiql",
	"/api/users", "/api/config", "/api/admin", "/api/health",
	"/api/keys", "/api/tokens", "/api/secrets", "/api/sessions",
	"/favicon.ico", "/robots.txt", "/sitemap.xml",
	"/.well-known/openapi.json", "/.well-known/openid-configuration",
}

func (s *Service) discoverFromProbing(ctx context.Context, targetURL string) ([]DiscoveredPath, error) {
	base := strings.TrimSuffix(targetURL, "/")
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var discovered []DiscoveredPath
	for _, path := range commonProbePaths {
		req, err := http.NewRequestWithContext(ctx, "HEAD", base+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			discovered = append(discovered, DiscoveredPath{
				Path:              path,
				HTTPMethods:       []string{"GET"},
				DiscoveryStrategy: "probe",
			})
		}
	}
	return discovered, nil
}

func (s *Service) discoverFromSitemap(ctx context.Context, targetURL string) ([]DiscoveredPath, error) {
	base := strings.TrimSuffix(targetURL, "/")
	client := &http.Client{Timeout: 10 * time.Second}
	var discovered []DiscoveredPath

	// Try sitemap.xml
	if req, err := http.NewRequestWithContext(ctx, "GET", base+"/sitemap.xml", nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
				locRe := regexp.MustCompile(`<loc>\s*(.*?)\s*</loc>`)
				matches := locRe.FindAllStringSubmatch(string(body), 200)
				parsedBase, _ := url.Parse(base)
				for _, m := range matches {
					if len(m) > 1 {
						u, err := url.Parse(m[1])
						if err != nil {
							continue
						}
						path := u.Path
						if parsedBase != nil && u.Host != "" && u.Host != parsedBase.Host {
							continue
						}
						if path == "" {
							path = "/"
						}
						discovered = append(discovered, DiscoveredPath{
							Path:              path,
							HTTPMethods:       []string{"GET"},
							DiscoveryStrategy: "sitemap",
						})
					}
				}
			}
		}
	}

	// Try robots.txt
	if req, err := http.NewRequestWithContext(ctx, "GET", base+"/robots.txt", nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				lines := strings.Split(string(body), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "Allow:") || strings.HasPrefix(line, "Disallow:") {
						parts := strings.SplitN(line, ":", 2)
						if len(parts) == 2 {
							path := strings.TrimSpace(parts[1])
							if path != "" && path != "/" && !strings.Contains(path, "*") {
								discovered = append(discovered, DiscoveredPath{
									Path:              path,
									HTTPMethods:       []string{"GET"},
									DiscoveryStrategy: "sitemap",
								})
							}
						}
					}
				}
			}
		}
	}

	return discovered, nil
}

var hrefRe = regexp.MustCompile(`href=["']([^"'#]+)["']`)

func (s *Service) discoverFromHTMLCrawl(ctx context.Context, targetURL string) ([]DiscoveredPath, error) {
	base := strings.TrimSuffix(targetURL, "/")
	parsedBase, err := url.Parse(base)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("root page returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	matches := hrefRe.FindAllStringSubmatch(string(body), 200)

	seen := map[string]bool{}
	var discovered []DiscoveredPath

	for _, m := range matches {
		if len(m) < 2 || len(discovered) >= 100 {
			break
		}
		href := m[1]
		u, err := url.Parse(href)
		if err != nil {
			continue
		}

		// Resolve relative URLs
		if !u.IsAbs() {
			u = parsedBase.ResolveReference(u)
		}

		// Only same-host links
		if u.Host != "" && u.Host != parsedBase.Host {
			continue
		}

		path := u.Path
		if path == "" {
			path = "/"
		}

		// Skip static assets with extensions
		if strings.Contains(path, ".css") || strings.Contains(path, ".js") ||
			strings.Contains(path, ".png") || strings.Contains(path, ".jpg") ||
			strings.Contains(path, ".svg") || strings.Contains(path, ".woff") {
			continue
		}

		if !seen[path] {
			seen[path] = true
			discovered = append(discovered, DiscoveredPath{
				Path:              path,
				HTTPMethods:       []string{"GET"},
				DiscoveryStrategy: "html_crawl",
			})
		}
	}

	return discovered, nil
}

// ---- Classification engine ----

func classifyPath(p *DiscoveredPath) {
	path := strings.ToLower(p.Path)
	hasDelete := containsMethod(p.HTTPMethods, "DELETE")

	// Critical: admin, settings, system, or any DELETE endpoint
	if matchesPattern(path, "/admin", "/settings", "/system", "/internal", "/management") || hasDelete {
		p.Classification = ClassCritical
		p.RequireAuth = true
		p.AllowedRoles = []string{"admin"}
		p.RequireDeviceTrust = true
		p.SuggestedPolicy = `user.roles in ["admin"] AND device.trusted == true`
		return
	}

	// Sensitive: user data, keys, tokens, secrets
	if matchesPattern(path, "/api/users", "/api/keys", "/api/tokens", "/api/secrets",
		"/api/credentials", "/api/passwords", "/api/v1/users", "/api/v1/keys",
		"/api/v1/tokens", "/api/v1/secrets") {
		p.Classification = ClassSensitive
		p.RequireAuth = true
		p.AllowedRoles = []string{"admin"}
		p.RequireDeviceTrust = false
		p.SuggestedPolicy = `user.roles in ["admin"]`
		return
	}

	// Public: health, login, docs, static assets
	if matchesPattern(path, "/health", "/healthz", "/ready", "/login", "/logout",
		"/register", "/signup", "/docs", "/documentation", "/swagger",
		"/redoc", "/static", "/assets", "/public", "/favicon",
		"/robots.txt", "/sitemap.xml", "/.well-known") || path == "/" {
		p.Classification = ClassPublic
		p.RequireAuth = false
		p.AllowedRoles = []string{}
		p.SuggestedPolicy = ""
		return
	}

	// Default: Protected (authenticated, any role)
	p.Classification = ClassProtected
	p.RequireAuth = true
	p.AllowedRoles = []string{}
	p.SuggestedPolicy = ""
}

// ---- Helpers ----

func deduplicatePaths(paths []DiscoveredPath) []DiscoveredPath {
	seen := map[string]int{}
	var result []DiscoveredPath

	for _, p := range paths {
		if idx, exists := seen[p.Path]; exists {
			// Merge HTTP methods
			existing := &result[idx]
			methodSet := map[string]bool{}
			for _, m := range existing.HTTPMethods {
				methodSet[m] = true
			}
			for _, m := range p.HTTPMethods {
				methodSet[m] = true
			}
			merged := make([]string, 0, len(methodSet))
			for m := range methodSet {
				merged = append(merged, m)
			}
			existing.HTTPMethods = merged
			// Merge metadata
			if p.Metadata != nil {
				if existing.Metadata == nil {
					existing.Metadata = map[string]interface{}{}
				}
				for k, v := range p.Metadata {
					existing.Metadata[k] = v
				}
			}
		} else {
			seen[p.Path] = len(result)
			result = append(result, p)
		}
	}
	return result
}

func matchesPattern(path string, patterns ...string) bool {
	for _, pat := range patterns {
		if path == pat || strings.HasPrefix(path, pat+"/") || strings.HasPrefix(path, pat) {
			return true
		}
	}
	return false
}

func containsMethod(methods []string, target string) bool {
	for _, m := range methods {
		if strings.EqualFold(m, target) {
			return true
		}
	}
	return false
}

func parseTargetHostPort(targetURL string) (string, int) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "localhost", 80
	}
	host := u.Hostname()
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	return host, port
}

// handleConsolidateApp collapses an app that was previously exploded into many
// per-path routes (legacy publish) down to a single host route, tearing down the
// orphaned per-path Ziti services/policies/configs and stale APISIX routes.
func (s *Service) handleConsolidateApp(c *gin.Context) {
	appID := c.Param("appId")
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := ""
	if uid, exists := c.Get("user_id"); exists {
		userID = uid.(string)
	}
	routeID, paths, err := s.consolidateApp(c.Request.Context(), org.ID, appID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.logAuditEvent(c, "app_consolidated", appID, "published_app", map[string]interface{}{
		"route_id": routeID, "paths_relinked": paths,
	})
	c.JSON(http.StatusOK, gin.H{
		"route_id": routeID, "paths_relinked": paths,
		"message": "App consolidated to a single host route.",
	})
}

// consolidateApp collapses all of an app's routes (the legacy per-path explosion)
// into one canonical host route. It tears down each old route's Ziti service +
// policies + host.v1 + SERP (via TeardownZitiForRoute, which must run BEFORE the
// proxy_routes row is deleted — it reads ziti_services.route_id), deletes the old
// routes + their per-route tiles, repoints discovered_paths to the canonical
// route, re-enables Ziti/BrowZer once (clean service name), and regenerates the
// edge (RegenerateConfigs prunes stale browzer-* APISIX routes). Idempotent.
func (s *Service) consolidateApp(ctx context.Context, orgID, appID, userID string) (string, int, error) {
	var appName, appDesc, targetURL, publicHostCol string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT name, COALESCE(description,''), target_url, COALESCE(public_host,'') FROM published_apps WHERE id=$1`,
		appID).Scan(&appName, &appDesc, &targetURL, &publicHostCol); err != nil {
		return "", 0, fmt.Errorf("app not found: %w", err)
	}
	publicHost, err := s.resolveAppPublicHost(publicHostCol, appName)
	if err != nil {
		return "", 0, err
	}
	fromURL := "https://" + publicHost

	// Collect every existing route for this app: those linked from discovered_paths
	// plus any proxy_route on this host (the exploded per-path ones carry a path).
	routeIDs := map[string]bool{}
	if rows, e := s.db.Pool.Query(ctx,
		`SELECT DISTINCT route_id FROM discovered_paths WHERE app_id=$1 AND route_id IS NOT NULL`, appID); e == nil {
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				routeIDs[id] = true
			}
		}
		rows.Close()
	}
	if rows, e := s.db.Pool.Query(ctx,
		//orgscope:ignore scoped by org_id in predicate
		`SELECT id FROM proxy_routes WHERE org_id=$1 AND (from_url=$2 OR from_url LIKE $3)`,
		orgID, fromURL, fromURL+"/%"); e == nil {
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				routeIDs[id] = true
			}
		}
		rows.Close()
	}

	// Did the app have Ziti/BrowZer on any route?
	var hadZiti, hadBrowzer bool
	for id := range routeIDs {
		var z, b bool
		s.db.Pool.QueryRow(ctx,
			`SELECT COALESCE(ziti_enabled,false), COALESCE(browzer_enabled,false) FROM proxy_routes WHERE id=$1`, id).Scan(&z, &b)
		hadZiti = hadZiti || z
		hadBrowzer = hadBrowzer || b
	}

	// Tear down Ziti for each old route BEFORE deleting the rows (teardown reads
	// ziti_services.route_id), then delete the routes + their per-route tiles.
	zm := s.ziti()
	for id := range routeIDs {
		if zm != nil {
			if err := zm.TeardownZitiForRoute(ctx, id); err != nil {
				s.logger.Warn("consolidate: ziti teardown failed", zap.String("route_id", id), zap.Error(err))
			}
		}
	}
	// The reconciler creates controller services WITHOUT a ziti_services row, so
	// the DB-driven teardown above misses them. Sweep the legacy per-path service
	// names by name — computed precisely from the app's discovered paths
	// (openidx-<app><path>, the old derivation), excluding the canonical
	// openidx-<app>. Precise computation avoids matching a different app's prefix.
	if zm != nil {
		canonicalSvc := "openidx-" + sanitizeName(appName)
		if rows, e := s.db.Pool.Query(ctx, `SELECT path FROM discovered_paths WHERE app_id=$1`, appID); e == nil {
			var paths []string
			for rows.Next() {
				var p string
				if rows.Scan(&p) == nil {
					paths = append(paths, p)
				}
			}
			rows.Close()
			for _, p := range paths {
				legacy := "openidx-" + sanitizeName(appName) + sanitizeName(p)
				if legacy != canonicalSvc {
					if err := zm.TeardownZitiServiceByName(ctx, legacy); err != nil {
						s.logger.Warn("consolidate: legacy ziti service teardown failed", zap.String("svc", legacy), zap.Error(err))
					}
				}
			}
		}
	}
	// Unlink discovered_paths first (FK is ON DELETE SET NULL; unlink keeps it explicit).
	s.db.Pool.Exec(ctx, `UPDATE discovered_paths SET route_id=NULL WHERE app_id=$1`, appID)
	for id := range routeIDs {
		s.db.Pool.Exec(ctx, `DELETE FROM proxy_routes WHERE id=$1 AND org_id=$2`, id, orgID)
		s.deleteAppTile(ctx, id)
	}

	// One canonical host route.
	canonicalID, err := s.ensureHostRoute(ctx, orgID, appName, fromURL, targetURL, true)
	if err != nil {
		return "", 0, err
	}
	res, _ := s.db.Pool.Exec(ctx,
		`UPDATE discovered_paths SET route_id=$1, published=true, updated_at=NOW() WHERE app_id=$2`, canonicalID, appID)
	pathCount := int(res.RowsAffected())

	// Re-enable Ziti/BrowZer once on the canonical route (clean service name).
	if hadZiti && s.featureManager != nil {
		host, port := parseTargetHostPort(targetURL)
		cfgJSON, _ := json.Marshal(map[string]interface{}{
			"ziti_service_name": "openidx-" + sanitizeName(appName),
			"ziti_host":         host,
			"ziti_port":         port,
		})
		var fc FeatureConfig
		json.Unmarshal(cfgJSON, &fc)
		if err := s.featureManager.EnableFeature(ctx, canonicalID, FeatureZiti, &fc, userID); err != nil {
			s.logger.Warn("consolidate: enable ziti failed", zap.Error(err))
		} else if hadBrowzer {
			s.featureManager.EnableFeature(ctx, canonicalID, FeatureBrowZer, &FeatureConfig{}, userID)
		}
	}

	s.upsertAppLauncherTile(ctx, orgID, appID, appName, appDesc, fromURL+"/")
	s.registerAccessProxyCallback(ctx, publicHost)
	s.db.Pool.Exec(ctx, `
		UPDATE published_apps SET public_host=$1, status='published',
			total_paths_published=(SELECT COUNT(*) FROM discovered_paths WHERE app_id=$2 AND published=true),
			updated_at=NOW() WHERE id=$2`, publicHost, appID)

	// Regenerate the edge (prunes stale browzer-* APISIX routes) + reconcile Ziti.
	if s.browzerTargetManager != nil {
		if err := s.browzerTargetManager.RegenerateConfigs(ctx); err != nil {
			s.logger.Warn("consolidate: regenerate configs failed", zap.Error(err))
		}
	}
	s.enqueueReconcile()
	s.healthEngine.HealRoute(ctx, canonicalID)
	return canonicalID, pathCount, nil
}

// handleGetAppZitiServices returns Ziti services linked to a published app
// via the chain: published_apps → discovered_paths → proxy_routes → ziti_services
func (s *Service) handleGetAppZitiServices(c *gin.Context) {
	appID := c.Param("appId")
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var appName string
	err = s.db.Pool.QueryRow(ctx, `SELECT name FROM published_apps WHERE id=$1`, appID).Scan(&appName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "app not found"})
		return
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT DISTINCT zs.id, zs.ziti_id, zs.name, COALESCE(zs.description,''), zs.protocol,
		       zs.host, zs.port, zs.enabled, dp.path, COALESCE(dp.classification,''), pr.name as route_name
		FROM discovered_paths dp
		JOIN proxy_routes pr ON pr.id = dp.route_id
		JOIN ziti_services zs ON zs.name = pr.ziti_service_name AND zs.org_id = pr.org_id
		WHERE dp.app_id = $1 AND dp.published = true AND pr.ziti_service_name IS NOT NULL AND pr.org_id = $2
		ORDER BY zs.name`, appID, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type appZitiService struct {
		ID             string `json:"id"`
		ZitiID         string `json:"ziti_id"`
		Name           string `json:"name"`
		Description    string `json:"description,omitempty"`
		Protocol       string `json:"protocol"`
		Host           string `json:"host"`
		Port           int    `json:"port"`
		Enabled        bool   `json:"enabled"`
		LinkedPath     string `json:"linked_path"`
		Classification string `json:"classification"`
		RouteName      string `json:"route_name"`
	}

	var services []appZitiService
	for rows.Next() {
		var svc appZitiService
		if err := rows.Scan(&svc.ID, &svc.ZitiID, &svc.Name, &svc.Description, &svc.Protocol,
			&svc.Host, &svc.Port, &svc.Enabled, &svc.LinkedPath, &svc.Classification, &svc.RouteName); err != nil {
			continue
		}
		services = append(services, svc)
	}
	if services == nil {
		services = []appZitiService{}
	}
	c.JSON(http.StatusOK, gin.H{"services": services, "app_name": appName})
}

func sanitizeName(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "_", "-")
	// Remove leading/trailing dashes
	s = strings.Trim(s, "-")
	return s
}
