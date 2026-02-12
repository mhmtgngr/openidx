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
	TotalRequested int             `json:"total_requested"`
	TotalPublished int             `json:"total_published"`
	TotalFailed    int             `json:"total_failed"`
	Published      []PublishedPathRoute `json:"published"`
	Errors         []string        `json:"errors,omitempty"`
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

	go s.runAppDiscovery(context.Background(), appID)

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

	// Build dynamic update
	sets := []string{"classification_source='manual'", "updated_at=NOW()"}
	args := []interface{}{}
	argIdx := 1

	if req.Classification != "" {
		sets = append(sets, fmt.Sprintf("classification=$%d", argIdx))
		args = append(args, req.Classification)
		argIdx++
	}
	if req.AllowedRoles != nil {
		rolesJSON, _ := json.Marshal(req.AllowedRoles)
		sets = append(sets, fmt.Sprintf("allowed_roles=$%d", argIdx))
		args = append(args, rolesJSON)
		argIdx++
	}
	if req.RequireAuth != nil {
		sets = append(sets, fmt.Sprintf("require_auth=$%d", argIdx))
		args = append(args, *req.RequireAuth)
		argIdx++
	}
	if req.RequireDeviceTrust != nil {
		sets = append(sets, fmt.Sprintf("require_device_trust=$%d", argIdx))
		args = append(args, *req.RequireDeviceTrust)
		argIdx++
	}
	if req.SuggestedPolicy != "" {
		sets = append(sets, fmt.Sprintf("suggested_policy=$%d", argIdx))
		args = append(args, req.SuggestedPolicy)
		argIdx++
	}

	args = append(args, pathID)
	query := fmt.Sprintf("UPDATE discovered_paths SET %s WHERE id=$%d", strings.Join(sets, ", "), argIdx)

	tag, err := s.db.Pool.Exec(ctx, query, args...)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "path not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "classification updated"})
}

func (s *Service) handlePublishPaths(c *gin.Context) {
	appID := c.Param("appId")
	ctx := c.Request.Context()

	var req PublishPathsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Load app
	var appName, targetURL string
	err := s.db.Pool.QueryRow(ctx, `SELECT name, target_url FROM published_apps WHERE id=$1`, appID).Scan(&appName, &targetURL)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "app not found"})
		return
	}

	userID := ""
	if uid, exists := c.Get("user_id"); exists {
		userID = uid.(string)
	}

	result := &PublishResult{TotalRequested: len(req.PathIDs)}

	for _, pathID := range req.PathIDs {
		var dp DiscoveredPath
		var methodsJSON, rolesJSON []byte
		err := s.db.Pool.QueryRow(ctx, `
			SELECT id, path, http_methods, classification, suggested_policy,
			       require_auth, allowed_roles, require_device_trust, published
			FROM discovered_paths WHERE id=$1 AND app_id=$2`, pathID, appID).
			Scan(&dp.ID, &dp.Path, &methodsJSON, &dp.Classification, &dp.SuggestedPolicy,
				&dp.RequireAuth, &rolesJSON, &dp.RequireDeviceTrust, &dp.Published)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("path %s: not found", pathID))
			result.TotalFailed++
			continue
		}
		json.Unmarshal(methodsJSON, &dp.HTTPMethods)
		json.Unmarshal(rolesJSON, &dp.AllowedRoles)

		if dp.Published {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: already published", dp.Path))
			result.TotalFailed++
			continue
		}

		routeName := fmt.Sprintf("%s - %s", appName, dp.Path)
		toURL := strings.TrimSuffix(targetURL, "/") + dp.Path

		fromURL := toURL
		if req.FromURLPrefix != "" {
			fromURL = strings.TrimSuffix(req.FromURLPrefix, "/") + dp.Path
		}

		routeID := uuid.New().String()
		if dp.AllowedRoles == nil {
			dp.AllowedRoles = []string{}
		}
		rolesJSON, _ = json.Marshal(dp.AllowedRoles)

		_, err = s.db.Pool.Exec(ctx, `
			INSERT INTO proxy_routes (id, name, description, from_url, to_url,
				require_auth, allowed_roles, enabled, priority, route_type,
				inline_policy, require_device_trust, max_risk_score,
				allowed_groups, policy_ids, cors_allowed_origins, custom_headers,
				posture_check_ids, allowed_countries, idle_timeout, absolute_timeout)
			VALUES ($1, $2, $3, $4, $5, $6, $7, true, 0, 'http',
				$8, $9, 100,
				'[]', '[]', '[]', '{}', '[]', '[]', 900, 43200)`,
			routeID, routeName,
			fmt.Sprintf("Auto-published from %s app discovery", appName),
			fromURL, toURL, dp.RequireAuth, rolesJSON,
			dp.SuggestedPolicy, dp.RequireDeviceTrust)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", dp.Path, err.Error()))
			result.TotalFailed++
			continue
		}

		// Enable Ziti/BrowZer if requested
		if req.EnableZiti && s.featureManager != nil {
			host, port := parseTargetHostPort(targetURL)
			svcName := fmt.Sprintf("openidx-%s%s", sanitizeName(appName), sanitizeName(dp.Path))
			cfg := map[string]interface{}{
				"ziti_service_name": svcName,
				"ziti_host":         host,
				"ziti_port":         port,
			}
			cfgJSON, _ := json.Marshal(cfg)
			var fc FeatureConfig
			json.Unmarshal(cfgJSON, &fc)
			if err := s.featureManager.EnableFeature(ctx, routeID, FeatureZiti, &fc, userID); err != nil {
				s.logger.Warn("Failed to enable Ziti on published route", zap.Error(err))
			} else if req.EnableBrowzer {
				s.featureManager.EnableFeature(ctx, routeID, FeatureBrowZer, &FeatureConfig{}, userID)
			}
		}

		// Mark path as published
		s.db.Pool.Exec(ctx, `UPDATE discovered_paths SET published=true, route_id=$1, updated_at=NOW() WHERE id=$2`, routeID, pathID)

		result.Published = append(result.Published, PublishedPathRoute{
			PathID: pathID, RouteID: routeID, Path: dp.Path, Name: routeName,
		})
		result.TotalPublished++
	}

	// Update app counters
	s.db.Pool.Exec(ctx, `
		UPDATE published_apps SET total_paths_published = (
			SELECT COUNT(*) FROM discovered_paths WHERE app_id=$1 AND published=true
		), status = 'published', updated_at=NOW() WHERE id=$1`, appID)

	s.logAuditEvent(c, "app_paths_published", appID, "published_app", map[string]interface{}{
		"total_published": result.TotalPublished,
		"total_failed":    result.TotalFailed,
	})

	c.JSON(http.StatusOK, result)
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

func sanitizeName(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "_", "-")
	// Remove leading/trailing dashes
	s = strings.Trim(s, "-")
	return s
}
