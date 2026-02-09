// Package access provides BrowZer bootstrapper target configuration management.
// The BrowZer bootstrapper reads targets from a config.json file (via nconf).
// This file generates that config from the database whenever BrowZer targets change.
// It also generates the nginx router config for path-based BrowZer routing.
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

const (
	// BrowZerRouterServiceName is the Ziti service name for the path-based router
	BrowZerRouterServiceName = "browzer-router-zt"
	// BrowZerRouterHost is the Docker service name for the router
	BrowZerRouterHost = "browzer-router"
	// BrowZerRouterPort is the port the router listens on
	BrowZerRouterPort = 80
	// DefaultBrowZerDomain is the default domain for path-based BrowZer routing
	DefaultBrowZerDomain = "browzer.localtest.me"
)

// BrowZerTarget represents a single target entry for the bootstrapper
type BrowZerTarget struct {
	VHost        string `json:"vhost"`
	Service      string `json:"service"`
	Path         string `json:"path"`
	Scheme       string `json:"scheme"`
	IDPIssuerURL string `json:"idp_issuer_base_url"`
	IDPClientID  string `json:"idp_client_id"`
}

// BrowZerTargetArray is the top-level structure the bootstrapper expects
type BrowZerTargetArray struct {
	TargetArray []BrowZerTarget `json:"targetArray"`
}

// BrowZerTargetManager handles generation and writing of bootstrapper targets and router config
type BrowZerTargetManager struct {
	db               *database.PostgresDB
	logger           *zap.Logger
	targetsPath      string
	routerConfigPath string
	mu               sync.Mutex
}

// NewBrowZerTargetManager creates a new target manager
func NewBrowZerTargetManager(db *database.PostgresDB, logger *zap.Logger, targetsPath string) *BrowZerTargetManager {
	return &BrowZerTargetManager{
		db:          db,
		logger:      logger.With(zap.String("component", "browzer_targets")),
		targetsPath: targetsPath,
	}
}

// SetRouterConfigPath sets the path for the nginx router config file
func (tm *BrowZerTargetManager) SetRouterConfigPath(path string) {
	tm.routerConfigPath = path
}

// browzerRouteInfo holds parsed route information for target/router generation
type browzerRouteInfo struct {
	fromURL     string
	toURL       string
	serviceName string
	hostname    string
	pathPrefix  string
}

// queryBrowZerRoutes fetches all BrowZer-enabled routes from the database
func (tm *BrowZerTargetManager) queryBrowZerRoutes(ctx context.Context) ([]browzerRouteInfo, error) {
	rows, err := tm.db.Pool.Query(ctx,
		`SELECT from_url, to_url, ziti_service_name
		 FROM proxy_routes
		 WHERE ziti_enabled = true
		   AND browzer_enabled = true
		   AND ziti_service_name IS NOT NULL
		   AND ziti_service_name != ''
		   AND enabled = true
		 ORDER BY priority DESC, name`)
	if err != nil {
		return nil, fmt.Errorf("failed to query BrowZer-enabled routes: %w", err)
	}
	defer rows.Close()

	var routes []browzerRouteInfo
	for rows.Next() {
		var fromURL, toURL, serviceName string
		if err := rows.Scan(&fromURL, &toURL, &serviceName); err != nil {
			tm.logger.Warn("Failed to scan route row", zap.Error(err))
			continue
		}

		info := browzerRouteInfo{
			fromURL:     fromURL,
			toURL:       toURL,
			serviceName: serviceName,
			hostname:    fromURL,
			pathPrefix:  "/",
		}

		if parsed, err := url.Parse(fromURL); err == nil && parsed.Host != "" {
			info.hostname = parsed.Hostname()
			if parsed.Path != "" && parsed.Path != "/" {
				info.pathPrefix = parsed.Path
			}
		}

		routes = append(routes, info)
	}
	return routes, nil
}

// GenerateBrowZerTargets queries the database for all BrowZer-enabled routes
// and builds the target configuration JSON for the bootstrapper.
// Routes with a path prefix on the default BrowZer domain are grouped into a single
// router target; routes with unique domains get individual targets.
func (tm *BrowZerTargetManager) GenerateBrowZerTargets(ctx context.Context) (*BrowZerTargetArray, error) {
	// Get OIDC settings from BrowZer config
	var oidcIssuer, oidcClientID string
	err := tm.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(oidc_issuer, ''), COALESCE(oidc_client_id, '')
		 FROM ziti_browzer_config WHERE enabled = true LIMIT 1`).Scan(&oidcIssuer, &oidcClientID)
	if err != nil {
		tm.logger.Debug("No BrowZer config found, generating empty targets", zap.Error(err))
		return &BrowZerTargetArray{TargetArray: []BrowZerTarget{}}, nil
	}

	routes, err := tm.queryBrowZerRoutes(ctx)
	if err != nil {
		return nil, err
	}

	var targets []BrowZerTarget
	hasRouterTarget := false

	for _, r := range routes {
		// Routes with a path prefix on the default BrowZer domain → router target
		if r.hostname == DefaultBrowZerDomain && r.pathPrefix != "/" {
			if !hasRouterTarget {
				targets = append(targets, BrowZerTarget{
					VHost:        DefaultBrowZerDomain,
					Service:      BrowZerRouterServiceName,
					Path:         "/",
					Scheme:       "http",
					IDPIssuerURL: oidcIssuer,
					IDPClientID:  oidcClientID,
				})
				hasRouterTarget = true
			}
			continue
		}

		// Routes with unique domains → direct targets
		targets = append(targets, BrowZerTarget{
			VHost:        r.hostname,
			Service:      r.serviceName,
			Path:         "/",
			Scheme:       "http",
			IDPIssuerURL: oidcIssuer,
			IDPClientID:  oidcClientID,
		})
	}

	if targets == nil {
		targets = []BrowZerTarget{}
	}

	tm.logger.Info("Generated BrowZer targets",
		zap.Int("count", len(targets)),
		zap.Bool("router_target", hasRouterTarget))
	return &BrowZerTargetArray{TargetArray: targets}, nil
}

// WriteBrowZerTargets generates the target config and writes it to the shared config file.
// The file is written in the nconf config.json format where the targets JSON is a string value.
func (tm *BrowZerTargetManager) WriteBrowZerTargets(ctx context.Context) error {
	if tm.targetsPath == "" {
		tm.logger.Debug("No targets path configured, skipping write")
		return nil
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	targets, err := tm.GenerateBrowZerTargets(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate targets: %w", err)
	}

	// The bootstrapper's nconf expects config.json with the targets as a JSON string value
	targetsJSON, err := json.Marshal(targets)
	if err != nil {
		return fmt.Errorf("failed to marshal targets: %w", err)
	}

	// Build the nconf config.json format
	configMap := map[string]string{
		"ZITI_BROWZER_BOOTSTRAPPER_TARGETS": string(targetsJSON),
	}
	configJSON, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := writeFileAtomic(tm.targetsPath, configJSON); err != nil {
		return err
	}

	tm.logger.Info("BrowZer targets written",
		zap.String("path", tm.targetsPath),
		zap.Int("targets", len(targets.TargetArray)))
	return nil
}

// GenerateBrowZerRouterConfig generates nginx config for path-based BrowZer routing.
// Routes with a path prefix on browzer.localtest.me get location blocks mapping to their backends.
func (tm *BrowZerTargetManager) GenerateBrowZerRouterConfig(ctx context.Context) ([]byte, error) {
	routes, err := tm.queryBrowZerRoutes(ctx)
	if err != nil {
		return nil, err
	}

	// Filter to path-based routes on the default BrowZer domain
	type routeMapping struct {
		pathPrefix string
		upstream   string
		isGuac     bool
	}
	var mappings []routeMapping

	for _, r := range routes {
		if r.hostname != DefaultBrowZerDomain || r.pathPrefix == "/" {
			continue
		}

		upstream := r.toURL
		isGuac := false

		// Special case: Guacamole routes use the ZBR proxy for fetch tunnel injection
		if strings.Contains(r.toURL, "guacamole") || strings.Contains(r.serviceName, "guacamole") {
			upstream = "http://guacamole-zbr-proxy:80"
			isGuac = true
		}

		mappings = append(mappings, routeMapping{
			pathPrefix: r.pathPrefix,
			upstream:   upstream,
			isGuac:     isGuac,
		})
	}

	// Build nginx config
	var b strings.Builder
	b.WriteString("# Auto-generated BrowZer router config — do not edit manually\n")
	b.WriteString("server {\n")
	b.WriteString("    listen 80;\n")
	b.WriteString("    server_name _;\n")
	b.WriteString("    absolute_redirect off;\n\n")

	// Generate location blocks for each path-based route
	for _, m := range mappings {
		pathWithSlash := m.pathPrefix
		if !strings.HasSuffix(pathWithSlash, "/") {
			pathWithSlash += "/"
		}

		b.WriteString(fmt.Sprintf("    location %s {\n", pathWithSlash))

		if m.isGuac {
			// Guacamole keeps the prefix (it expects /guacamole)
			b.WriteString(fmt.Sprintf("        proxy_pass %s%s;\n", m.upstream, pathWithSlash))
			b.WriteString("        proxy_http_version 1.1;\n")
			b.WriteString("        proxy_set_header Host $host;\n")
			b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
			b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
			b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
			b.WriteString("        proxy_read_timeout 86400s;\n")
			b.WriteString("        proxy_send_timeout 86400s;\n")
			b.WriteString("        proxy_buffering off;\n")
		} else {
			// Strip path prefix: trailing slash on proxy_pass strips the matched prefix
			parsed, _ := url.Parse(m.upstream)
			upstreamBase := fmt.Sprintf("%s://%s/", parsed.Scheme, parsed.Host)
			b.WriteString(fmt.Sprintf("        proxy_pass %s;\n", upstreamBase))
			b.WriteString("        proxy_http_version 1.1;\n")
			b.WriteString("        proxy_set_header Host $host;\n")
			b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
			b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
			b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
		}

		b.WriteString("    }\n\n")
	}

	// Landing page listing available services
	b.WriteString("    location / {\n")
	b.WriteString("        default_type text/html;\n")
	b.WriteString("        return 200 '<!DOCTYPE html><html><head><title>OpenIDX BrowZer Services</title>")
	b.WriteString("<style>body{font-family:system-ui;max-width:600px;margin:40px auto;padding:0 20px}")
	b.WriteString("a{display:block;padding:12px;margin:8px 0;background:#f0f0f0;border-radius:8px;text-decoration:none;color:#333}")
	b.WriteString("a:hover{background:#e0e0e0}</style></head><body>")
	b.WriteString("<h1>OpenIDX BrowZer Services</h1><p>Available services:</p>")
	for _, m := range mappings {
		label := strings.TrimPrefix(m.pathPrefix, "/")
		b.WriteString(fmt.Sprintf("<a href=\"%s\">%s</a>", m.pathPrefix, label))
	}
	b.WriteString("</body></html>';\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")

	tm.logger.Info("Generated BrowZer router config", zap.Int("routes", len(mappings)))
	return []byte(b.String()), nil
}

// WriteBrowZerRouterConfig generates the nginx router config and writes it to the shared config file.
func (tm *BrowZerTargetManager) WriteBrowZerRouterConfig(ctx context.Context) error {
	if tm.routerConfigPath == "" {
		tm.logger.Debug("No router config path configured, skipping write")
		return nil
	}

	config, err := tm.GenerateBrowZerRouterConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate router config: %w", err)
	}

	if err := writeFileAtomic(tm.routerConfigPath, config); err != nil {
		return err
	}

	tm.logger.Info("BrowZer router config written",
		zap.String("path", tm.routerConfigPath))
	return nil
}

// writeFileAtomic writes data to a file using a temp file + rename pattern for atomicity.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp config: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename config: %w", err)
	}
	return nil
}
