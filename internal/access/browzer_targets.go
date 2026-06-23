// Package access provides BrowZer bootstrapper target configuration management.
// The BrowZer bootstrapper reads targets from a config.json file (via nconf).
// This file generates that config from the database whenever BrowZer targets change.
// It also generates the nginx router config for path-based BrowZer routing.
package access

import (
	"bufio"
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
	"github.com/openidx/openidx/internal/common/orgctx"
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
	certsPath        string
	domain           string
	dnsResolvers     string // nginx resolver addresses (auto-detected from /etc/resolv.conf)
	mu               sync.Mutex
}

// NewBrowZerTargetManager creates a new target manager
func NewBrowZerTargetManager(db *database.PostgresDB, logger *zap.Logger, targetsPath string) *BrowZerTargetManager {
	tm := &BrowZerTargetManager{
		db:          db,
		logger:      logger.With(zap.String("component", "browzer_targets")),
		targetsPath: targetsPath,
	}
	tm.dnsResolvers = tm.detectDNSResolvers()
	return tm
}

// detectDNSResolvers reads /etc/resolv.conf to build the nginx resolver string.
// Docker's embedded DNS (127.0.0.11) round-robins queries to external servers,
// so if a public DNS (e.g. 8.8.8.8) returns NXDOMAIN for an internal domain before
// the corporate DNS responds, resolution fails. To fix this, we extract the external
// DNS servers and prefer private/corporate ones that can resolve both internal and
// external domains. If none are found, fall back to 127.0.0.11.
func (tm *BrowZerTargetManager) detectDNSResolvers() string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "127.0.0.11"
	}
	defer f.Close()

	var allServers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Docker adds: # ExtServers: [8.8.8.8 8.8.4.4 10.10.12.30]
		if strings.Contains(line, "ExtServers:") {
			start := strings.Index(line, "[")
			end := strings.Index(line, "]")
			if start >= 0 && end > start {
				allServers = strings.Fields(line[start+1 : end])
			}
		}
	}

	// Filter to private/corporate DNS servers (RFC 1918 ranges).
	// These can resolve both internal and external domains, unlike public DNS
	// which returns NXDOMAIN for internal corporate domains.
	var privateServers []string
	for _, s := range allServers {
		if isPrivateIP(s) {
			privateServers = append(privateServers, s)
		}
	}

	var result string
	if len(privateServers) > 0 {
		result = strings.Join(privateServers, " ")
	} else if len(allServers) > 0 {
		// No private servers found — use all (probably no internal domains)
		result = "127.0.0.11 " + strings.Join(allServers, " ")
	} else {
		result = "127.0.0.11"
	}

	tm.logger.Info("Detected DNS resolvers for nginx",
		zap.String("resolvers", result),
		zap.Strings("all_ext_servers", allServers),
		zap.Strings("private_servers", privateServers))
	return result
}

// isPrivateIP returns true if the IP is in RFC 1918 private ranges
// (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
func isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		(strings.HasPrefix(ip, "172.") && len(ip) > 4 && ip[4] == '.' &&
			ip[3] >= '1' && ip[3] <= '3') // 172.16-31.x.x
}

// SetRouterConfigPath sets the path for the nginx router config file
func (tm *BrowZerTargetManager) SetRouterConfigPath(path string) {
	tm.routerConfigPath = path
}

// SetCertsPath sets the path for the shared BrowZer certificates directory
func (tm *BrowZerTargetManager) SetCertsPath(path string) {
	tm.certsPath = path
}

// GetCertsPath returns the configured certificates directory path
func (tm *BrowZerTargetManager) GetCertsPath() string {
	return tm.certsPath
}

// GetDomain returns the current BrowZer domain, falling back to DefaultBrowZerDomain
func (tm *BrowZerTargetManager) GetDomain() string {
	if tm.domain != "" {
		return tm.domain
	}
	return DefaultBrowZerDomain
}

// SetDomain sets the BrowZer domain
func (tm *BrowZerTargetManager) SetDomain(domain string) {
	tm.domain = domain
}

// LoadDomainFromDB reads the browzer_domain_config from system_settings and sets the domain
func (tm *BrowZerTargetManager) LoadDomainFromDB(ctx context.Context) error {
	var configJSON []byte
	err := tm.db.Pool.QueryRow(ctx,
		`SELECT value FROM system_settings WHERE key = 'browzer_domain_config'`).Scan(&configJSON)
	if err != nil {
		tm.logger.Debug("No browzer_domain_config in DB, using default domain", zap.Error(err))
		return nil
	}

	var cfg struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return fmt.Errorf("failed to parse browzer_domain_config: %w", err)
	}

	if cfg.Domain != "" {
		tm.domain = cfg.Domain
		tm.logger.Info("Loaded BrowZer domain from DB", zap.String("domain", cfg.Domain))
	}
	return nil
}

// GetDB returns the database handle
func (tm *BrowZerTargetManager) GetDB() *database.PostgresDB {
	return tm.db
}

// browzerRouteInfo holds parsed route information for target/router generation
type browzerRouteInfo struct {
	fromURL     string
	toURL       string
	serviceName string
	hostname    string
	pathPrefix  string
	landingPath string
	hostingMode string
}

// queryBrowZerRoutes fetches all BrowZer-enabled routes from the database
func (tm *BrowZerTargetManager) queryBrowZerRoutes(ctx context.Context) ([]browzerRouteInfo, error) {
	rows, err := tm.db.Pool.Query(ctx,
		//orgscope:ignore install-wide BrowZer bootstrapper config generation; the shared bootstrapper serves every ziti+browzer-enabled route across all orgs into one config file
		`SELECT from_url, to_url, ziti_service_name, COALESCE(landing_path, '/'), COALESCE(hosting_mode, 'identity')
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
		var fromURL, toURL, serviceName, landingPath, hostingMode string
		if err := rows.Scan(&fromURL, &toURL, &serviceName, &landingPath, &hostingMode); err != nil {
			tm.logger.Warn("Failed to scan route row", zap.Error(err))
			continue
		}

		info := browzerRouteInfo{
			fromURL:     fromURL,
			toURL:       toURL,
			serviceName: serviceName,
			hostname:    fromURL,
			pathPrefix:  "/",
			landingPath: landingPath,
			hostingMode: hostingMode,
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

// buildBrowZerTargets maps each BrowZer route to a bootstrapper target. Each app
// uses its OWN Ziti service (per-app direct hosting) so the browser dials it
// directly — no shared Host-demux. Scheme comes from the route's to_url so the
// runtime's WASM TLS connects end-to-end for https upstreams.
func buildBrowZerTargets(routes []browzerRouteInfo, domain, idpIssuer, idpClientID string) []BrowZerTarget {
	targets := make([]BrowZerTarget, 0, len(routes))
	for _, r := range routes {
		scheme := "http"
		if parsed, err := url.Parse(r.toURL); err == nil && parsed.Scheme != "" {
			scheme = parsed.Scheme
		}
		targets = append(targets, BrowZerTarget{
			VHost:        r.hostname,
			Service:      r.serviceName,
			Path:         "/",
			Scheme:       scheme,
			IDPIssuerURL: idpIssuer,
			IDPClientID:  idpClientID,
		})
	}
	return targets
}

// GenerateBrowZerTargets queries the database for all BrowZer-enabled routes
// and builds the target configuration JSON for the bootstrapper. Each route maps
// to its own per-app Ziti service so the browser dials it directly.
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

	targets := buildBrowZerTargets(routes, tm.GetDomain(), oidcIssuer, oidcClientID)

	tm.logger.Info("Generated BrowZer targets",
		zap.Int("count", len(targets)))
	return &BrowZerTargetArray{TargetArray: targets}, nil
}

// WriteBrowZerTargets generates the target config and writes it to the shared config file.
// The file is written in the nconf config.json format where the targets JSON is a string value.
func (tm *BrowZerTargetManager) WriteBrowZerTargets(ctx context.Context) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.writeTargetsLocked(ctx)
}

// writeTargetsLocked is the lock-free body of WriteBrowZerTargets. The caller
// must hold tm.mu (so target + router-config regeneration can share one lock).
func (tm *BrowZerTargetManager) writeTargetsLocked(ctx context.Context) error {
	if tm.targetsPath == "" {
		tm.logger.Debug("No targets path configured, skipping write")
		return nil
	}

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
	// Include HOST override so the bootstrapper uses the configured domain
	domain := tm.GetDomain()
	if domain != DefaultBrowZerDomain {
		configMap["ZITI_BROWZER_BOOTSTRAPPER_HOST"] = domain
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

// browzerUpstream rewrites a route's to_url into the address the BrowZer router
// container must use to reach the target. When the target is bound to the host
// loopback (a "dark" service published only on 127.0.0.1, reachable over the
// overlay), the router — which runs in its own network namespace — cannot use
// 127.0.0.1 directly; it must use the host-loopback alias for its runtime (e.g.
// slirp4netns exposes the host loopback at 10.0.2.2 with allow_host_loopback).
//
// The alias is configured via BROWZER_HOST_LOOPBACK_ALIAS. When unset (the
// default, e.g. docker-compose where the router shares a bridge with the app),
// to_url is returned unchanged so behavior is identical to before.
func browzerUpstream(toURL string) string {
	alias := os.Getenv("BROWZER_HOST_LOOPBACK_ALIAS")
	if alias == "" {
		return toURL
	}
	parsed, err := url.Parse(toURL)
	if err != nil || parsed.Host == "" {
		return toURL
	}
	switch parsed.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		if port := parsed.Port(); port != "" {
			parsed.Host = alias + ":" + port
		} else {
			parsed.Host = alias
		}
		return parsed.String()
	default:
		return toURL
	}
}

// GenerateBrowZerRouterConfig generates nginx config for path-based and vhost-based BrowZer routing.
// Path-based routes on the default domain get location blocks; routes with unique domains get
// separate server blocks with simple proxy_pass (no sub_filter needed since the app runs at /).
func (tm *BrowZerTargetManager) GenerateBrowZerRouterConfig(ctx context.Context) ([]byte, error) {
	routes, err := tm.queryBrowZerRoutes(ctx)
	if err != nil {
		return nil, err
	}

	// Separate path-based routes from vhost routes
	type routeMapping struct {
		pathPrefix string
		upstream   string
		isGuac     bool
	}
	type vhostMapping struct {
		hostname    string
		upstream    string
		landingPath string
	}
	var mappings []routeMapping
	var vhosts []vhostMapping

	domain := tm.GetDomain()
	for _, r := range routes {
		if r.hostingMode == HostingModeDirect {
			continue // per-app direct route: hosted by the edge router via host.v1, not the shared browzer-router
		}
		// Vhost routes: different domain, root path
		if r.hostname != domain {
			vhosts = append(vhosts, vhostMapping{
				hostname:    r.hostname,
				upstream:    browzerUpstream(r.toURL),
				landingPath: r.landingPath,
			})
			continue
		}
		// Skip root path on default domain (not a path-based route)
		if r.pathPrefix == "/" {
			continue
		}

		upstream := browzerUpstream(r.toURL)
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

	// Check if any route has an external upstream (needs resolver for runtime DNS)
	hasExternal := false
	for _, m := range mappings {
		parsed, _ := url.Parse(m.upstream)
		if parsed != nil && parsed.Scheme == "https" {
			hasExternal = true
			break
		}
	}

	// Build nginx config
	var b strings.Builder
	b.WriteString("# Auto-generated BrowZer router config — do not edit manually\n")
	// WebSocket upgrade map for vhost proxying
	if len(vhosts) > 0 {
		b.WriteString("map $http_upgrade $connection_upgrade {\n")
		b.WriteString("    default upgrade;\n")
		b.WriteString("    ''      close;\n")
		b.WriteString("}\n\n")
	}
	b.WriteString("server {\n")
	b.WriteString("    listen 80;\n")
	b.WriteString("    server_name _;\n")
	b.WriteString("    absolute_redirect off;\n")
	// Use detected DNS resolvers for external upstream resolution at runtime.
	// Without this, nginx resolves hostnames at config load time and crashes if DNS fails.
	// Includes Docker embedded DNS (127.0.0.11) plus host DNS servers from /etc/resolv.conf
	// so internal/corporate domains can be resolved.
	if hasExternal {
		fmt.Fprintf(&b, "    resolver %s valid=30s ipv6=off;\n", tm.dnsResolvers)
	}
	b.WriteString("\n")

	// Generate location blocks for each path-based route
	for _, m := range mappings {
		pathWithSlash := m.pathPrefix
		if !strings.HasSuffix(pathWithSlash, "/") {
			pathWithSlash += "/"
		}

		fmt.Fprintf(&b, "    location %s {\n", pathWithSlash)

		// Generate a safe variable name from the path prefix (e.g. /psm/ -> upstream_psm)
		varName := "upstream_" + strings.ReplaceAll(strings.Trim(m.pathPrefix, "/"), "-", "_")

		if m.isGuac {
			// Guacamole keeps the prefix (it expects /guacamole)
			fmt.Fprintf(&b, "        proxy_pass %s%s;\n", m.upstream, pathWithSlash)
			b.WriteString("        proxy_http_version 1.1;\n")
			b.WriteString("        proxy_set_header Host $host;\n")
			b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
			b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
			b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
			b.WriteString("        proxy_read_timeout 86400s;\n")
			b.WriteString("        proxy_send_timeout 86400s;\n")
			b.WriteString("        proxy_buffering off;\n")
		} else {
			parsed, _ := url.Parse(m.upstream)
			upstreamBase := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
			upstreamPath := strings.TrimSuffix(parsed.Path, "/")
			pathTrimmed := strings.TrimSuffix(pathWithSlash, "/")

			if upstreamPath != "" && upstreamPath != "/" {
				// Upstream has a non-root path (e.g. https://psm.tdv.org/psm).
				// Pass the URI through as-is — nginx forwards /psm/... to upstream /psm/...
				// Use variable-based proxy_pass so nginx resolves DNS at request time,
				// not at startup (prevents crash when external hosts are unreachable).
				fmt.Fprintf(&b, "        set $%s %s;\n", varName, upstreamBase)
				fmt.Fprintf(&b, "        proxy_pass $%s;\n", varName)
				// Rewrite Location headers so redirects stay on BrowZer domain
				fmt.Fprintf(&b, "        proxy_redirect https://%s/ /;\n", parsed.Host)
				fmt.Fprintf(&b, "        proxy_redirect http://%s/ /;\n", parsed.Host)
				b.WriteString("        proxy_http_version 1.1;\n")
				fmt.Fprintf(&b, "        proxy_set_header Host %s;\n", parsed.Host)
				b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
				b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
				b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
				b.WriteString("        proxy_ssl_server_name on;\n")
				b.WriteString("        proxy_ssl_verify off;\n")
				// Rewrite HTML content that references the upstream domain
				b.WriteString("        proxy_set_header Accept-Encoding \"\";\n")
				b.WriteString("        sub_filter_once off;\n")
				b.WriteString("        sub_filter_types text/html application/javascript text/javascript text/css;\n")
				fmt.Fprintf(&b, "        sub_filter 'https://%s' '';\n", parsed.Host)
				fmt.Fprintf(&b, "        sub_filter 'http://%s' '';\n", parsed.Host)
			} else if parsed.Scheme == "https" {
				// External HTTPS app: strip the prefix from ALL requests since the
				// backend doesn't know about the BrowZer path prefix. Rewrite every
				// URI from /prefix/... to /... before proxying.
				// Use variable-based proxy_pass for runtime DNS resolution.
				fmt.Fprintf(&b, "        set $%s %s;\n", varName, upstreamBase)
				fmt.Fprintf(&b, "        rewrite ^%s(/.*)?$ $1 break;\n", pathTrimmed)
				fmt.Fprintf(&b, "        proxy_pass $%s;\n", varName)
				fmt.Fprintf(&b, "        proxy_redirect / %s;\n", pathWithSlash)
				b.WriteString("        proxy_http_version 1.1;\n")
				fmt.Fprintf(&b, "        proxy_set_header Host %s;\n", parsed.Host)
				b.WriteString("        proxy_ssl_server_name on;\n")
				b.WriteString("        proxy_ssl_verify off;\n")
				b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
				b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
				b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
				b.WriteString("        proxy_set_header Accept-Encoding \"\";\n")
				b.WriteString("        sub_filter_once off;\n")
				b.WriteString("        sub_filter_types text/html application/javascript text/javascript text/css;\n")
				fmt.Fprintf(&b, "        sub_filter 'src=\"/' 'src=\"%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter 'href=\"/' 'href=\"%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter 'url(/' 'url(%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter \"url('/\" \"url('%s\";\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter 'url(\"/' 'url(\"%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter 'action=\"/' 'action=\"%s';\n", pathWithSlash)
			} else {
				// Internal HTTP app: hybrid path handling — rewrite rules strip the
				// prefix for the root page and static assets only. All other paths
				// (API calls, SPA page routes) pass through with the full URI so the
				// backend sees its expected paths (e.g. /apisix/admin/*). sub_filter
				// rewrites HTML asset paths, and the webpack publicPath so async
				// chunks load from the correct prefix.
				fmt.Fprintf(&b, "        rewrite ^%s/?$ / break;\n", pathTrimmed)
				fmt.Fprintf(&b, "        rewrite \"^%s/(.+\\.(?:js|mjs|css|html|htm|png|svg|ico|jpg|jpeg|gif|webp|woff2?|ttf|eot|otf|map|json|txt|xml|webmanifest))$\" /$1 break;\n", pathTrimmed)
				fmt.Fprintf(&b, "        proxy_pass %s;\n", upstreamBase)
				fmt.Fprintf(&b, "        proxy_redirect / %s;\n", pathWithSlash)
				b.WriteString("        proxy_http_version 1.1;\n")
				b.WriteString("        proxy_set_header Host $host;\n")
				b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
				b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
				b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
				b.WriteString("        proxy_set_header Accept-Encoding \"\";\n")
				b.WriteString("        sub_filter_once off;\n")
				b.WriteString("        sub_filter_types text/html application/javascript text/javascript text/css;\n")
				fmt.Fprintf(&b, "        sub_filter 'src=\"/' 'src=\"%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter 'href=\"/' 'href=\"%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter 'url(/' 'url(%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter \"url('/\" \"url('%s\";\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter 'url(\"/' 'url(\"%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter '.p=\"/\"' '.p=\"%s\"';\n", pathWithSlash)
			}
		}

		// Strip backend CSP headers — BrowZer SDK needs to connect to the Ziti controller
		// and OIDC provider, which restrictive CSP from backend apps would block
		b.WriteString("        proxy_hide_header Content-Security-Policy;\n")
		b.WriteString("        proxy_hide_header Content-Security-Policy-Report-Only;\n")
		b.WriteString("        proxy_hide_header X-Frame-Options;\n")

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
		fmt.Fprintf(&b, "<a href=\"%s\">%s</a>", m.pathPrefix, label)
	}
	b.WriteString("</body></html>';\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")

	// Generate vhost server blocks for routes with unique domains.
	// These are simple reverse proxies — no sub_filter needed since the app runs at root /.
	for i, vh := range vhosts {
		fmt.Fprintf(&b, "\n# Vhost: %s\n", vh.hostname)
		b.WriteString("server {\n")
		// The first vhost is the default server. BrowZer's WASM runtime fetches the
		// origin over the overlay (dialing browzer-router-zt), and the Host it
		// presents to this router does not always match the vhost name — without a
		// default_server those requests fall through to the static landing block
		// instead of the app. Making the primary app the default routes any
		// otherwise-unmatched Host to it; additional vhosts still match by name.
		if i == 0 {
			b.WriteString("    listen 80 default_server;\n")
		} else {
			b.WriteString("    listen 80;\n")
		}
		fmt.Fprintf(&b, "    server_name %s;\n\n", vh.hostname)
		// Land the bare host on the app's real entry path when it serves under a
		// subpath (e.g. /ui/). Without this, the BrowZer/OIDC round-trip returns
		// to "/", which many apps 404. Exact-match so deeper paths proxy normally.
		// absolute_redirect off keeps the Location relative ("/ui/") — nginx behind
		// the overlay sees http, so an absolute Location would downgrade the https
		// page's scheme and break the BrowZer fetch.
		if lp := vh.landingPath; lp != "" && lp != "/" {
			b.WriteString("    absolute_redirect off;\n")
			fmt.Fprintf(&b, "    location = / { return 302 %s; }\n", lp)
		}
		b.WriteString("    location / {\n")
		fmt.Fprintf(&b, "        proxy_pass %s;\n", vh.upstream)
		b.WriteString("        proxy_http_version 1.1;\n")
		b.WriteString("        proxy_set_header Host $host;\n")
		b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
		b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
		b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
		b.WriteString("        proxy_set_header Connection $connection_upgrade;\n")
		b.WriteString("        proxy_hide_header Content-Security-Policy;\n")
		b.WriteString("        proxy_hide_header Content-Security-Policy-Report-Only;\n")
		b.WriteString("        proxy_hide_header X-Frame-Options;\n")
		b.WriteString("    }\n")
		b.WriteString("}\n")
	}

	tm.logger.Info("Generated BrowZer router config",
		zap.Int("path_routes", len(mappings)),
		zap.Int("vhost_routes", len(vhosts)))
	return []byte(b.String()), nil
}

// WriteBrowZerRouterConfig generates the nginx router config and writes it to the shared config file.
func (tm *BrowZerTargetManager) WriteBrowZerRouterConfig(ctx context.Context) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.writeRouterConfigLocked(ctx)
}

// writeRouterConfigLocked is the lock-free body of WriteBrowZerRouterConfig. The
// caller must hold tm.mu.
func (tm *BrowZerTargetManager) writeRouterConfigLocked(ctx context.Context) error {
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

// RegenerateConfigs rewrites BOTH the bootstrapper targets and the nginx router
// config under a single lock, so the two files are always mutually consistent
// and concurrent callers serialize (whichever runs last reflects the latest
// committed proxy_routes state). Always queries install-wide (RLS bypassed),
// matching the shared bootstrapper's all-orgs view.
//
// Call this SYNCHRONOUSLY and AFTER the proxy_routes feature flags are
// committed. The previous fire-and-forget goroutines were spawned mid-toggle,
// before the flag commit, so they raced it and intermittently wrote empty
// (0-route) configs even when the DB was correct.
func (tm *BrowZerTargetManager) RegenerateConfigs(ctx context.Context) error {
	ctx = orgctx.WithBypassRLS(ctx)
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if err := tm.writeTargetsLocked(ctx); err != nil {
		return err
	}
	return tm.writeRouterConfigLocked(ctx)
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
