// ============================================================================
// OpenIDX Production nginx Configuration Tests
// Tests for nginx configuration validation
// ============================================================================

package docker

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestNginxMainConfiguration validates main nginx.conf structure
func TestNginxMainConfiguration(t *testing.T) {
	confPath := "nginx/nginx.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read nginx.conf: %v", err)
	}

	contentStr := string(content)

	// Validate user directive
	if !strings.Contains(contentStr, "user nginx;") {
		t.Error("Should run as nginx user")
	}

	// Validate worker processes
	if !strings.Contains(contentStr, "worker_processes auto;") {
		t.Error("Should use auto worker processes")
	}

	// Validate events section
	if !strings.Contains(contentStr, "events {") {
		t.Error("Missing events section")
	}

	// Validate worker connections
	if !strings.Contains(contentStr, "worker_connections 4096;") {
		t.Error("Should configure 4096 worker connections")
	}

	// Validate http section
	if !strings.Contains(contentStr, "http {") {
		t.Error("Missing http section")
	}
}

// TestNginxPerformanceSettings validates performance optimization
func TestNginxPerformanceSettings(t *testing.T) {
	confPath := "nginx/nginx.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read nginx.conf: %v", err)
	}

	contentStr := string(content)

	// Validate sendfile
	if !strings.Contains(contentStr, "sendfile on;") {
		t.Error("sendfile should be enabled")
	}

	// Validate tcp_nopush
	if !strings.Contains(contentStr, "tcp_nopush on;") {
		t.Error("tcp_nopush should be enabled")
	}

	// Validate tcp_nodelay
	if !strings.Contains(contentStr, "tcp_nodelay on;") {
		t.Error("tcp_nodelay should be enabled")
	}

	// Validate keepalive
	if !strings.Contains(contentStr, "keepalive_timeout") {
		t.Error("Should configure keepalive_timeout")
	}

	// Validate server tokens off
	if !strings.Contains(contentStr, "server_tokens off;") {
		t.Error("server_tokens should be disabled")
	}
}

// TestNginxGzipConfiguration validates gzip compression
func TestNginxGzipConfiguration(t *testing.T) {
	confPath := "nginx/nginx.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read nginx.conf: %v", err)
	}

	contentStr := string(content)

	// Validate gzip enabled
	if !strings.Contains(contentStr, "gzip on;") {
		t.Error("gzip should be enabled")
	}

	// Validate gzip_vary
	if !strings.Contains(contentStr, "gzip_vary on;") {
		t.Error("gzip_vary should be enabled")
	}

	// Validate gzip_proxied
	if !strings.Contains(contentStr, "gzip_proxied any;") {
		t.Error("gzip_proxied should be set to any")
	}

	// Validate gzip_comp_level
	if !strings.Contains(contentStr, "gzip_comp_level 6;") {
		t.Error("gzip_comp_level should be 6")
	}

	// Validate gzip_types includes common formats
	requiredTypes := []string{
		"text/plain",
		"text/css",
		"application/json",
		"application/javascript",
	}

	for _, contentType := range requiredTypes {
		if !strings.Contains(contentStr, contentType) {
			t.Errorf("gzip_types should include: %s", contentType)
		}
	}
}

// TestNginxUpstreamDefinitions validates upstream configuration
func TestNginxUpstreamDefinitions(t *testing.T) {
	confPath := "nginx/nginx.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read nginx.conf: %v", err)
	}

	contentStr := string(content)

	// Required upstream definitions
	requiredUpstreams := []string{
		"upstream admin_console {",
		"upstream apisix_gateway {",
		"upstream oauth_service {",
		"upstream access_service {",
	}

	for _, upstream := range requiredUpstreams {
		if !strings.Contains(contentStr, upstream) {
			t.Errorf("Missing upstream: %s", upstream)
		}
	}

	// Validate keepalive directive in upstreams
	if strings.Count(contentStr, "keepalive") < 2 {
		t.Error("Upstreams should configure keepalive connections")
	}
}

// TestNginxSecurityHeaders validates security headers
func TestNginxSecurityHeaders(t *testing.T) {
	confPath := "nginx/nginx.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read nginx.conf: %v", err)
	}

	contentStr := string(content)

	// Validate security headers are added
	requiredHeaders := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Strict-Transport-Security",
	}

	for _, header := range requiredHeaders {
		if !strings.Contains(contentStr, "add_header "+header) && !strings.Contains(contentStr, "add_header "+header+" ") {
			t.Errorf("Missing security header: %s", header)
		}
	}

	// Validate HSTS configuration
	if !strings.Contains(contentStr, "max-age=31536000") {
		t.Error("HSTS should have 1 year max-age")
	}

	if !strings.Contains(contentStr, "includeSubDomains") {
		t.Error("HSTS should include subdomains")
	}
}

// TestNginxBuffersConfiguration validates buffer settings
func TestNginxBuffersConfiguration(t *testing.T) {
	confPath := "nginx/nginx.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read nginx.conf: %v", err)
	}

	contentStr := string(content)

	// Validate buffer size directives
	bufferDirectives := []string{
		"client_body_buffer_size",
		"client_max_body_size",
		"client_header_buffer_size",
		"large_client_header_buffers",
	}

	for _, directive := range bufferDirectives {
		if !strings.Contains(contentStr, directive) {
			t.Errorf("Missing buffer directive: %s", directive)
		}
	}

	// Validate max body size allows uploads
	if !strings.Contains(contentStr, "client_max_body_size 10m") {
		t.Error("Should allow 10M body size")
	}
}

// TestNginxSSLSessionCache validates SSL session cache
func TestNginxSSLSessionCache(t *testing.T) {
	confPath := "nginx/nginx.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read nginx.conf: %v", err)
	}

	contentStr := string(content)

	// Validate SSL session cache
	if !strings.Contains(contentStr, "ssl_session_cache shared:SSL:10m;") {
		t.Error("Should configure SSL session cache")
	}

	// Validate SSL session timeout
	if !strings.Contains(contentStr, "ssl_session_timeout 10m;") {
		t.Error("Should configure SSL session timeout")
	}
}

// TestNginxSiteHTTPRedirect validates HTTP to HTTPS redirect
func TestNginxSiteHTTPRedirect(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate HTTP server block
	if !strings.Contains(contentStr, "server {") {
		t.Error("Missing server block")
	}

	// Validate listen 80
	if !strings.Contains(contentStr, "listen 80;") {
		t.Error("Should listen on port 80")
	}

	// Validate server_name
	if !strings.Contains(contentStr, "server_name openidx.tdv.org") {
		t.Error("Should configure server_name")
	}

	// Validate redirect to HTTPS
	if !strings.Contains(contentStr, "return 301 https://") {
		t.Error("Should redirect HTTP to HTTPS")
	}
}

// TestNginxSiteSSLConfiguration validates SSL/TLS configuration
func TestNginxSiteSSLConfiguration(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate HTTPS server block
	if strings.Count(contentStr, "listen 443 ssl") < 1 {
		t.Error("Should listen on port 443 with SSL")
	}

	// Validate HTTP/2
	if !strings.Contains(contentStr, "http2") {
		t.Error("Should enable HTTP/2")
	}

	// Validate certificate paths
	requiredCertPaths := []string{
		"ssl_certificate /etc/letsencrypt/live/openidx.tdv.org/fullchain.pem;",
		"ssl_certificate_key /etc/letsencrypt/live/openidx.tdv.org/privkey.pem;",
		"ssl_trusted_certificate /etc/letsencrypt/live/openidx.tdv.org/chain.pem;",
	}

	for _, path := range requiredCertPaths {
		if !strings.Contains(contentStr, path) {
			t.Errorf("Missing certificate path: %s", path)
		}
	}
}

// TestNginxSiteSSLProtocols validates TLS protocol configuration
func TestNginxSiteSSLProtocols(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate TLS 1.2 and 1.3 only
	if !strings.Contains(contentStr, "ssl_protocols TLSv1.2 TLSv1.3;") {
		t.Error("Should only allow TLS 1.2 and 1.3")
	}

	// Validate strong ciphers
	if !strings.Contains(contentStr, "ssl_ciphers") {
		t.Error("Should configure SSL ciphers")
	}

	// Validate prefer server ciphers
	if !strings.Contains(contentStr, "ssl_prefer_server_ciphers off;") {
		t.Error("Should prefer server ciphers off (let client choose)")
	}
}

// TestNginxSiteSSLStapling validates OCSP stapling
func TestNginxSiteSSLStapling(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate SSL stapling
	if !strings.Contains(contentStr, "ssl_stapling on;") {
		t.Error("SSL stapling should be enabled")
	}

	if !strings.Contains(contentStr, "ssl_stapling_verify on;") {
		t.Error("SSL stapling verification should be enabled")
	}
}

// TestNginxSiteSecurityHeaders validates site security headers
func TestNginxSiteSecurityHeaders(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate security headers
	requiredHeaders := []string{
		`add_header X-Frame-Options "SAMEORIGIN"`,
		`add_header X-Content-Type-Options "nosniff"`,
		`add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`,
	}

	for _, header := range requiredHeaders {
		if !strings.Contains(contentStr, header) {
			t.Errorf("Missing security header: %s", header)
		}
	}

	// Validate CSP header
	if !strings.Contains(contentStr, "add_header Content-Security-Policy") {
		t.Error("Should have Content-Security-Policy header")
	}

	// Validate CSP includes production domain
	if !strings.Contains(contentStr, "connect-src 'self' https://openidx.tdv.org") {
		t.Error("CSP should allow connections to production domain")
	}
}

// TestNginxSiteACMEChallenge validates ACME challenge location
func TestNginxSiteACMEChallenge(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate ACME challenge location
	if !strings.Contains(contentStr, "/.well-known/acme-challenge/") {
		t.Error("Should configure ACME challenge location")
	}

	// Validate webroot path
	if !strings.Contains(contentStr, "root /var/www/certbot;") {
		t.Error("Should use certbot webroot for ACME challenges")
	}

	// Validate try_files
	if !strings.Contains(contentStr, "try_files $uri =404;") {
		t.Error("Should use try_files for ACME challenges")
	}
}

// TestNginxSiteHealthCheck validates health check endpoint
func TestNginxSiteHealthCheck(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate health check location
	if !strings.Contains(contentStr, "location /health") {
		t.Error("Should have /health location")
	}

	// Validate health returns 200
	if !strings.Contains(contentStr, "return 200 \"healthy\\n\";") {
		t.Error("Health check should return 200 with 'healthy' text")
	}

	// Validate health check has no access log
	if !strings.Contains(contentStr, "access_log off;") {
		t.Error("Health check should disable access logging")
	}
}

// TestNginxSiteAdminConsoleLocation validates admin console proxy
func TestNginxSiteAdminConsoleLocation(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate admin console location
	if !strings.Contains(contentStr, "location / {") {
		t.Error("Should have root location for admin console")
	}

	// Validate proxy_pass to admin_console
	if !strings.Contains(contentStr, "proxy_pass http://admin_console;") {
		t.Error("Should proxy to admin_console upstream")
	}

	// Validate HTTP/1.1 for proxy
	if !strings.Contains(contentStr, "proxy_http_version 1.1;") {
		t.Error("Should use HTTP/1.1 for proxying")
	}

	// Validate Upgrade header for WebSocket
	if !strings.Contains(contentStr, "proxy_set_header Upgrade $http_upgrade;") {
		t.Error("Should set Upgrade header for WebSocket support")
	}

	// Validate Connection header
	if !strings.Contains(contentStr, "proxy_set_header Connection 'upgrade';") {
		t.Error("Should set Connection header for upgrade")
	}
}

// TestNginxSiteProxyHeaders validates proxy headers
func TestNginxSiteProxyHeaders(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Required proxy headers
	requiredHeaders := []string{
		"proxy_set_header Host $host;",
		"proxy_set_header X-Real-IP $remote_addr;",
		"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
		"proxy_set_header X-Forwarded-Proto $scheme;",
		"proxy_set_header X-Forwarded-Host $host;",
	}

	for _, header := range requiredHeaders {
		if !strings.Contains(contentStr, header) {
			t.Errorf("Missing proxy header: %s", header)
		}
	}
}

// TestNginxSiteAPIGatewayLocation validates API gateway proxy
func TestNginxSiteAPIGatewayLocation(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate API location
	if !strings.Contains(contentStr, "location /api/v1/ {") {
		t.Error("Should have /api/v1/ location")
	}

	// Validate proxy to APISIX
	if !strings.Contains(contentStr, "proxy_pass http://apisix_gateway;") {
		t.Error("Should proxy API requests to APISIX gateway")
	}

	// Validate CORS preflight handling
	if !strings.Contains(contentStr, "$request_method = 'OPTIONS'") {
		t.Error("Should handle OPTIONS preflight requests")
	}
}

// TestNginxSiteOAuthLocation validates OAuth service proxy
func TestNginxSiteOAuthLocation(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate OAuth location with regex
	if !strings.Contains(contentStr, "location ~ ^/(oauth|\\.well-known)/") {
		t.Error("Should have regex location for OAuth and .well-known")
	}

	// Validate proxy to oauth_service
	if !strings.Contains(contentStr, "proxy_pass http://oauth_service;") {
		t.Error("Should proxy OAuth requests to oauth_service upstream")
	}
}

// TestNginxSiteSCIMLocation validates SCIM endpoint proxy
func TestNginxSiteSCIMLocation(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate SCIM location
	if !strings.Contains(contentStr, "location /scim/v2/ {") {
		t.Error("Should have /scim/v2/ location")
	}

	// Validate SCIM proxy to APISIX
	if !strings.Contains(contentStr, "proxy_pass http://apisix_gateway;") {
		t.Error("Should proxy SCIM requests through APISIX gateway")
	}
}

// TestNginxSiteAccessServiceLocation validates access service proxy
func TestNginxSiteAccessServiceLocation(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate access service location
	if !strings.Contains(contentStr, "location /access/ {") {
		t.Error("Should have /access/ location")
	}

	// Validate proxy to access_service
	if !strings.Contains(contentStr, "proxy_pass http://access_service;") {
		t.Error("Should proxy access requests to access_service upstream")
	}

	// Validate longer timeouts for WebSocket
	if !strings.Contains(contentStr, "proxy_connect_timeout 300s;") {
		t.Error("Access service should have long connect timeout for WebSocket")
	}

	if !strings.Contains(contentStr, "proxy_read_timeout 300s;") {
		t.Error("Access service should have long read timeout for WebSocket")
	}
}

// TestNginxSiteStaticAssetsCaching validates static asset caching
func TestNginxSiteStaticAssetsCaching(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate static asset location
	if !strings.Contains(contentStr, "location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$") {
		t.Error("Should have location for static assets")
	}

	// Validate cache headers
	if !strings.Contains(contentStr, "expires 1y;") {
		t.Error("Static assets should have long expiry")
	}

	if !strings.Contains(contentStr, "add_header Cache-Control \"public, immutable\";") {
		t.Error("Static assets should have immutable cache control")
	}
}

// TestNginxSiteSPAFallback validates SPA fallback configuration
func TestNginxSiteSPAFallback(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate try_files for SPA fallback
	if !strings.Contains(contentStr, "try_files $uri $uri/ /index.html;") {
		t.Error("Should have SPA fallback to index.html")
	}
}

// TestNginxSiteJWKSLocation validates JWKS endpoint configuration
func TestNginxSiteJWKSLocation(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate JWKS location
	if !strings.Contains(contentStr, "location = /.well-known/jwks.json") {
		t.Error("Should have exact match location for JWKS")
	}

	// Validate proxy to oauth service
	if !strings.Contains(contentStr, "proxy_pass http://oauth_service/.well-known/jwks.json;") {
		t.Error("Should proxy JWKS to oauth service")
	}

	// Validate JWKS caching
	if !strings.Contains(contentStr, "proxy_cache_valid 200 5m;") {
		t.Error("JWKS should be cached for 5 minutes")
	}
}

// TestNginxSiteOIDCLocation validates OIDC discovery configuration
func TestNginxSiteOIDCLocation(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate OIDC discovery location
	if !strings.Contains(contentStr, "location = /.well-known/openid-configuration") {
		t.Error("Should have exact match location for OIDC discovery")
	}

	// Validate proxy to oauth service
	if !strings.Contains(contentStr, "proxy_pass http://oauth_service/.well-known/openid-configuration;") {
		t.Error("Should proxy OIDC discovery to oauth service")
	}

	// Validate OIDC caching (1 hour)
	if !strings.Contains(contentStr, "proxy_cache_valid 200 1h;") {
		t.Error("OIDC discovery should be cached for 1 hour")
	}
}

// TestNginxSiteClientBodySize validates client body size limit
func TestNginxSiteClientBodySize(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate client_max_body_size
	if !strings.Contains(contentStr, "client_max_body_size 10M;") {
		t.Error("Should allow 10M client body size")
	}
}

// TestNginxSiteAccessLogs validates access log configuration
func TestNginxSiteAccessLogs(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate access log
	if !strings.Contains(contentStr, "access_log /var/log/nginx/openidx-access.log;") {
		t.Error("Should configure access log")
	}

	// Validate error log
	if !strings.Contains(contentStr, "error_log /var/log/nginx/openidx-error.log;") {
		t.Error("Should configure error log")
	}
}

// TestNginxSiteDefaultServer validates default server block
func TestNginxSiteDefaultServer(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate default server for invalid hostnames
	if !strings.Contains(contentStr, "server_name _;") {
		t.Error("Should have default server for invalid hostnames")
	}

	// Validate default_server directive
	if !strings.Contains(contentStr, "default_server") {
		t.Error("Should mark server as default")
	}

	// Validate returns 444 for invalid hostnames
	if !strings.Contains(contentStr, "return 444;") {
		t.Error("Should return 444 for invalid hostnames")
	}
}

// TestNginxConfigSyntax validates config file syntax
func TestNginxConfigSyntax(t *testing.T) {
	confPath := "nginx/nginx.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read nginx.conf: %v", err)
	}

	contentStr := string(content)

	// Check for balanced braces
	openBraces := strings.Count(contentStr, "{")
	closeBraces := strings.Count(contentStr, "}")

	if openBraces != closeBraces {
		t.Errorf("Unbalanced braces: %d open, %d close", openBraces, closeBraces)
	}

	// Count potential missing semicolons (lines that should have them but don't)
	lines := strings.Split(contentStr, "\n")
	missingSemicolon := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip comments, empty lines, and blocks
		if strings.HasPrefix(line, "#") || line == "" ||
			strings.HasSuffix(line, "{") || strings.HasSuffix(line, "}") {
			continue
		}
		// Check if line looks like a directive without semicolon
		if regexp.MustCompile(`^[a-z_]+`).MatchString(line) &&
			!strings.Contains(line, ";") &&
			!strings.Contains(line, "#") {
			missingSemicolon++
		}
	}

	if missingSemicolon > 5 {
		t.Errorf("Too many directives possibly missing semicolons: %d", missingSemicolon)
	}
}

// TestNginxSiteCORSPreflight validates CORS preflight handling
func TestNginxSiteCORSPreflight(t *testing.T) {
	confPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read site config: %v", err)
	}

	contentStr := string(content)

	// Validate CORS headers for OPTIONS
	if !strings.Contains(contentStr, "Access-Control-Allow-Origin") {
		t.Error("Should set CORS Allow-Origin header")
	}

	if !strings.Contains(contentStr, "Access-Control-Allow-Methods") {
		t.Error("Should set CORS Allow-Methods header")
	}

	if !strings.Contains(contentStr, "Access-Control-Allow-Headers") {
		t.Error("Should set CORS Allow-Headers header")
	}

	// Validate Access-Control-Max-Age
	if !strings.Contains(contentStr, "Access-Control-Max-Age") {
		t.Error("Should set CORS Max-Age header")
	}
}

// TestNginxMimeTypes validates MIME types configuration
func TestNginxMimeTypes(t *testing.T) {
	confPath := "nginx/nginx.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read nginx.conf: %v", err)
	}

	contentStr := string(content)

	// Validate mime.types include
	if !strings.Contains(contentStr, "include /etc/nginx/mime.types;") {
		t.Error("Should include mime.types")
	}

	// Validate default type
	if !strings.Contains(contentStr, "default_type application/octet-stream;") {
		t.Error("Should set default MIME type")
	}
}

// TestNginxLoggingFormat validates log format
func TestNginxLoggingFormat(t *testing.T) {
	confPath := "nginx/nginx.conf"

	content, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("Failed to read nginx.conf: %v", err)
	}

	contentStr := string(content)

	// Validate log_format definition
	if !strings.Contains(contentStr, "log_format main") {
		t.Error("Should define main log format")
	}

	// Validate log format includes common variables
	requiredVars := []string{
		"$remote_addr",
		"$request",
		"$status",
		"$body_bytes_sent",
		"$request_time",
	}

	for _, logVar := range requiredVars {
		if !strings.Contains(contentStr, logVar) {
			t.Errorf("Log format should include: %s", logVar)
		}
	}
}
