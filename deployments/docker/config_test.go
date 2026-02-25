// Package docker provides tests for production Docker configuration
package docker

import (
	"os"
	"strings"
	"testing"
)

// TestDockerComposeProdSyntax validates docker-compose.prod.yml syntax
func TestDockerComposeProdSyntax(t *testing.T) {
	// This test validates the docker-compose.prod.yml file structure
	// In a real environment, we'd use docker-compose config command

	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Validate key sections
	requiredSections := []string{
		"version:",
		"services:",
		"volumes:",
		"networks:",
	}

	for _, section := range requiredSections {
		if !strings.Contains(contentStr, section) {
			t.Errorf("Missing required section: %s", section)
		}
	}

	// Validate required services are defined
	requiredServices := []string{
		"postgres:",
		"redis:",
		"elasticsearch:",
		"apisix:",
		"etcd:",
		"identity-service:",
		"governance-service:",
		"provisioning-service:",
		"audit-service:",
		"admin-api:",
		"oauth-service:",
		"access-service:",
		"admin-console:",
		"nginx-proxy:",
		"certbot:",
		"opa:",
		"backup-scheduler:",
	}

	for _, service := range requiredServices {
		if !strings.Contains(contentStr, service) {
			t.Errorf("Missing required service: %s", service)
		}
	}

	// Validate production domain configuration
	if !strings.Contains(contentStr, "openidx.tdv.org") {
		t.Error("Missing production domain configuration")
	}

	// Validate SSL/TLS configuration
	if !strings.Contains(contentStr, "443:9443") {
		t.Error("Missing HTTPS port configuration")
	}

	// Validate restart policy
	if strings.Count(contentStr, "restart: always") < 10 {
		t.Error("Production services should have restart: always policy")
	}
}

// TestEnvProductionTemplate validates .env.production template
func TestEnvProductionTemplate(t *testing.T) {
	envPath := ".env.production"

	content, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("Failed to read .env.production: %v", err)
	}

	contentStr := string(content)

	// Validate required environment variables
	requiredVars := []string{
		"APP_ENV=production",
		"DOMAIN=openidx.tdv.org",
		"POSTGRES_PASSWORD=",
		"REDIS_PASSWORD=",
		"JWT_SECRET=",
		"OAUTH_ISSUER=https://openidx.tdv.org",
		"OAUTH_JWKS_URL=https://openidx.tdv.org/.well-known/jwks.json",
		"ACCESS_SESSION_SECRET=",
		"SCIM_BEARER_TOKEN=",
		"ZITI_PWD=",
		"GUACAMOLE_ADMIN_PASSWORD=",
	}

	for _, envVar := range requiredVars {
		if !strings.Contains(contentStr, envVar) {
			t.Errorf("Missing required environment variable: %s", envVar)
		}
	}

	// Validate warning comment about not committing
	if !strings.Contains(contentStr, "DO NOT commit this file") {
		t.Error("Missing security warning in .env.production")
	}
}

// TestNginxConfiguration validates nginx production configuration
func TestNginxConfiguration(t *testing.T) {
	nginxConfPath := "nginx/nginx.conf"

	content, err := os.ReadFile(nginxConfPath)
	if err != nil {
		t.Fatalf("Failed to read nginx.conf: %v", err)
	}

	contentStr := string(content)

	// Validate essential nginx directives
	requiredDirectives := []string{
		"user nginx;",
		"worker_processes auto;",
		"events {",
		"http {",
		"server_tokens off;",
		"sendfile on;",
		"keepalive_timeout",
	}

	for _, directive := range requiredDirectives {
		if !strings.Contains(contentStr, directive) {
			t.Errorf("Missing required nginx directive: %s", directive)
		}
	}

	// Validate gzip is enabled
	if !strings.Contains(contentStr, "gzip on;") {
		t.Error("Gzip compression should be enabled")
	}

	// Validate SSL session cache
	if !strings.Contains(contentStr, "ssl_session_cache") {
		t.Error("SSL session cache should be configured")
	}

	// Validate upstream definitions
	requiredUpstreams := []string{
		"upstream admin_console",
		"upstream apisix_gateway",
		"upstream oauth_service",
		"upstream access_service",
	}

	for _, upstream := range requiredUpstreams {
		if !strings.Contains(contentStr, upstream) {
			t.Errorf("Missing upstream: %s", upstream)
		}
	}
}

// TestNginxSiteConfiguration validates site-specific nginx configuration
func TestNginxSiteConfiguration(t *testing.T) {
	siteConfPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(siteConfPath)
	if err != nil {
		t.Fatalf("Failed to read site configuration: %v", err)
	}

	contentStr := string(content)

	// Validate domain
	if !strings.Contains(contentStr, "server_name openidx.tdv.org") {
		t.Error("Missing production domain in server_name directive")
	}

	// Validate HTTP to HTTPS redirect
	if !strings.Contains(contentStr, "return 301 https://") {
		t.Error("Missing HTTP to HTTPS redirect")
	}

	// Validate SSL certificate paths
	if !strings.Contains(contentStr, "ssl_certificate") {
		t.Error("Missing SSL certificate configuration")
	}

	// Validate SSL protocols
	if !strings.Contains(contentStr, "ssl_protocols TLSv1.2 TLSv1.3") {
		t.Error("Should use TLS 1.2 and 1.3 only")
	}

	// Validate security headers
	securityHeaders := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Strict-Transport-Security",
		"Content-Security-Policy",
	}

	for _, header := range securityHeaders {
		if !strings.Contains(contentStr, header) {
			t.Errorf("Missing security header: %s", header)
		}
	}

	// Validate ACME challenge location
	if !strings.Contains(contentStr, "/.well-known/acme-challenge/") {
		t.Error("Missing Let's Encrypt ACME challenge location")
	}

	// Validate health check endpoint
	if !strings.Contains(contentStr, "location /health") {
		t.Error("Missing health check endpoint")
	}

	// Validate API location
	if !strings.Contains(contentStr, "location /api/v1/") {
		t.Error("Missing API location block")
	}

	// Validate OAuth location
	if !strings.Contains(contentStr, "location ~ ^/(oauth|\\.well-known)/") {
		t.Error("Missing OAuth location block")
	}

	// Validate SCIM location
	if !strings.Contains(contentStr, "location /scim/v2/") {
		t.Error("Missing SCIM location block")
	}
}

// TestCertbotEntrypointScript validates the certbot entrypoint script
func TestCertbotEntrypointScript(t *testing.T) {
	scriptPath := "scripts/certbot-entrypoint.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read certbot-entrypoint.sh: %v", err)
	}

	contentStr := string(content)

	// Validate shebang
	if !strings.HasPrefix(contentStr, "#!/bin/bash") {
		t.Error("Script should have bash shebang")
	}

	// Validate error handling
	if !strings.Contains(contentStr, "set -e") {
		t.Error("Script should use 'set -e' for error handling")
	}

	// Validate certbot command
	if !strings.Contains(contentStr, "certbot") {
		t.Error("Script should call certbot")
	}

	// Validate domain configuration
	if !strings.Contains(contentStr, "CERTBOT_DOMAIN") {
		t.Error("Missing CERTBOT_DOMAIN variable")
	}

	// Validate webroot configuration
	if !strings.Contains(contentStr, "--webroot") {
		t.Error("Should use webroot authentication")
	}

	// Validate certificate check
	if !strings.Contains(contentStr, "fullchain.pem") {
		t.Error("Should check for fullchain.pem certificate")
	}

	// Validate nginx reload
	if !strings.Contains(contentStr, "nginx -s reload") {
		t.Error("Should reload nginx after certificate renewal")
	}

	// Validate renewal loop
	if !strings.Contains(contentStr, "certbot renew") {
		t.Error("Should have certificate renewal logic")
	}
}

// TestLoadProductionRoutesScript validates the production routes loading script
func TestLoadProductionRoutesScript(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate shebang
	if !strings.HasPrefix(contentStr, "#!/bin/bash") {
		t.Error("Script should have bash shebang")
	}

	// Validate error handling
	if !strings.Contains(contentStr, "set -e") {
		t.Error("Script should use 'set -e' for error handling")
	}

	// Validate APISIX admin API
	if !strings.Contains(contentStr, "APISIX_ADMIN_URL") {
		t.Error("Missing APISIX_ADMIN_URL variable")
	}

	// Validate domain configuration
	if !strings.Contains(contentStr, "PRODUCTION_DOMAIN") {
		t.Error("Missing PRODUCTION_DOMAIN variable")
	}

	// Validate curl commands for API calls
	if strings.Count(contentStr, "curl -s") < 5 {
		t.Error("Script should make API calls via curl")
	}

	// Validate upstream creation
	if !strings.Contains(contentStr, "create_upstream") {
		t.Error("Should have upstream creation function")
	}

	// Validate route creation
	if !strings.Contains(contentStr, "create_route") {
		t.Error("Should have route creation function")
	}

	// Validate service creation
	if !strings.Contains(contentStr, "create_service") {
		t.Error("Should have service creation function")
	}

	// Validate CORS configuration
	if !strings.Contains(contentStr, "cors") {
		t.Error("Should configure CORS for production domain")
	}

	// Validate health check routes
	if strings.Count(contentStr, "health-") < 3 {
		t.Error("Should create health check routes for all services")
	}

	// Validate OIDC discovery route
	if !strings.Contains(contentStr, ".well-known") {
		t.Error("Should route OIDC discovery endpoints")
	}

	// Validate SCIM routes
	if strings.Count(contentStr, "scim") < 2 {
		t.Error("Should route SCIM endpoints")
	}
}

// TestBackupScript validates the database backup script
func TestBackupScript(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Validate shebang
	if !strings.HasPrefix(contentStr, "#!/bin/bash") {
		t.Error("Script should have bash shebang")
	}

	// Validate error handling
	if !strings.Contains(contentStr, "set -e") {
		t.Error("Script should use 'set -e' for error handling")
	}

	// Validate PostgreSQL configuration
	requiredVars := []string{
		"POSTGRES_HOST",
		"POSTGRES_USER",
		"POSTGRES_PASSWORD",
		"POSTGRES_DB",
		"BACKUP_DIR",
	}

	for _, envVar := range requiredVars {
		if !strings.Contains(contentStr, envVar) {
			t.Errorf("Missing required variable: %s", envVar)
		}
	}

	// Validate pg_dump command
	if !strings.Contains(contentStr, "pg_dump") {
		t.Error("Script should use pg_dump for backup")
	}

	// Validate gzip compression
	if !strings.Contains(contentStr, "gzip") {
		t.Error("Backup should be compressed with gzip")
	}

	// Validate retention policy
	if !strings.Contains(contentStr, "RETENTION_DAYS") {
		t.Error("Should have backup retention policy")
	}

	// Validate cleanup of old backups
	if !strings.Contains(contentStr, "-mtime +") {
		t.Error("Should clean up old backups based on retention")
	}

	// Validate password cleanup
	if !strings.Contains(contentStr, "unset PGPASSWORD") {
		t.Error("Should unset PGPASSWORD after backup")
	}
}

// TestProductionReadme validates production deployment documentation
func TestProductionReadme(t *testing.T) {
	readmePath := "README.PRODUCTION.md"

	content, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("Failed to read README.PRODUCTION.md: %v", err)
	}

	contentStr := string(content)

	// Validate required sections
	requiredSections := []string{
		"## Prerequisites",
		"## Quick Start",
		"## Configuration",
		"## Deployment Steps",
		"## SSL Certificate Management",
		"## Service Access",
		"## Backup and Restore",
		"## Troubleshooting",
	}

	for _, section := range requiredSections {
		if !strings.Contains(contentStr, section) {
			t.Errorf("Missing required section: %s", section)
		}
	}

	// Validate domain references
	if strings.Count(contentStr, "openidx.tdv.org") < 5 {
		t.Error("Documentation should reference the production domain")
	}

	// Validate security considerations
	if !strings.Contains(contentStr, "## Security Considerations") {
		t.Error("Missing security considerations section")
	}

	// Validate secrets generation
	if !strings.Contains(contentStr, "openssl") {
		t.Error("Should document secrets generation with openssl")
	}
}

// TestProductionFilesExist verifies all production files exist
func TestProductionFilesExist(t *testing.T) {
	requiredFiles := []string{
		"docker-compose.prod.yml",
		".env.production",
		"nginx/nginx.conf",
		"nginx/conf.d/openidx.tdv.org.conf",
		"scripts/certbot-entrypoint.sh",
		"scripts/backup.sh",
		"load-production-routes.sh",
		"README.PRODUCTION.md",
	}

	for _, file := range requiredFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			t.Errorf("Required production file missing: %s", file)
		}
	}
}

// TestProductionConfigurationConsistency validates consistency across files
func TestProductionConfigurationConsistency(t *testing.T) {
	// Read all configuration files
	composeContent, _ := os.ReadFile("docker-compose.prod.yml")
	envContent, _ := os.ReadFile(".env.production")
	nginxContent, _ := os.ReadFile("nginx/conf.d/openidx.tdv.org.conf")

	composeStr := string(composeContent)
	envStr := string(envContent)
	nginxStr := string(nginxContent)

	// All files should reference the same domain
	domain := "openidx.tdv.org"

	if !strings.Contains(composeStr, domain) {
		t.Error("docker-compose.prod.yml should reference production domain")
	}

	if !strings.Contains(envStr, domain) {
		t.Error(".env.production should reference production domain")
	}

	if !strings.Contains(nginxStr, domain) {
		t.Error("nginx configuration should reference production domain")
	}

	// Validate sufficient domain references in compose
	if strings.Count(composeStr, domain) < 5 {
		t.Error("docker-compose.prod.yml should have multiple domain references")
	}

	// Validate port consistency
	// Identity service
	if !strings.Contains(composeStr, "\"127.0.0.1:8001:8001\"") {
		t.Error("Identity service port configuration inconsistent")
	}

	// OAuth service
	if !strings.Contains(composeStr, "\"127.0.0.1:8006:8006\"") {
		t.Error("OAuth service port configuration inconsistent")
	}

	// Validate environment variable references
	if !strings.Contains(composeStr, "POSTGRES_PASSWORD") {
		t.Error("Should reference POSTGRES_PASSWORD from environment")
	}

	if !strings.Contains(composeStr, "REDIS_PASSWORD") {
		t.Error("Should reference REDIS_PASSWORD from environment")
	}

	if !strings.Contains(composeStr, "JWT_SECRET") {
		t.Error("Should reference JWT_SECRET from environment")
	}
}

// TestServicePortMappings validates service port mappings
func TestServicePortMappings(t *testing.T) {
	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Expected internal service ports
	expectedPorts := map[string]string{
		"identity-service":    "8001:8001",
		"governance-service":  "8002:8002",
		"provisioning-service": "8003:8003",
		"audit-service":       "8004:8004",
		"admin-api":           "8005:8005",
		"oauth-service":       "8006:8006",
		"access-service":      "8007:8007",
	}

	for service, port := range expectedPorts {
		if !strings.Contains(contentStr, port) {
			t.Errorf("Service %s should have port mapping %s", service, port)
		}
	}

	// Validate ports are only exposed on localhost
	if !strings.Contains(contentStr, "127.0.0.1:8001") {
		t.Error("Service ports should be bound to localhost only")
	}
}

// TestVolumeConfiguration validates persistent volume configuration
func TestVolumeConfiguration(t *testing.T) {
	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Validate volume definitions
	requiredVolumes := []string{
		"postgres_data:",
		"redis_data:",
		"elasticsearch_data:",
		"etcd_data:",
		"certbot_certs:",
	}

	for _, volume := range requiredVolumes {
		if !strings.Contains(contentStr, volume) {
			t.Errorf("Missing volume definition: %s", volume)
		}
	}

	// Validate backup volume path
	if !strings.Contains(contentStr, "POSTGRES_BACKUP_PATH") {
		t.Error("Should configure backup path for PostgreSQL")
	}
}

// TestResourceLimits validates resource limits are configured
func TestResourceLimits(t *testing.T) {
	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Validate resource limits section exists
	if !strings.Contains(contentStr, "deploy:") {
		t.Error("Production services should have deployment configuration")
	}

	if !strings.Contains(contentStr, "resources:") {
		t.Error("Production services should have resource limits")
	}

	// Validate memory limits exist
	if strings.Count(contentStr, "memory:") < 5 {
		t.Error("Services should have memory limits configured")
	}

	// Validate CPU limits exist
	if strings.Count(contentStr, "cpus:") < 5 {
		t.Error("Services should have CPU limits configured")
	}
}

// TestLoggingConfiguration validates logging configuration
func TestLoggingConfiguration(t *testing.T) {
	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Validate JSON file driver is used
	if !strings.Contains(contentStr, `driver: "json-file"`) {
		t.Error("Production services should use json-file log driver")
	}

	// Validate log rotation is configured
	if strings.Count(contentStr, "max-size") < 5 {
		t.Error("Services should have log size limits configured")
	}

	if strings.Count(contentStr, "max-file") < 5 {
		t.Error("Services should have log file count limits configured")
	}

	// Expected log size limit
	if !strings.Contains(contentStr, `"10m"`) {
		t.Error("Log files should be limited to 10m")
	}
}

// TestSSLConfiguration validates SSL/TLS configuration
func TestSSLConfiguration(t *testing.T) {
	nginxConfPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(nginxConfPath)
	if err != nil {
		t.Fatalf("Failed to read nginx site configuration: %v", err)
	}

	contentStr := string(content)

	// Validate TLS 1.2 and 1.3 only (no SSLv3, TLS 1.0, 1.1)
	if !strings.Contains(contentStr, "ssl_protocols TLSv1.2 TLSv1.3") {
		t.Error("Should only allow TLS 1.2 and 1.3")
	}

	// Validate strong ciphers
	if !strings.Contains(contentStr, "ssl_ciphers") {
		t.Error("Should configure SSL ciphers")
	}

	// Validate SSL stapling
	if !strings.Contains(contentStr, "ssl_stapling on") {
		t.Error("SSL stapling should be enabled")
	}

	// Validate HSTS header
	if !strings.Contains(contentStr, "Strict-Transport-Security") {
		t.Error("HSTS header should be configured")
	}

	// Validate HSTS includes preload
	if !strings.Contains(contentStr, "preload") {
		t.Error("HSTS should include preload directive")
	}
}

// TestCORSEnabledForProductionDomain validates CORS configuration
func TestCORSEnabledForProductionDomain(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Count CORS configuration occurrences
	corsCount := strings.Count(contentStr, "\"allow_origins\"")

	if corsCount < 5 {
		t.Errorf("Expected at least 5 CORS configurations, found %d", corsCount)
	}

	// Validate production domain is used for CORS
	if !strings.Contains(contentStr, "https://'$DOMAIN'") {
		t.Error("CORS should be configured for production domain")
	}
}

// TestHealthCheckEndpoints validates health check configuration
func TestHealthCheckEndpoints(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate health check routes for all services
	healthRoutes := []string{
		"health-identity",
		"health-governance",
		"health-provisioning",
		"health-audit",
		"health-admin",
		"health-oauth",
		"health-access",
	}

	for _, route := range healthRoutes {
		if !strings.Contains(contentStr, "'"+route+"'") {
			t.Errorf("Missing health check route: %s", route)
		}
	}
}

// TestBackupSchedulerConfiguration validates backup scheduler
func TestBackupSchedulerConfiguration(t *testing.T) {
	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Validate backup scheduler service
	if !strings.Contains(contentStr, "backup-scheduler:") {
		t.Error("Missing backup-scheduler service")
	}

	// Validate cron configuration
	if !strings.Contains(contentStr, "BACKUP_SCHEDULE") {
		t.Error("Should configure backup schedule")
	}

	// Validate retention
	if !strings.Contains(contentStr, "BACKUP_RETENTION_DAYS") {
		t.Error("Should configure backup retention")
	}

	// Validate backup script mount
	if !strings.Contains(contentStr, "./scripts/backup.sh") {
		t.Error("Should mount backup script")
	}

	// Validate backup directory mount
	if !strings.Contains(contentStr, "/backups") {
		t.Error("Should mount backup directory")
	}
}

// TestOauthConfiguration validates OAuth service configuration
func TestOauthConfiguration(t *testing.T) {
	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Validate OAuth issuer URL
	if strings.Count(contentStr, "OAUTH_ISSUER=https://openidx.tdv.org") < 2 {
		t.Error("OAuth issuer should be configured for production domain")
	}

	// Validate JWKS URL
	if strings.Count(contentStr, "OAUTH_JWKS_URL=https://openidx.tdv.org/.well-known/jwks.json") < 2 {
		t.Error("JWKS URL should be configured for production domain")
	}
}

// TestScimConfiguration validates SCIM provisioning configuration
func TestScimConfiguration(t *testing.T) {
	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Validate SCIM bearer token
	if !strings.Contains(contentStr, "SCIM_BEARER_TOKEN") {
		t.Error("SCIM bearer token should be configured")
	}

	// Validate SCIM routes are defined
	scriptPath := "load-production-routes.sh"
	routesContent, _ := os.ReadFile(scriptPath)

	if !strings.Contains(string(routesContent), "/scim/v2/Users") {
		t.Error("SCIM user routes should be configured")
	}

	if !strings.Contains(string(routesContent), "/scim/v2/Groups") {
		t.Error("SCIM group routes should be configured")
	}
}

// TestRateLimitingConfiguration validates rate limiting is configured
func TestRateLimitingConfiguration(t *testing.T) {
	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Validate rate limiting is enabled
	if !strings.Contains(contentStr, "OPENIDX_ENABLE_RATE_LIMIT=true") {
		t.Error("Rate limiting should be enabled")
	}

	// Validate rate limit configuration
	if !strings.Contains(contentStr, "RATE_LIMIT_RPM") {
		t.Error("Rate limit RPM should be configured")
	}

	// Validate APISIX rate limiting plugin
	scriptPath := "load-production-routes.sh"
	routesContent, _ := os.ReadFile(scriptPath)

	if !strings.Contains(string(routesContent), "limit-req") {
		t.Error("APISIX rate limiting plugin should be configured")
	}
}

// TestProductionNetworkConfiguration validates network configuration
func TestProductionNetworkConfiguration(t *testing.T) {
	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Validate network section
	if !strings.Contains(contentStr, "networks:") {
		t.Error("Networks section should be defined")
	}

	// Validate bridge network
	if !strings.Contains(contentStr, "driver: bridge") {
		t.Error("Should use bridge network driver")
	}

	// Validate network name
	if !strings.Contains(contentStr, "openidx-prod") {
		t.Error("Should configure production network name")
	}
}

// TestSMTPConfiguration validates email configuration
func TestSMTPConfiguration(t *testing.T) {
	envPath := ".env.production"

	content, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("Failed to read .env.production: %v", err)
	}

	contentStr := string(content)

	// Validate SMTP configuration
	requiredSMTPVars := []string{
		"SMTP_HOST=",
		"SMTP_PORT=",
		"SMTP_USER=",
		"SMTP_PASSWORD=",
		"SMTP_FROM=",
	}

	for _, envVar := range requiredSMTPVars {
		if !strings.Contains(contentStr, envVar) {
			t.Errorf("Missing SMTP configuration: %s", envVar)
		}
	}

	// Validate default SMTP from address
	if !strings.Contains(contentStr, "noreply@openidx.tdv.org") {
		t.Error("Default from address should use production domain")
	}
}

// TestCertificatePaths validates certificate path configuration
func TestCertificatePaths(t *testing.T) {
	nginxConfPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(nginxConfPath)
	if err != nil {
		t.Fatalf("Failed to read nginx site configuration: %v", err)
	}

	contentStr := string(content)

	// Validate certificate paths
	expectedPaths := []string{
		"/etc/letsencrypt/live/openidx.tdv.org/fullchain.pem",
		"/etc/letsencrypt/live/openidx.tdv.org/privkey.pem",
		"/etc/letsencrypt/live/openidx.tdv.org/chain.pem",
	}

	for _, path := range expectedPaths {
		if !strings.Contains(contentStr, path) {
			t.Errorf("Missing certificate path: %s", path)
		}
	}
}

// TestACMEChallengeConfiguration validates Let's Encrypt ACME challenge
func TestACMEChallengeConfiguration(t *testing.T) {
	nginxConfPath := "nginx/conf.d/openidx.tdv.org.conf"

	content, err := os.ReadFile(nginxConfPath)
	if err != nil {
		t.Fatalf("Failed to read nginx site configuration: %v", err)
	}

	contentStr := string(content)

	// Validate ACME challenge location
	if !strings.Contains(contentStr, "/.well-known/acme-challenge/") {
		t.Error("Missing ACME challenge location for Let's Encrypt")
	}

	// Validate webroot path
	if !strings.Contains(contentStr, "/var/www/certbot") {
		t.Error("Missing certbot webroot path")
	}

	// Validate compose file has certbot webroot volume
	composePath := "docker-compose.prod.yml"
	composeContent, _ := os.ReadFile(composePath)

	if !strings.Contains(string(composeContent), "certbot_webroot") {
		t.Error("Missing certbot webroot volume")
	}
}

// TestDemoAppsDisabled validates demo apps are disabled in production
func TestDemoAppsDisabled(t *testing.T) {
	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Validate demo apps have restart: no or profiles
	demoApps := []string{
		"demo-app:",
		"simple-web:",
		"mailpit:",
	}

	for _, app := range demoApps {
		if !strings.Contains(contentStr, app) {
			continue // App might not be in file
		}

		// Find the app section and check restart policy or profile
		appIndex := strings.Index(contentStr, app)
		if appIndex > 0 {
			section := contentStr[appIndex:appIndex+200]
			if !strings.Contains(section, "restart: \"no\"") &&
			   !strings.Contains(section, "profiles:") {
				t.Errorf("Demo app %s should be disabled in production", app)
			}
		}
	}
}
