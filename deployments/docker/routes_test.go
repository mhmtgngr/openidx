// ============================================================================
// OpenIDX Production Routes Configuration Tests
// Tests for load-production-routes.sh script validation
// ============================================================================

package docker

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestRoutesScriptStructure validates script structure
func TestRoutesScriptStructure(t *testing.T) {
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

	// Validate script has functions
	requiredFunctions := []string{
		"create_route()",
		"update_route()",
		"delete_route()",
		"create_upstream()",
		"create_service()",
	}

	for _, fn := range requiredFunctions {
		if !strings.Contains(contentStr, fn) {
			t.Errorf("Missing function: %s", fn)
		}
	}
}

// TestRoutesAPIConfiguration validates APISIX admin API configuration
func TestRoutesAPIConfiguration(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate APISIX admin URL variable
	if !strings.Contains(contentStr, "APISIX_ADMIN_URL") {
		t.Error("Missing APISIX_ADMIN_URL variable")
	}

	// Validate default admin URL
	if !strings.Contains(contentStr, "http://localhost:9188") {
		t.Error("Should use localhost:9188 as default admin URL")
	}

	// Validate API key variable
	if !strings.Contains(contentStr, "APISIX_ADMIN_KEY") {
		t.Error("Missing APISIX_ADMIN_KEY variable")
	}

	// Validate API key header in curl commands
	if !strings.Contains(contentStr, "X-API-KEY:") {
		t.Error("Should use X-API-KEY header for authentication")
	}

	// Validate Content-Type header
	if strings.Count(contentStr, "Content-Type: application/json") < 3 {
		t.Error("Should set Content-Type for JSON API calls")
	}
}

// TestRoutesWaitForAPISIX validates APISIX readiness check
func TestRoutesWaitForAPISIX(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate wait loop
	if !strings.Contains(contentStr, "APISIX to be ready") {
		t.Error("Should wait for APISIX to be ready")
	}

	// Validate max attempts
	if !strings.Contains(contentStr, "max_attempts") {
		t.Error("Should have max attempts for readiness check")
	}

	// Validate curl check
	if !strings.Contains(contentStr, `curl -s -f "$ADMIN_API_URL/apisix/admin/services"`) {
		t.Error("Should check APISIX admin API endpoint")
	}
}

// TestRoutesUpstreamConfiguration validates upstream definitions
func TestRoutesUpstreamConfiguration(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate all service upstreams are created
	requiredUpstreams := []string{
		"identity-service-upstream",
		"governance-service-upstream",
		"provisioning-service-upstream",
		"audit-service-upstream",
		"admin-api-upstream",
		"oauth-service-upstream",
		"access-service-upstream",
	}

	for _, upstream := range requiredUpstreams {
		if !strings.Contains(contentStr, "'"+upstream+"'") {
			t.Errorf("Missing upstream: %s", upstream)
		}
	}

	// Validate upstream configuration includes nodes
	if !strings.Contains(contentStr, `"nodes":`) {
		t.Error("Upstreams should define nodes")
	}

	// Validate upstream type
	if !strings.Contains(contentStr, `"type": "roundrobin"`) {
		t.Error("Upstreams should use roundrobin type")
	}

	// Validate timeout configuration
	if !strings.Contains(contentStr, `"timeout":`) {
		t.Error("Upstreams should have timeout configuration")
	}
}

// TestRoutesServicePlugins validates service plugin configuration
func TestRoutesServicePlugins(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate rate limiting plugin
	if !strings.Contains(contentStr, `"limit-req":`) {
		t.Error("Services should have rate limiting plugin")
	}

	// Validate CORS plugin
	if !strings.Contains(contentStr, `"cors":`) {
		t.Error("Services should have CORS plugin")
	}

	// Validate Prometheus plugin
	if !strings.Contains(contentStr, `"prometheus":`) {
		t.Error("Services should have Prometheus metrics plugin")
	}

	// Validate CORS allow_origins uses production domain
	if !strings.Contains(contentStr, "https://'$DOMAIN'") {
		t.Error("CORS should be configured for production domain")
	}
}

// TestRoutesIdentityService validates identity service routes
func TestRoutesIdentityService(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate identity service route creation
	if !strings.Contains(contentStr, "'identity-service-users'") {
		t.Error("Missing identity service users route")
	}

	// Validate route paths
	if !strings.Contains(contentStr, `"/api/v1/identity/users"`) {
		t.Error("Identity service should have users route")
	}

	if !strings.Contains(contentStr, `"/api/v1/identity/sessions"`) {
		t.Error("Identity service should have sessions route")
	}

	if !strings.Contains(contentStr, `"/api/v1/identity/mfa/*"`) {
		t.Error("Identity service should have MFA route")
	}
}

// TestRoutesOAuthService validates OAuth service routes
func TestRoutesOAuthService(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate OAuth routes
	requiredOAuthRoutes := []string{
		"'oauth-service-authorize'",
		"'oauth-service-token'",
		"'oauth-service-introspect'",
		"'oauth-service-userinfo'",
	}

	for _, route := range requiredOAuthRoutes {
		if !strings.Contains(contentStr, route) {
			t.Errorf("Missing OAuth route: %s", route)
		}
	}

	// Validate OIDC discovery route
	if !strings.Contains(contentStr, "'oidc-discovery'") {
		t.Error("Missing OIDC discovery route")
	}

	// Validate .well-known path (uses wildcard in uris array)
	if !strings.Contains(contentStr, `"uris": ["/.well-known/"`) &&
	   !strings.Contains(contentStr, `"uris": ["/.well-known/*"`) {
		t.Error("Missing .well-known route pattern")
	}
}

// TestRoutesSCIMService validates SCIM provisioning routes
func TestRoutesSCIMService(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate SCIM routes
	requiredSCIMRoutes := []string{
		"'provisioning-service-scim-users'",
		"'provisioning-service-scim-groups'",
		"'provisioning-service-scim-schemas'",
	}

	for _, route := range requiredSCIMRoutes {
		if !strings.Contains(contentStr, route) {
			t.Errorf("Missing SCIM route: %s", route)
		}
	}

	// Validate SCIM paths
	requiredSCIMPaths := []string{
		`"/scim/v2/Users"`,
		`"/scim/v2/Groups"`,
		`"/scim/v2/Schemas"`,
		`"/scim/v2/ResourceTypes"`,
		`"/scim/v2/ServiceProviderConfig"`,
	}

	for _, path := range requiredSCIMPaths {
		if !strings.Contains(contentStr, path) {
			t.Errorf("Missing SCIM path: %s", path)
		}
	}
}

// TestRoutesHealthChecks validates health check routes
func TestRoutesHealthChecks(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate health check routes for all services
	healthRoutes := []string{
		"'health-identity'",
		"'health-governance'",
		"'health-provisioning'",
		"'health-audit'",
		"'health-admin'",
		"'health-oauth'",
		"'health-access'",
	}

	for _, route := range healthRoutes {
		if !strings.Contains(contentStr, route) {
			t.Errorf("Missing health route: %s", route)
		}
	}

	// Validate health check paths
	healthPaths := []string{
		`"/api/v1/identity/health"`,
		`"/api/v1/governance/health"`,
		`"/oauth/health"`,
	}

	for _, path := range healthPaths {
		if !strings.Contains(contentStr, path) {
			t.Errorf("Missing health path: %s", path)
		}
	}

	// Validate health routes have no auth (plugins: {})
	if !strings.Contains(contentStr, `"plugins": {}`) {
		t.Error("Health check routes should have no plugins (no auth)")
	}
}

// TestRoutesCORSPreflight validates CORS preflight route
func TestRoutesCORSPreflight(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate CORS preflight route
	if !strings.Contains(contentStr, "'cors-preflight'") {
		t.Error("Missing CORS preflight route")
	}

	// Validate OPTIONS method
	if !strings.Contains(contentStr, `"methods": ["OPTIONS"]`) {
		t.Error("CORS preflight should handle OPTIONS method")
	}

	// Validate catch-all URI pattern
	if !strings.Contains(contentStr, `"uri": "/.*"`) {
		t.Error("CORS preflight should catch all URIs")
	}

	// Validate high priority for preflight
	if !strings.Contains(contentStr, `"priority": 1000`) {
		t.Error("CORS preflight should have high priority")
	}
}

// TestRoutesAdminAPI validates admin API routes
func TestRoutesAdminAPI(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate admin API routes
	adminRoutes := []string{
		"'admin-api-dashboard'",
		"'admin-api-settings'",
		"'admin-api-applications'",
		"'admin-api-users'",
	}

	for _, route := range adminRoutes {
		if !strings.Contains(contentStr, route) {
			t.Errorf("Missing admin API route: %s", route)
		}
	}

	// Validate admin API paths
	adminPaths := []string{
		`"/api/v1/dashboard"`,
		`"/api/v1/settings"`,
		`"/api/v1/applications"`,
		`"/api/v1/users"`,
	}

	for _, path := range adminPaths {
		if !strings.Contains(contentStr, path) {
			t.Errorf("Missing admin API path: %s", path)
		}
	}
}

// TestRoutesAccessService validates access service routes
func TestRoutesAccessService(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate access service routes
	accessRoutes := []string{
		"'access-service-api'",
		"'access-service-auth-flow'",
		"'access-service-proxy'",
	}

	for _, route := range accessRoutes {
		if !strings.Contains(contentStr, route) {
			t.Errorf("Missing access service route: %s", route)
		}
	}

	// Validate access proxy rewrite plugin
	if !strings.Contains(contentStr, `"proxy-rewrite":`) {
		t.Error("Access proxy should use proxy-rewrite plugin")
	}

	// Validate longer timeouts for access service (WebSocket support)
	if !strings.Contains(contentStr, `"send": 300`) {
		t.Error("Access service should have longer timeout for WebSocket")
	}
}

// TestRoutesVerification validates route verification logic
func TestRoutesVerification(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Verify section exists
	if !strings.Contains(contentStr, "Verifying routes...") {
		t.Error("Script should verify routes after creation")
	}

	// Validate total routes check
	if !strings.Contains(contentStr, "total_routes") {
		t.Error("Should count total routes")
	}

	// Validate test routes function
	if !strings.Contains(contentStr, "test_route()") {
		t.Error("Should have test_route function")
	}

	// Validate test calls for critical routes
	criticalTests := []string{
		"Identity Service",
		"OAuth Service",
		"OIDC Discovery",
	}

	for _, test := range criticalTests {
		if !strings.Contains(contentStr, test) {
			t.Errorf("Should test critical route: %s", test)
		}
	}
}

// TestRoutesColorOutput validates colored output functions
func TestRoutesColorOutput(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate color definitions
	colors := []string{
		"GREEN='\\033[0;32m'",
		"RED='\\033[0;31m'",
		"YELLOW='\\033[1;33m'",
		"BLUE='\\033[0;34m'",
		"NC='\\033[0m'",
	}

	for _, color := range colors {
		if !strings.Contains(contentStr, color) {
			t.Errorf("Missing color definition: %s", color)
		}
	}

	// Validate logging functions
	logFunctions := []string{
		"log()",
		"warn()",
		"error()",
		"info()",
	}

	for _, fn := range logFunctions {
		if !strings.Contains(contentStr, fn) {
			t.Errorf("Missing log function: %s", fn)
		}
	}
}

// TestRoutesRateLimiting validates rate limiting configuration
func TestRoutesRateLimiting(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate rate limiting configuration
	if !strings.Contains(contentStr, `"rate":`) {
		t.Error("Should configure rate limit rate")
	}

	if !strings.Contains(contentStr, `"burst":`) {
		t.Error("Should configure rate limit burst")
	}

	if !strings.Contains(contentStr, `"key": "remote_addr"`) {
		t.Error("Should use remote_addr as rate limit key")
	}

	if !strings.Contains(contentStr, `"rejected_code": 429`) {
		t.Error("Should return 429 for rate limited requests")
	}
}

// TestRoutesMethodsConfiguration validates HTTP methods configuration
func TestRoutesMethodsConfiguration(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate common methods are used
	commonMethods := []string{
		`"GET"`,
		`"POST"`,
		`"PUT"`,
		`"DELETE"`,
		`"PATCH"`,
		`"OPTIONS"`,
	}

	for _, method := range commonMethods {
		if !strings.Contains(contentStr, method) {
			t.Errorf("Routes should support method: %s", method)
		}
	}
}

// TestRoutesJSONStructure validates JSON structure in route definitions
func TestRoutesJSONStructure(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate proper JSON structure
	// Routes should have proper quoting
	if !strings.Contains(contentStr, `"uris": [`) {
		t.Error("Routes should define uris as array")
	}

	if !strings.Contains(contentStr, `"name":`) {
		t.Error("Routes should have name property")
	}

	if !strings.Contains(contentStr, `"methods":`) {
		t.Error("Routes should define methods")
	}

	if !strings.Contains(contentStr, `"priority":`) {
		t.Error("Routes should have priority")
	}
}

// TestRoutesUpstreamTimeouts validates upstream timeout configuration
func TestRoutesUpstreamTimeouts(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate timeout configuration structure
	if !strings.Contains(contentStr, `"timeout": {`) {
		t.Error("Upstreams should have timeout configuration")
	}

	// Validate timeout types
	timeoutTypes := []string{
		`"connect":`,
		`"send":`,
		`"read":`,
	}

	for _, tt := range timeoutTypes {
		if !strings.Contains(contentStr, tt) {
			t.Errorf("Upstreams should have %s timeout", tt)
		}
	}

	// Validate retry configuration
	if !strings.Contains(contentStr, `"retries":`) {
		t.Error("Upstreams should configure retries")
	}
}

// TestRoutesServiceLinking validates service to upstream linking
func TestRoutesServiceLinking(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate services reference upstreams
	if !strings.Contains(contentStr, `"upstream_id":`) {
		t.Error("Services should reference upstreams")
	}

	// Validate routes reference services
	if !strings.Contains(contentStr, `"service_id":`) {
		t.Error("Routes should reference services")
	}
}

// TestRoutesURIPatterns validates URI pattern configuration
func TestRoutesURIPatterns(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate exact URI match
	if !strings.Contains(contentStr, `"uris": ["`) {
		t.Error("Should use exact URI matching where appropriate")
	}

	// Validate wildcard URI
	if !strings.Contains(contentStr, `"uri":`) {
		t.Error("Should support wildcard URI patterns")
	}

	// Validate regex URI for proxy rewrite
	if !strings.Contains(contentStr, `"regex_uri":`) {
		t.Error("Access proxy should use regex_uri for rewrite")
	}
}

// TestRoutesProductionDomain validates production domain usage
func TestRoutesProductionDomain(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate PRODUCTION_DOMAIN variable
	if !strings.Contains(contentStr, "PRODUCTION_DOMAIN") {
		t.Error("Missing PRODUCTION_DOMAIN variable")
	}

	// Validate default domain
	if !strings.Contains(contentStr, "openidx.tdv.org") {
		t.Error("Should default to openidx.tdv.org")
	}

	// Validate domain variable is used in routes
	if strings.Count(contentStr, "'$DOMAIN'") < 2 {
		t.Error("Domain variable should be used in route configuration")
	}
}

// TestRoutesAuditServiceRoutes validates audit service routes
func TestRoutesAuditServiceRoutes(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate audit service routes
	auditRoutes := []string{
		"'audit-service-events'",
		"'audit-service-reports'",
		"'audit-service-statistics'",
	}

	for _, route := range auditRoutes {
		if !strings.Contains(contentStr, route) {
			t.Errorf("Missing audit service route: %s", route)
		}
	}

	// Validate audit paths
	auditPaths := []string{
		`"/api/v1/audit/events"`,
		`"/api/v1/audit/reports"`,
		`"/api/v1/audit/statistics"`,
	}

	for _, path := range auditPaths {
		if !strings.Contains(contentStr, path) {
			t.Errorf("Missing audit path: %s", path)
		}
	}
}

// TestRoutesGovernanceServiceRoutes validates governance service routes
func TestRoutesGovernanceServiceRoutes(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate governance service routes
	governanceRoutes := []string{
		"'governance-service-reviews'",
		"'governance-service-policies'",
	}

	for _, route := range governanceRoutes {
		if !strings.Contains(contentStr, route) {
			t.Errorf("Missing governance service route: %s", route)
		}
	}

	// Validate governance paths
	governancePaths := []string{
		`"/api/v1/governance/reviews"`,
		`"/api/v1/governance/policies"`,
	}

	for _, path := range governancePaths {
		if !strings.Contains(contentStr, path) {
			t.Errorf("Missing governance path: %s", path)
		}
	}
}

// TestRoutesComplexJSON validates complex JSON structures are properly formed
func TestRoutesComplexJSON(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Count opening and closing braces for plugins sections
	pluginOpenCount := strings.Count(contentStr, `"plugins": {`)
	_ = strings.Count(contentStr, `"limit-req": {`) + strings.Count(contentStr, `"cors": {`)

	if pluginOpenCount < 5 {
		t.Error("Should have multiple plugin configurations")
	}

	// Validate nested JSON is properly quoted
	if !strings.Contains(contentStr, `"allow_origins": "https://'$DOMAIN'"`) {
		t.Error("CORS origins should be properly quoted")
	}
}

// TestRoutesCurlCommands validates curl command usage
func TestRoutesCurlCommands(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate PUT for creating routes
	if !strings.Contains(contentStr, `curl -s -X PUT`) {
		t.Error("Should use PUT for creating resources")
	}

	// Validate PATCH for updating
	if !strings.Contains(contentStr, `curl -s -X PATCH`) {
		t.Error("Should use PATCH for updates")
	}

	// Validate DELETE for deletion
	if !strings.Contains(contentStr, `curl -s -X DELETE`) {
		t.Error("Should use DELETE for removal")
	}

	// Validate silent flag
	if !strings.Contains(contentStr, `curl -s`) {
		t.Error("Should use silent curl for clean output")
	}
}

// TestRoutesErrorDetection validates error detection in API calls
func TestRoutesErrorDetection(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate error detection
	if !strings.Contains(contentStr, `grep -q '"error"'`) {
		t.Error("Should check for error in API responses")
	}

	// Validate FAILED message
	if !strings.Contains(contentStr, `"FAILED"`) && !strings.Contains(contentStr, `${RED}FAILED`) {
		t.Error("Should indicate FAILED on error")
	}

	// Validate OK message
	if !strings.Contains(contentStr, `"OK"`) && !strings.Contains(contentStr, `${GREEN}OK`) {
		t.Error("Should indicate OK on success")
	}
}

// TestRoutesWildcardMatching validates wildcard URI patterns
func TestRoutesWildcardMatching(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate wildcard patterns
	wildcardPatterns := []string{
		`"/*"`,
		`"/.*"`,
		`"~^/"`,
	}

	hasWildcard := false
	for _, pattern := range wildcardPatterns {
		if strings.Contains(contentStr, pattern) {
			hasWildcard = true
			break
		}
	}

	if !hasWildcard {
		t.Error("Should use wildcard patterns for some routes")
	}
}

// TestRoutesServicePriorities validates route priority configuration
func TestRoutesServicePriorities(t *testing.T) {
	scriptPath := "load-production-routes.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read load-production-routes.sh: %v", err)
	}

	contentStr := string(content)

	// Validate priority is set on routes
	if !strings.Contains(contentStr, `"priority":`) {
		t.Error("Routes should have priority configuration")
	}

	// Validate different priority levels
	priorityPattern := regexp.MustCompile(`"priority":\s*(\d+)`)
	priorities := priorityPattern.FindAllStringSubmatch(contentStr, -1)

	if len(priorities) < 5 {
		t.Error("Should have multiple priority levels configured")
	}

	// Check for high priority (CORS preflight)
	hasHighPriority := false
	for _, match := range priorities {
		if len(match) > 1 {
			priority := match[1]
			if priority == "1000" || priority == "100" {
				hasHighPriority = true
				break
			}
		}
	}

	if !hasHighPriority {
		t.Error("Should have high priority routes for critical endpoints")
	}
}
