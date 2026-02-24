#!/usr/bin/env bats
# ============================================================================
# OpenIDX Production - APISIX Routes Loading Script Tests
# Tests the production route configuration script
# ============================================================================

load test-helper/bats-support/load.bash
load test-helper/bats-assert/load.bash

# ============================================================================
# Test Setup
# ============================================================================

setup() {
  # Create temp directory for tests
  TEST_TMP_DIR="$(mktemp -d)"
  export TEST_TMP_DIR

  # Export production domain
  export PRODUCTION_DOMAIN="openidx.tdv.org"
  export APISIX_ADMIN_URL="http://localhost:9188"
  export APISIX_ADMIN_KEY="test-admin-key"

  # Copy script to temp location
  cp ../deployments/docker/load-production-routes.sh "$TEST_TMP_DIR/"
  chmod +x "$TEST_TMP_DIR/load-production-routes.sh"
}

teardown() {
  rm -rf "$TEST_TMP_DIR"
}

# ============================================================================
# Script Structure Tests
# ============================================================================

@test "load-production-routes.sh should exist and be executable" {
  [ -f "../deployments/docker/load-production-routes.sh" ]
}

@test "load-production-routes.sh should have bash shebang" {
  run head -n 1 ../deployments/docker/load-production-routes.sh
  assert_output --partial "#!/bin/bash"
}

@test "load-production-routes.sh should use set -e for error handling" {
  run grep "set -e" ../deployments/docker/load-production-routes.sh
  assert_success
}

# ============================================================================
# Configuration Tests
# ============================================================================

@test "script should define APISIX_ADMIN_URL variable" {
  run grep "APISIX_ADMIN_URL=" ../deployments/docker/load-production-routes.sh
  assert_output --partial "http://localhost:9188"
  assert_success
}

@test "script should define APISIX_ADMIN_KEY variable" {
  run grep "APISIX_ADMIN_KEY=" ../deployments/docker/load-production-routes.sh
  assert_output --partial "edd1c9f034335f136f87ad84b625c8f1"
  assert_success
}

@test "script should define PRODUCTION_DOMAIN variable" {
  run grep "PRODUCTION_DOMAIN=" ../deployments/docker/load-production-routes.sh
  assert_output --partial "openidx.tdv.org"
  assert_success
}

# ============================================================================
# Helper Function Tests
# ============================================================================

@test "script should define create_route function" {
  run grep "^create_route()" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should define update_route function" {
  run grep "^update_route()" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should define delete_route function" {
  run grep "^delete_route()" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should define create_upstream function" {
  run grep "^create_upstream()" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should define create_service function" {
  run grep "^create_service()" ../deployments/docker/load-production-routes.sh
  assert_success
}

# ============================================================================
# APISIX API Call Tests
# ============================================================================

@test "create_route should use PUT method" {
  run grep -A 10 "create_route()" ../deployments/docker/load-production-routes.sh
  assert_output --partial "curl -s -X PUT"
}

@test "create_upstream should use PUT method" {
  run grep -A 10 "create_upstream()" ../deployments/docker/load-production-routes.sh
  assert_output --partial "curl -s -X PUT"
}

@test "create_service should use PUT method" {
  run grep -A 10 "create_service()" ../deployments/docker/load-production-routes.sh
  assert_output --partial "curl -s -X PUT"
}

@test "update_route should use PATCH method" {
  run grep -A 10 "update_route()" ../deployments/docker/load-production-routes.sh
  assert_output --partial "curl -s -X PATCH"
}

@test "delete_route should use DELETE method" {
  run grep -A 10 "delete_route()" ../deployments/docker/load-production-routes.sh
  assert_output --partial "curl -s -X DELETE"
}

@test "API calls should include X-API-KEY header" {
  run grep 'X-API-KEY:' ../deployments/docker/load-production-routes.sh
  assert_output --partial "\$ADMIN_KEY"
}

@test "API calls should include Content-Type header" {
  run grep 'Content-Type: application/json' ../deployments/docker/load-production-routes.sh
  assert_success
}

# ============================================================================
# Upstream Creation Tests
# ============================================================================

@test "script should create identity-service-upstream" {
  run grep "identity-service-upstream" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create governance-service-upstream" {
  run grep "governance-service-upstream" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create provisioning-service-upstream" {
  run grep "provisioning-service-upstream" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create audit-service-upstream" {
  run grep "audit-service-upstream" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create admin-api-upstream" {
  run grep "admin-api-upstream" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create oauth-service-upstream" {
  run grep "oauth-service-upstream" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create access-service-upstream" {
  run grep "access-service-upstream" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "upstreams should configure roundrobin load balancing" {
  run grep -A 5 "create_upstream" ../deployments/docker/load-production-routes.sh
  assert_output --partial '"type": "roundrobin"'
}

@test "upstreams should configure timeouts" {
  run grep -A 5 "create_upstream" ../deployments/docker/load-production-routes.sh
  assert_output --partial '"timeout"'
}

@test "upstreams should configure retries" {
  run grep -A 5 "create_upstream" ../deployments/docker/load-production-routes.sh
  assert_output --partial '"retries"'
}

# ============================================================================
# Service Creation Tests
# ============================================================================

@test "script should create identity-service-svc" {
  run grep "identity-service-svc" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create governance-service-svc" {
  run grep "governance-service-svc" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create provisioning-service-svc" {
  run grep "provisioning-service-svc" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create audit-service-svc" {
  run grep "audit-service-svc" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create admin-api-svc" {
  run grep "admin-api-svc" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create oauth-service-svc" {
  run grep "oauth-service-svc" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create access-service-svc" {
  run grep "access-service-svc" ../deployments/docker/load-production-routes.sh
  assert_success
}

# ============================================================================
# CORS Configuration Tests
# ============================================================================

@test "services should configure CORS plugin" {
  run grep '"cors"' ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "CORS should use production domain" {
  run grep "allow_origins" ../deployments/docker/load-production-routes.sh
  assert_output --partial "https://'\$DOMAIN'"
}

@test "CORS should allow common HTTP methods" {
  run grep "allow_methods" ../deployments/docker/load-production-routes.sh
  assert_output --partial "GET,POST,PUT,DELETE"
}

@test "CORS should allow required headers" {
  run grep "allow_headers" ../deployments/docker/load-production-routes.sh
  assert_output --partial "Content-Type,Authorization"
}

@test "CORS should allow credentials" {
  run grep "allow_credential" ../deployments/docker/load-production-routes.sh
  assert_output --partial "true"
}

# ============================================================================
# Rate Limiting Tests
# ============================================================================

@test "services should configure rate limiting plugin" {
  run grep '"limit-req"' ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "rate limiting should define rate limit" {
  run grep '"rate"' ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "rate limiting should define burst size" {
  run grep '"burst"' ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "rate limiting should use remote_addr as key" {
  run grep '"key".*remote_addr' ../deployments/docker/load-production-routes.sh
  assert_success
}

# ============================================================================
# Route Creation Tests
# ============================================================================

@test "script should create identity service routes" {
  run grep "identity-service-users" ../deployments/docker/load-production-routes.sh
  assert_success
  run grep "identity-service-sessions" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create governance service routes" {
  run grep "governance-service-reviews" ../deployments/docker/load-production-routes.sh
  assert_success
  run grep "governance-service-policies" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create SCIM routes" {
  run grep "provisioning-service-scim-users" ../deployments/docker/load-production-routes.sh
  assert_success
  run grep "provisioning-service-scim-groups" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create audit service routes" {
  run grep "audit-service-events" ../deployments/docker/load-production-routes.sh
  assert_success
  run grep "audit-service-reports" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create OAuth service routes" {
  run grep "oauth-service-authorize" ../deployments/docker/load-production-routes.sh
  assert_success
  run grep "oauth-service-token" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create admin API routes" {
  run grep "admin-api-dashboard" ../deployments/docker/load-production-routes.sh
  assert_success
  run grep "admin-api-users" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create access service routes" {
  run grep "access-service-api" ../deployments/docker/load-production-routes.sh
  assert_success
  run grep "access-service-auth-flow" ../deployments/docker/load-production-routes.sh
  assert_success
}

# ============================================================================
# Health Check Route Tests
# ============================================================================

@test "script should create health-identity route" {
  run grep "health-identity" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create health-governance route" {
  run grep "health-governance" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create health-provisioning route" {
  run grep "health-provisioning" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create health-audit route" {
  run grep "health-audit" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create health-admin route" {
  run grep "health-admin" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create health-oauth route" {
  run grep "health-oauth" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should create health-access route" {
  run grep "health-access" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "health check routes should have priority 1" {
  run grep -B 5 "health-identity" ../deployments/docker/load-production-routes.sh
  assert_output --partial '"priority": 1'
}

# ============================================================================
# OIDC Discovery Tests
# ============================================================================

@test "script should create oidc-discovery route" {
  run grep "oidc-discovery" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "oidc-discovery should match .well-known paths" {
  run grep -A 5 "oidc-discovery" ../deployments/docker/load-production-routes.sh
  assert_output --partial '"/.well-known/*"'
}

@test "oidc-discovery should route to oauth-service-svc" {
  run grep -A 10 "oidc-discovery" ../deployments/docker/load-production-routes.sh
  assert_output --partial 'oauth-service-svc'
}

# ============================================================================
# Logging Tests
# ============================================================================

@test "script should define log function" {
  run grep "^log()" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should define warn function" {
  run grep "^warn()" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should define error function" {
  run grep "^error()" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should define info function" {
  run grep "^info()" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should use colored output" {
  run grep "GREEN=" ../deployments/docker/load-production-routes.sh
  assert_success
  run grep "RED=" ../deployments/docker/load-production-routes.sh
  assert_success
  run grep "BLUE=" ../deployments/docker/load-production-routes.sh
  assert_success
}

# ============================================================================
# Wait for APISIX Tests
# ============================================================================

@test "script should wait for APISIX to be ready" {
  run grep "Waiting for APISIX" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should check APISIX health before configuring routes" {
  run grep "curl.*apisix/admin/services" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should have max attempts for APISIX readiness check" {
  run grep "max_attempts" ../deployments/docker/load-production-routes.sh
  assert_success
}

# ============================================================================
# Route Verification Tests
# ============================================================================

@test "script should verify routes after creation" {
  run grep "Verifying routes" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should query total route count" {
  run grep "total_routes" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should test specific routes" {
  run grep "test_route" ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "route tests should check HTTP status codes" {
  run grep -A 10 "test_route" ../deployments/docker/load-production-routes.sh
  assert_output --partial "status="
}

# ============================================================================
# Service Port Tests
# ============================================================================

@test "upstreams should point to correct service ports" {
  run grep "identity-service:8001" ../deployments/docker/load-production-routes.sh
  assert_success
  run grep "governance-service:8002" ../deployments/docker/load-production-routes.sh
  assert_success
  run grep "oauth-service:8006" ../deployments/docker/load-production-routes.sh
  assert_success
}

# ============================================================================
# Error Handling Tests
# ============================================================================

@test "create_route should check for errors in response" {
  run grep -A 10 "create_route()" ../deployments/docker/load-production-routes.sh
  assert_output --partial '"error"'
}

@test "create_upstream should check for errors in response" {
  run grep -A 10 "create_upstream()" ../deployments/docker/load-production-routes.sh
  assert_output --partial '"error"'
}

@test "script should log errors on failure" {
  run grep "error.*Error:" ../deployments/docker/load-production-routes.sh
  assert_success
}

# ============================================================================
# SCIM Configuration Tests
# ============================================================================

@test "script should route SCIM /Users endpoint" {
  run grep '"/scim/v2/Users"' ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should route SCIM /Groups endpoint" {
  run grep '"/scim/v2/Groups"' ../deployments/docker/load-production-routes.sh
  assert_success
}

@test "script should route SCIM discovery endpoints" {
  run grep "Schemas" ../deployments/docker/load-production-routes.sh
  assert_success
  run grep "ServiceProviderConfig" ../deployments/docker/load-production-routes.sh
  assert_success
}
