#!/bin/bash
# ============================================================================
# OpenIDX Production - APISIX Route Configuration
# Configures production routes for openidx.tdv.org
# ============================================================================

set -e

# Configuration
ADMIN_API_URL="${APISIX_ADMIN_URL:-http://localhost:9188}"
ADMIN_KEY="${APISIX_ADMIN_KEY:-edd1c9f034335f136f87ad84b625c8f1}"
DOMAIN="${PRODUCTION_DOMAIN:-openidx.tdv.org}"

# Color output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] ERROR:${NC} $1"
}

info() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')] INFO:${NC} $1"
}

# Function to create a route via Admin API
create_route() {
    local route_id="$1"
    local route_data="$2"

    echo -n "Creating route: ${BLUE}$route_id${NC}... "

    response=$(curl -s -X PUT "$ADMIN_API_URL/apisix/admin/routes/$route_id" \
        -H "X-API-KEY: $ADMIN_KEY" \
        -H "Content-Type: application/json" \
        -d "$route_data")

    if echo "$response" | grep -q '"error"'; then
        echo -e "${RED}FAILED${NC}"
        error "Error: $response"
        return 1
    else
        echo -e "${GREEN}OK${NC}"
        return 0
    fi
}

# Function to update a route
update_route() {
    local route_id="$1"
    local route_data="$2"

    echo -n "Updating route: ${BLUE}$route_id${NC}... "

    response=$(curl -s -X PATCH "$ADMIN_API_URL/apisix/admin/routes/$route_id" \
        -H "X-API-KEY: $ADMIN_KEY" \
        -H "Content-Type: application/json" \
        -d "$route_data")

    if echo "$response" | grep -q '"error"'; then
        echo -e "${RED}FAILED${NC}"
        error "Error: $response"
        return 1
    else
        echo -e "${GREEN}OK${NC}"
        return 0
    fi
}

# Function to delete a route
delete_route() {
    local route_id="$1"

    echo -n "Deleting route: ${BLUE}$route_id${NC}... "

    response=$(curl -s -X DELETE "$ADMIN_API_URL/apisix/admin/routes/$route_id" \
        -H "X-API-KEY: $ADMIN_KEY")

    if echo "$response" | grep -q '"error"'; then
        echo -e "${YELLOW}NOT FOUND${NC}"
        return 0
    else
        echo -e "${GREEN}OK${NC}"
        return 0
    fi
}

# Function to create an upstream
create_upstream() {
    local upstream_id="$1"
    local upstream_data="$2"

    echo -n "Creating upstream: ${BLUE}$upstream_id${NC}... "

    response=$(curl -s -X PUT "$ADMIN_API_URL/apisix/admin/upstreams/$upstream_id" \
        -H "X-API-KEY: $ADMIN_KEY" \
        -H "Content-Type: application/json" \
        -d "$upstream_data")

    if echo "$response" | grep -q '"error"'; then
        echo -e "${RED}FAILED${NC}"
        error "Error: $response"
        return 1
    else
        echo -e "${GREEN}OK${NC}"
        return 0
    fi
}

# Function to create a service
create_service() {
    local service_id="$1"
    local service_data="$2"

    echo -n "Creating service: ${BLUE}$service_id${NC}... "

    response=$(curl -s -X PUT "$ADMIN_API_URL/apisix/admin/services/$service_id" \
        -H "X-API-KEY: $ADMIN_KEY" \
        -H "Content-Type: application/json" \
        -d "$service_data")

    if echo "$response" | grep -q '"error"'; then
        echo -e "${RED}FAILED${NC}"
        error "Error: $response"
        return 1
    else
        echo -e "${GREEN}OK${NC}"
        return 0
    fi
}

# Wait for APISIX to be ready
log "Waiting for APISIX to be ready..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -s -f "$ADMIN_API_URL/apisix/admin/services" -H "X-API-KEY: $ADMIN_KEY" > /dev/null 2>&1; then
        log "APISIX is ready!"
        break
    fi
    attempt=$((attempt + 1))
    echo -n "."
    sleep 2
done

if [ $attempt -eq $max_attempts ]; then
    error "APISIX did not become ready in time"
    exit 1
fi

echo
log "========================================"
log "Loading Production Routes for $DOMAIN"
log "========================================"
echo

# ============================================================================
# Create Upstreams
# ============================================================================

log "Creating upstream definitions..."

create_upstream 'identity-service-upstream' '{
    "type": "roundrobin",
    "nodes": {
        "identity-service:8001": 1
    },
    "timeout": {
        "connect": 15,
        "send": 15,
        "read": 15
    },
    "scheme": "http",
    "retry_timeout": 0,
    "retries": 2
}'

create_upstream 'governance-service-upstream' '{
    "type": "roundrobin",
    "nodes": {
        "governance-service:8002": 1
    },
    "timeout": {
        "connect": 15,
        "send": 15,
        "read": 15
    },
    "scheme": "http",
    "retry_timeout": 0,
    "retries": 2
}'

create_upstream 'provisioning-service-upstream' '{
    "type": "roundrobin",
    "nodes": {
        "provisioning-service:8003": 1
    },
    "timeout": {
        "connect": 15,
        "send": 15,
        "read": 15
    },
    "scheme": "http",
    "retry_timeout": 0,
    "retries": 2
}'

create_upstream 'audit-service-upstream' '{
    "type": "roundrobin",
    "nodes": {
        "audit-service:8004": 1
    },
    "timeout": {
        "connect": 15,
        "send": 15,
        "read": 15
    },
    "scheme": "http",
    "retry_timeout": 0,
    "retries": 2
}'

create_upstream 'admin-api-upstream' '{
    "type": "roundrobin",
    "nodes": {
        "admin-api:8005": 1
    },
    "timeout": {
        "connect": 15,
        "send": 15,
        "read": 15
    },
    "scheme": "http",
    "retry_timeout": 0,
    "retries": 2
}'

create_upstream 'oauth-service-upstream' '{
    "type": "roundrobin",
    "nodes": {
        "oauth-service:8006": 1
    },
    "timeout": {
        "connect": 15,
        "send": 15,
        "read": 15
    },
    "scheme": "http",
    "retry_timeout": 0,
    "retries": 2
}'

create_upstream 'access-service-upstream' '{
    "type": "roundrobin",
    "nodes": {
        "access-service:8007": 1
    },
    "timeout": {
        "connect": 15,
        "send": 300,
        "read": 300
    },
    "scheme": "http",
    "retry_timeout": 0,
    "retries": 2
}'

echo

# ============================================================================
# Create Services (with plugins)
# ============================================================================

log "Creating service definitions..."

create_service 'identity-service-svc' '{
    "upstream_id": "identity-service-upstream",
    "plugins": {
        "limit-req": {
            "rate": 100,
            "burst": 50,
            "key": "remote_addr",
            "rejected_code": 429
        },
        "cors": {
            "allow_origins": "https://'$DOMAIN'",
            "allow_methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Requested-With,Accept,Origin",
            "expose_headers": "Content-Length,Content-Range",
            "max_age": 3600,
            "allow_credential": true
        },
        "prometheus": {
            "prefer_name": true
        }
    }
}'

create_service 'governance-service-svc' '{
    "upstream_id": "governance-service-upstream",
    "plugins": {
        "limit-req": {
            "rate": 50,
            "burst": 25,
            "key": "remote_addr",
            "rejected_code": 429
        },
        "cors": {
            "allow_origins": "https://'$DOMAIN'",
            "allow_methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Requested-With,Accept,Origin",
            "max_age": 3600,
            "allow_credential": true
        },
        "prometheus": {
            "prefer_name": true
        }
    }
}'

create_service 'provisioning-service-svc' '{
    "upstream_id": "provisioning-service-upstream",
    "plugins": {
        "limit-req": {
            "rate": 30,
            "burst": 15,
            "key": "remote_addr",
            "rejected_code": 429
        },
        "cors": {
            "allow_origins": "https://'$DOMAIN'",
            "allow_methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Requested-With,Accept,Origin",
            "max_age": 3600,
            "allow_credential": true
        },
        "prometheus": {
            "prefer_name": true
        }
    }
}'

create_service 'audit-service-svc' '{
    "upstream_id": "audit-service-upstream",
    "plugins": {
        "limit-req": {
            "rate": 200,
            "burst": 100,
            "key": "remote_addr",
            "rejected_code": 429
        },
        "cors": {
            "allow_origins": "https://'$DOMAIN'",
            "allow_methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Requested-With,Accept,Origin",
            "max_age": 3600,
            "allow_credential": true
        },
        "prometheus": {
            "prefer_name": true
        }
    }
}'

create_service 'admin-api-svc' '{
    "upstream_id": "admin-api-upstream",
    "plugins": {
        "limit-req": {
            "rate": 50,
            "burst": 25,
            "key": "remote_addr",
            "rejected_code": 429
        },
        "cors": {
            "allow_origins": "https://'$DOMAIN'",
            "allow_methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Requested-With,Accept,Origin",
            "max_age": 3600,
            "allow_credential": true
        },
        "prometheus": {
            "prefer_name": true
        }
    }
}'

create_service 'oauth-service-svc' '{
    "upstream_id": "oauth-service-upstream",
    "plugins": {
        "limit-req": {
            "rate": 100,
            "burst": 50,
            "key": "remote_addr",
            "rejected_code": 429
        },
        "cors": {
            "allow_origins": "https://'$DOMAIN'",
            "allow_methods": "GET,POST,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Requested-With,Accept,Origin",
            "max_age": 3600,
            "allow_credential": true
        },
        "prometheus": {
            "prefer_name": true
        }
    }
}'

create_service 'access-service-svc' '{
    "upstream_id": "access-service-upstream",
    "plugins": {
        "limit-req": {
            "rate": 100,
            "burst": 50,
            "key": "remote_addr",
            "rejected_code": 429
        },
        "cors": {
            "allow_origins": "https://'$DOMAIN'",
            "allow_methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Requested-With,X-Forwarded-Host,X-Forwarded-Uri,X-Forwarded-Method,X-Forwarded-For,Cookie",
            "max_age": 3600,
            "allow_credential": true
        },
        "prometheus": {
            "prefer_name": true
        }
    }
}'

echo

# ============================================================================
# Create Routes
# ============================================================================

log "Creating API routes..."

# 1. CORS preflight route (catch-all for OPTIONS)
create_route 'cors-preflight' '{
    "uri": "/.*",
    "name": "cors-preflight",
    "methods": ["OPTIONS"],
    "priority": 1000,
    "plugins": {
        "cors": {
            "allow_origins": "https://'$DOMAIN'",
            "allow_methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Requested-With,Accept,Origin",
            "max_age": 86400
        }
    },
    "upstream_id": "admin-api-upstream"
}'

# 2. Identity service routes
create_route 'identity-service-users' '{
    "uris": ["/api/v1/identity/users", "/api/v1/identity/users/*"],
    "name": "identity-service-users",
    "methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
    "priority": 10,
    "service_id": "identity-service-svc"
}'

create_route 'identity-service-sessions' '{
    "uris": ["/api/v1/identity/sessions", "/api/v1/identity/sessions/*"],
    "name": "identity-service-sessions",
    "methods": ["GET", "POST", "DELETE"],
    "priority": 10,
    "service_id": "identity-service-svc"
}'

create_route 'identity-service-mfa' '{
    "uris": ["/api/v1/identity/mfa/*"],
    "name": "identity-service-mfa",
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "priority": 10,
    "service_id": "identity-service-svc"
}'

# 3. Governance service routes
create_route 'governance-service-reviews' '{
    "uris": ["/api/v1/governance/reviews", "/api/v1/governance/reviews/*"],
    "name": "governance-service-reviews",
    "methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
    "priority": 10,
    "service_id": "governance-service-svc"
}'

create_route 'governance-service-policies' '{
    "uris": ["/api/v1/governance/policies", "/api/v1/governance/policies/*"],
    "name": "governance-service-policies",
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "priority": 10,
    "service_id": "governance-service-svc"
}'

# 4. Provisioning service routes (SCIM)
create_route 'provisioning-service-scim-users' '{
    "uris": ["/scim/v2/Users", "/scim/v2/Users/*"],
    "name": "provisioning-service-scim-users",
    "methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
    "priority": 10,
    "service_id": "provisioning-service-svc"
}'

create_route 'provisioning-service-scim-groups' '{
    "uris": ["/scim/v2/Groups", "/scim/v2/Groups/*"],
    "name": "provisioning-service-scim-groups",
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "priority": 10,
    "service_id": "provisioning-service-svc"
}'

create_route 'provisioning-service-scim-schemas' '{
    "uris": ["/scim/v2/Schemas", "/scim/v2/Schemas/*", "/scim/v2/ResourceTypes", "/scim/v2/ServiceProviderConfig"],
    "name": "provisioning-service-scim-discovery",
    "methods": ["GET"],
    "priority": 10,
    "service_id": "provisioning-service-svc"
}'

# 5. Audit service routes
create_route 'audit-service-events' '{
    "uris": ["/api/v1/audit/events", "/api/v1/audit/events/*"],
    "name": "audit-service-events",
    "methods": ["GET", "POST"],
    "priority": 10,
    "service_id": "audit-service-svc"
}'

create_route 'audit-service-reports' '{
    "uris": ["/api/v1/audit/reports", "/api/v1/audit/reports/*"],
    "name": "audit-service-reports",
    "methods": ["GET", "POST"],
    "priority": 10,
    "service_id": "audit-service-svc"
}'

create_route 'audit-service-statistics' '{
    "uris": ["/api/v1/audit/statistics"],
    "name": "audit-service-statistics",
    "methods": ["GET"],
    "priority": 10,
    "service_id": "audit-service-svc"
}'

# 6. OAuth/OIDC service routes
create_route 'oauth-service-authorize' '{
    "uris": ["/oauth/authorize"],
    "name": "oauth-service-authorize",
    "methods": ["GET", "POST"],
    "priority": 10,
    "service_id": "oauth-service-svc"
}'

create_route 'oauth-service-token' '{
    "uris": ["/oauth/token"],
    "name": "oauth-service-token",
    "methods": ["POST"],
    "priority": 10,
    "service_id": "oauth-service-svc"
}'

create_route 'oauth-service-introspect' '{
    "uris": ["/oauth/introspect", "/oauth/revoke"],
    "name": "oauth-service-introspect",
    "methods": ["POST"],
    "priority": 10,
    "service_id": "oauth-service-svc"
}'

create_route 'oauth-service-userinfo' '{
    "uris": ["/oauth/userinfo"],
    "name": "oauth-service-userinfo",
    "methods": ["GET"],
    "priority": 10,
    "service_id": "oauth-service-svc"
}'

# 7. OIDC discovery endpoints
create_route 'oidc-discovery' '{
    "uris": ["/.well-known/*"],
    "name": "oidc-discovery",
    "methods": ["GET"],
    "priority": 5,
    "service_id": "oauth-service-svc"
}'

# 8. Access service routes
create_route 'access-service-api' '{
    "uris": ["/api/v1/access/*"],
    "name": "access-service-api",
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "priority": 10,
    "service_id": "access-service-svc"
}'

create_route 'access-service-auth-flow' '{
    "uris": ["/access/.auth/*"],
    "name": "access-service-auth-flow",
    "methods": ["GET", "POST"],
    "priority": 10,
    "service_id": "access-service-svc"
}'

create_route 'access-service-proxy' '{
    "uris": ["/access/proxy/*"],
    "name": "access-service-proxy",
    "methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "CONNECT"],
    "priority": 10,
    "service_id": "access-service-svc",
    "plugins": {
        "proxy-rewrite": {
            "regex_uri": ["^/access/proxy/(.*)", "/$1"]
        }
    }
}'

# 9. Admin API routes (dashboard, settings, applications)
create_route 'admin-api-dashboard' '{
    "uris": ["/api/v1/dashboard", "/api/v1/dashboard/*"],
    "name": "admin-api-dashboard",
    "methods": ["GET", "POST"],
    "priority": 10,
    "service_id": "admin-api-svc"
}'

create_route 'admin-api-settings' '{
    "uris": ["/api/v1/settings"],
    "name": "admin-api-settings",
    "methods": ["GET", "PUT"],
    "priority": 10,
    "service_id": "admin-api-svc"
}'

create_route 'admin-api-applications' '{
    "uris": ["/api/v1/applications", "/api/v1/applications/*"],
    "name": "admin-api-applications",
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "priority": 10,
    "service_id": "admin-api-svc"
}'

create_route 'admin-api-users' '{
    "uris": ["/api/v1/users", "/api/v1/users/*"],
    "name": "admin-api-users",
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "priority": 10,
    "service_id": "admin-api-svc"
}'

echo

# ============================================================================
# Health Check Routes (no auth required)
# ============================================================================

log "Creating health check routes..."

create_route 'health-identity' '{
    "uris": ["/api/v1/identity/health"],
    "name": "health-identity",
    "methods": ["GET"],
    "priority": 1,
    "upstream_id": "identity-service-upstream",
    "plugins": {}
}'

create_route 'health-governance' '{
    "uris": ["/api/v1/governance/health"],
    "name": "health-governance",
    "methods": ["GET"],
    "priority": 1,
    "upstream_id": "governance-service-upstream",
    "plugins": {}
}'

create_route 'health-provisioning' '{
    "uris": ["/api/v1/provisioning/health"],
    "name": "health-provisioning",
    "methods": ["GET"],
    "priority": 1,
    "upstream_id": "provisioning-service-upstream",
    "plugins": {}
}'

create_route 'health-audit' '{
    "uris": ["/api/v1/audit/health"],
    "name": "health-audit",
    "methods": ["GET"],
    "priority": 1,
    "upstream_id": "audit-service-upstream",
    "plugins": {}
}'

create_route 'health-admin' '{
    "uris": ["/api/v1/admin/health"],
    "name": "health-admin",
    "methods": ["GET"],
    "priority": 1,
    "upstream_id": "admin-api-upstream",
    "plugins": {}
}'

create_route 'health-oauth' '{
    "uris": ["/oauth/health"],
    "name": "health-oauth",
    "methods": ["GET"],
    "priority": 1,
    "upstream_id": "oauth-service-upstream",
    "plugins": {}
}'

create_route 'health-access' '{
    "uris": ["/api/v1/access/health"],
    "name": "health-access",
    "methods": ["GET"],
    "priority": 1,
    "upstream_id": "access-service-upstream",
    "plugins": {}
}'

echo
log "========================================"
log "Route Loading Complete!"
log "========================================"

# Verify routes
echo
log "Verifying routes..."
total_routes=$(curl -s "$ADMIN_API_URL/apisix/admin/routes" -H "X-API-KEY: $ADMIN_KEY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('total', 0))" 2>/dev/null || echo "unknown")
log "Total routes in APISIX: ${YELLOW}${total_routes}${NC}"

# Test a few routes
echo
log "Testing routes..."

test_route() {
    local name="$1"
    local path="$2"
    local expected="$3"

    echo -n "  $name: "
    status=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8088$path")
    if [ "$status" = "$expected" ] || [ "$status" = "401" ] || [ "$status" = "403" ]; then
        echo -e "${GREEN}OK (status: $status)${NC}"
    else
        echo -e "${RED}FAILED (status: $status, expected: $expected)${NC}"
    fi
}

test_route "Identity Service" "/api/v1/identity/health" "200"
test_route "OAuth Service" "/oauth/health" "200"
test_route "Admin API" "/api/v1/admin/health" "200"
test_route "OIDC Discovery" "/.well-known/openid-configuration" "200"

echo
log -e "${GREEN}Production routes loaded successfully!${NC}"
log "API Gateway is accessible at: https://$DOMAIN"
