#!/bin/bash

# Update OpenIDX routes to include correct CORS origins

ADMIN_API_URL="http://localhost:9188"
ADMIN_KEY="edd1c9f034335f136f87ad84b625c8f1"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================"
echo "Updating CORS Origins in APISIX Routes"
echo "========================================"
echo
echo "Adding origin: http://openidx.tdv.org:3000"
echo "Adding origin: https://openidx.tdv.org"
echo "Adding origin: http://openidx.tdv.org"
echo

# Function to update route CORS configuration
update_route_cors() {
    local route_id="$1"
    local route_name="$2"
    local allow_origins="$3"

    echo -n "Updating $route_name... "

    # Get current route
    current_route=$(curl -s "$ADMIN_API_URL/apisix/admin/routes/$route_id" -H "X-API-KEY: $ADMIN_KEY")

    if echo "$current_route" | grep -q '"error"'; then
        echo -e "${YELLOW}SKIPPED (not found)${NC}"
        return
    fi

    # Update with new CORS config
    response=$(curl -s -X PATCH "$ADMIN_API_URL/apisix/admin/routes/$route_id" \
        -H "X-API-KEY: $ADMIN_KEY" \
        -H "Content-Type: application/json" \
        -d "{
            \"plugins\": {
                \"cors\": {
                    \"allow_origins\": \"$allow_origins\",
                    \"allow_methods\": \"GET,POST,PUT,DELETE,PATCH,OPTIONS\",
                    \"allow_headers\": \"Content-Type,Authorization,X-Requested-With,Accept,Origin\",
                    \"max_age\": 3600,
                    \"expose_headers\": \"*\"
                }
            }
        }")

    if echo "$response" | grep -q '"error"'; then
        echo -e "${YELLOW}WARNING${NC}"
        echo "  $response"
    else
        echo -e "${GREEN}OK${NC}"
    fi
}

# Update all OpenIDX routes with expanded CORS origins
CORS_ORIGINS="http://localhost:3000,http://openidx.tdv.org:3000,https://openidx.tdv.org,http://openidx.tdv.org"

update_route_cors "cors-preflight" "CORS Preflight" "$CORS_ORIGINS"
update_route_cors "identity-service" "Identity Service" "$CORS_ORIGINS"
update_route_cors "governance-service" "Governance Service" "$CORS_ORIGINS"
update_route_cors "provisioning-service" "Provisioning Service" "$CORS_ORIGINS"
update_route_cors "audit-service" "Audit Service" "$CORS_ORIGINS"
update_route_cors "oauth-service" "OAuth Service" "$CORS_ORIGINS"
update_route_cors "oidc-discovery" "OIDC Discovery" "$CORS_ORIGINS"
update_route_cors "access-service" "Access Service" "$CORS_ORIGINS"
update_route_cors "access-auth-flow" "Access Auth Flow" "$CORS_ORIGINS"
update_route_cors "admin-api" "Admin API" "$CORS_ORIGINS"

echo
echo "========================================"
echo -e "${GREEN}CORS Origins Updated!${NC}"
echo "========================================"
echo
echo "Testing CORS with new origins..."
echo

# Test CORS preflight with the new origin
echo -n "Testing OPTIONS request from openidx.tdv.org:3000... "
cors_response=$(curl -s -i -X OPTIONS "http://localhost:8088/api/v1/identity/providers" \
  -H "Origin: http://openidx.tdv.org:3000" \
  -H "Access-Control-Request-Method: GET")

if echo "$cors_response" | grep -q "Access-Control-Allow-Origin: http://openidx.tdv.org:3000"; then
    echo -e "${GREEN}✓ PASS${NC}"
else
    echo -e "${YELLOW}Check manually${NC}"
fi

echo
echo "CORS configuration now includes:"
echo "  - http://localhost:3000"
echo "  - http://openidx.tdv.org:3000"
echo "  - https://openidx.tdv.org"
echo "  - http://openidx.tdv.org"
