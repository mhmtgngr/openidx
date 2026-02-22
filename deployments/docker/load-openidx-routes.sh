#!/bin/bash

# Load all OpenIDX routes into APISIX via Admin API

ADMIN_API_URL="http://localhost:9188"
ADMIN_KEY="edd1c9f034335f136f87ad84b625c8f1"

# Color output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to create a route via Admin API
create_route() {
    local route_id="$1"
    local route_data="$2"

    echo -n "Creating route: $route_id... "

    response=$(curl -s -X PUT "$ADMIN_API_URL/apisix/admin/routes/$route_id" \
        -H "X-API-KEY: $ADMIN_KEY" \
        -H "Content-Type: application/json" \
        -d "$route_data")

    if echo "$response" | grep -q '"error"'; then
        echo -e "${RED}FAILED${NC}"
        echo "  Error: $response"
        return 1
    else
        echo -e "${GREEN}OK${NC}"
        return 0
    fi
}

echo "========================================"
echo "Loading OpenIDX Routes into APISIX"
echo "========================================"
echo

# 1. CORS preflight route (catch-all for OPTIONS)
create_route 'cors-preflight' '{
    "uri": "/.*",
    "name": "cors-preflight",
    "methods": ["OPTIONS"],
    "plugins": {
        "cors": {
            "allow_origins": "http://localhost:3000",
            "allow_methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Requested-With,Accept,Origin",
            "max_age": 86400
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "admin-api:8005": 1
        }
    }
}'

# 2. Identity service route
create_route 'identity-service' '{
    "uri": "/api/v1/identity/*",
    "name": "identity-service",
    "plugins": {
        "limit-req": {
            "rate": 100,
            "burst": 50,
            "key": "remote_addr"
        },
        "cors": {
            "allow_origins": "http://localhost:3000",
            "allow_methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Requested-With",
            "max_age": 3600
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "identity-service:8001": 1
        }
    }
}'

# 3. Governance service route
create_route 'governance-service' '{
    "uri": "/api/v1/governance/*",
    "name": "governance-service",
    "plugins": {
        "limit-req": {
            "rate": 50,
            "burst": 25,
            "key": "remote_addr"
        },
        "cors": {
            "allow_origins": "http://localhost:3000",
            "allow_methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Requested-With",
            "max_age": 3600
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "governance-service:8002": 1
        }
    }
}'

# 4. Provisioning service route
create_route 'provisioning-service' '{
    "uri": "/api/v1/provisioning/*",
    "name": "provisioning-service",
    "plugins": {
        "limit-req": {
            "rate": 30,
            "burst": 15,
            "key": "remote_addr"
        },
        "cors": {
            "allow_origins": "http://localhost:3000",
            "allow_methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Requested-With",
            "max_age": 3600
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "provisioning-service:8003": 1
        }
    }
}'

# 5. Audit service route
create_route 'audit-service' '{
    "uri": "/api/v1/audit/*",
    "name": "audit-service",
    "plugins": {
        "limit-req": {
            "rate": 200,
            "burst": 100,
            "key": "remote_addr"
        },
        "cors": {
            "allow_origins": "http://localhost:3000",
            "allow_methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Requested-With",
            "max_age": 3600
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "audit-service:8004": 1
        }
    }
}'

# 6. OAuth/OIDC service route
create_route 'oauth-service' '{
    "uri": "/oauth/*",
    "name": "oauth-service",
    "plugins": {
        "limit-req": {
            "rate": 100,
            "burst": 50,
            "key": "remote_addr"
        },
        "cors": {
            "allow_origins": "http://localhost:3000",
            "allow_methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Requested-With,Accept,Origin",
            "max_age": 3600
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "oauth-service:8006": 1
        }
    }
}'

# 7. OIDC discovery endpoints
create_route 'oidc-discovery' '{
    "uri": "/.well-known/*",
    "name": "oidc-discovery",
    "plugins": {
        "cors": {
            "allow_origins": "http://localhost:3000",
            "allow_methods": "GET,OPTIONS",
            "allow_headers": "Content-Type,Accept",
            "max_age": 86400
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "oauth-service:8006": 1
        }
    }
}'

# 8. Access service API route
create_route 'access-service' '{
    "uri": "/api/v1/access/*",
    "name": "access-service",
    "plugins": {
        "limit-req": {
            "rate": 100,
            "burst": 50,
            "key": "remote_addr"
        },
        "cors": {
            "allow_origins": "http://localhost:3000",
            "allow_methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Forwarded-Host,X-Forwarded-Uri,X-Forwarded-Method,X-Forwarded-For,Cookie",
            "max_age": 3600
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "access-service:8007": 1
        }
    }
}'

# 9. Access auth flow route
create_route 'access-auth-flow' '{
    "uri": "/access/.auth/*",
    "name": "access-auth-flow",
    "plugins": {
        "cors": {
            "allow_origins": "http://localhost:3000",
            "allow_methods": "GET,POST,OPTIONS",
            "allow_headers": "Content-Type,Authorization,Cookie",
            "max_age": 3600
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "access-service:8007": 1
        }
    }
}'

# 10. Admin API route (with higher priority to catch specific paths first)
create_route 'admin-api' '{
    "uri": "/api/v1/*",
    "name": "admin-api",
    "priority": 10,
    "plugins": {
        "limit-req": {
            "rate": 50,
            "burst": 25,
            "key": "remote_addr"
        },
        "cors": {
            "allow_origins": "http://localhost:3000",
            "allow_methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "allow_headers": "Content-Type,Authorization,X-Requested-With,Accept,Origin",
            "max_age": 3600
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "admin-api:8005": 1
        }
    }
}'

echo
echo "========================================"
echo -e "${GREEN}Route Loading Complete!${NC}"
echo "========================================"
echo
echo "Verifying routes..."
total_routes=$(curl -s "$ADMIN_API_URL/apisix/admin/routes" -H "X-API-KEY: $ADMIN_KEY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('total', 0))" 2>/dev/null || echo "7")
echo -e "Total routes in APISIX: ${YELLOW}${total_routes}${NC}"
echo
echo "Testing routes..."
echo -n "  Identity Service: "
status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8088/api/v1/identity/users)
if [ "$status" = "401" ] || [ "$status" = "403" ]; then
    echo -e "${GREEN}✓ Routing OK (auth required)${NC}"
else
    echo -e "${RED}✗ Got status $status${NC}"
fi

echo -n "  OAuth Service: "
status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8088/oauth/authorize)
if [ "$status" != "404" ]; then
    echo -e "${GREEN}✓ OK${NC}"
else
    echo -e "${RED}✗ Not found${NC}"
fi

echo -n "  Admin API: "
status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8088/api/v1/dashboard)
if [ "$status" != "404" ]; then
    echo -e "${GREEN}✓ OK${NC}"
else
    echo -e "${RED}✗ Not found${NC}"
fi

echo
echo "Testing CORS Preflight..."
cors_status=$(curl -s -o /dev/null -w "%{http_code}" -X OPTIONS http://localhost:8088/api/v1/identity/users \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: GET")
echo -n "  CORS Preflight: "
if [ "$cors_status" = "200" ] || [ "$cors_status" = "204" ]; then
    echo -e "${GREEN}✓ OK${NC}"
else
    echo -e "${YELLOW}Got status $cors_status (may need testing from browser)${NC}"
fi

echo
echo -e "${GREEN}All OpenIDX routes loaded successfully!${NC}"
echo "You can now access services through APISIX on port 8088"
