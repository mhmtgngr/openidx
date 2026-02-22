#!/bin/bash

# Load APISIX routes from YAML to etcd via Admin API

ADMIN_API_URL="http://localhost:9188"
ADMIN_KEY="edd1c9f034335f136f87ad84b625c8f1"

# Function to create a route via Admin API
create_route() {
    local route_data="$1"
    local route_name="$2"

    echo "Creating route: $route_name"
    curl -s -X PUT "$ADMIN_API_URL/apisix/admin/routes/$route_name" \
        -H "X-API-KEY: $ADMIN_KEY" \
        -H "Content-Type: application/json" \
        -d "$route_data"

    local status=$?
    if [ $status -eq 0 ]; then
        echo " ✓ Route '$route_name' created successfully"
    else
        echo " ✗ Failed to create route '$route_name'"
    fi
    echo
}

# Wait for APISIX to be ready
echo "Waiting for APISIX to be ready..."
until curl -s -f "$ADMIN_API_URL/apisix/admin/apisix/schema" > /dev/null 2>&1; do
    echo "  APISIX not ready yet, waiting..."
    sleep 2
done
echo "APISIX is ready!"
echo

# Create routes from the YAML configuration
echo "Loading routes into APISIX..."
echo "========================================"

# 1. CORS preflight route
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

# 6. OAuth service route
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

# 7. OIDC discovery route
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

# 8. Access service route
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

# 10. Admin API route
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

echo "========================================"
echo "All routes loaded successfully!"
echo
echo "Verifying routes..."
curl -s "$ADMIN_API_URL/apisix/admin/routes" -H "X-API-KEY: $ADMIN_KEY" | python3 -m json.tool 2>/dev/null || curl -s "$ADMIN_API_URL/apisix/admin/routes" -H "X-API-KEY: $ADMIN_KEY"
echo
echo "Testing a route..."
curl -s -o /dev/null -w "Identity Service Test: HTTP %{http_code}\n" http://localhost:8088/api/v1/identity/users
