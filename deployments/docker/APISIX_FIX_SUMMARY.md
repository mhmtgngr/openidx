# APISIX Configuration Fix Summary

## Issues Identified and Resolved

### 1. **"Missing Valid End Flag" Errors**
- **Problem**: APISIX was generating thousands of warnings about malformed YAML config
- **Root Cause**: Config file had incorrect `role: traditional` with unsupported `config_provider: yaml`
- **Solution**: Changed to `config_provider: etcd` which is supported in APISIX 3.8.0

### 2. **"Wait for More Time" Log Spam**
- **Problem**: 4.2MB+ of repetitive log entries
- **Root Cause**: APISIX's YAML config watcher was continuously retrying to read an incompatible configuration
- **Solution**: Fixed configuration provider issue

### 3. **Admin API 403 Forbidden**
- **Problem**: Admin API was inaccessible from host machine
- **Root Cause**: IP whitelist in nginx.conf only allowed `127.0.0.0/24` (localhost within container)
- **Solution**: Created wrapper script (`apisix-wrapper.sh`) that patches nginx.conf to allow Podman networks

### 4. **Routes Not Loading (404 Errors)**
- **Problem**: All OpenIDX routes returned 404
- **Root Cause**: Routes defined in YAML file but APISIX in etcd mode doesn't read YAML routes
- **Solution**: Created script (`load-openidx-routes.sh`) to load routes via Admin API

### 5. **CORS Policy Blocking Frontend**
- **Problem**: Frontend at `http://openidx.tdv.org:3000` blocked by CORS
- **Root Cause**: Routes only configured for `http://localhost:3000`
- **Solution**: Updated all routes to include additional origins

## Files Modified

### 1. `/home/cmit/openidx/deployments/docker/apisix/config.yaml`
- Changed `role: traditional` with `yaml` provider → `role: traditional` with `etcd` provider
- Added `enable_admin: true`
- Added `admin_key` configuration
- Added `etcd` configuration

### 2. `/home/cmit/openidx/deployments/docker/apisix-wrapper.sh` (NEW)
- Wrapper script that patches nginx.conf after APISIX generates it
- Adds IP allow rules for Podman networks:
  - `allow 10.0.0.0/8;` (Podman default)
  - `allow 172.16.0.0/12;` (Docker default)
  - `allow 192.168.0.0/16;` (Private networks)
- Reloads nginx to apply changes

### 3. `/home/cmit/openidx/deployments/docker/docker-compose.yml`
- Updated APISIX service to use `apisix-wrapper.sh` as entrypoint
- Mounted wrapper script into container

### 4. `/home/cmit/openidx/deployments/docker/apisix/apisix.yaml`
- Updated `allow_origins` from single origin to multiple:
  - `http://localhost:3000`
  - `http://openidx.tdv.org:3000`
  - `https://openidx.tdv.org`
  - `http://openidx.tdv.org`

### 5. `/home/cmit/openidx/deployments/docker/load-openidx-routes.sh` (NEW)
- Script to load all OpenIDX routes via Admin API
- Creates 10 routes with proper CORS and rate limiting configuration

### 6. `/home/cmit/openidx/deployments/docker/update-cors-origins.sh` (NEW)
- Script to update CORS origins in existing routes
- Patches routes to include additional allowed origins

## Routes Loaded

1. **cors-preflight** - `.*` (OPTIONS method only)
2. **identity-service** - `/api/v1/identity/*`
3. **governance-service** - `/api/v1/governance/*`
4. **provisioning-service** - `/api/v1/provisioning/*`
5. **audit-service** - `/api/v1/audit/*`
6. **oauth-service** - `/oauth/*`
7. **oidc-discovery** - `/.well-known/*`
8. **access-service** - `/api/v1/access/*`
9. **access-auth-flow** - `/access/.auth/*`
10. **admin-api** - `/api/v1/*` (priority 10)

## CORS Configuration

All routes now include CORS headers allowing:
- **Origins**: `http://localhost:3000`, `http://openidx.tdv.org:3000`, `https://openidx.tdv.org`, `http://openidx.tdv.org`
- **Methods**: GET, POST, PUT, DELETE, PATCH, OPTIONS
- **Headers**: Content-Type, Authorization, X-Requested-With, Accept, Origin
- **Max Age**: 3600 seconds (1 hour)
- **Expose Headers**: * (all headers)

## Verification

```bash
# Check APISIX is healthy
curl http://localhost:8088/api/v1/identity/users

# Test CORS preflight
curl -X OPTIONS http://localhost:8088/api/v1/identity/providers \
  -H "Origin: http://openidx.tdv.org:3000" \
  -H "Access-Control-Request-Method: GET"

# List all routes
curl http://localhost:9188/apisix/admin/routes \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1"
```

## Persistent Configuration

To ensure routes persist across container restarts:

1. Routes are stored in **etcd** (not the YAML file)
2. The `apisix.yaml` file is used for reference but not auto-loaded
3. To reload routes after a full restart:
   ```bash
   /home/cmit/openidx/deployments/docker/load-openidx-routes.sh
   ```

## Architecture

```
Frontend (http://openidx.tdv.org:3000)
         ↓
    APISIX Gateway (port 8088)
         ↓
    Services (8001-8007)
         - identity-service:8001
         - governance-service:8002
         - provisioning-service:8003
         - audit-service:8004
         - admin-api:8005
         - oauth-service:8006
         - access-service:8007
```

## Next Steps for Production

1. **Add HTTPS/SSL** - Configure SSL certificates for production domains
2. **Rate Limiting** - Adjust rate limits based on traffic patterns
3. **Authentication** - Ensure all services have proper auth middleware
4. **Monitoring** - Set up Prometheus metrics (already exposed on port 9091)
5. **Log Aggregation** - Configure centralized logging
