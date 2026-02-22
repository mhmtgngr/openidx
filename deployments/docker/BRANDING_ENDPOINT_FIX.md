# Branding Endpoint 404 Issue - Resolution

## Problem
The frontend was getting a 404 error when accessing:
```
GET /api/v1/identity/branding?domain=openidx.tdv.org
```

This caused the error:
```
TypeError: Cannot read properties of undefined (reading 'digest')
```

## Root Cause Analysis

### 1. **Missing Database Table**
The `tenant_branding` table didn't exist in the database. The branding feature was added in Phase 17 but the migration wasn't included in the standard migration files.

**Evidence:**
```sql
ERROR: relation "tenant_branding" does not exist
```

### 2. **Container Using Cached Image**
The identity service was running a cached image from 4 hours ago, before the branding feature was fully implemented.

## Solution Applied

### 1. **Created Migration Script**
File: `/home/cmit/openidx/deployments/docker/010_add_tenant_branding.sql`

```sql
CREATE TABLE IF NOT EXISTS tenant_branding (
    org_id UUID PRIMARY KEY,
    logo_url TEXT,
    favicon_url TEXT,
    primary_color VARCHAR(7) DEFAULT '#1e40af',
    secondary_color VARCHAR(7) DEFAULT '#3b82f6',
    background_color VARCHAR(7) DEFAULT '#f8fafc',
    background_image_url TEXT,
    login_page_title VARCHAR(255) DEFAULT 'Sign In',
    login_page_message TEXT,
    portal_title VARCHAR(255) DEFAULT 'OpenIDX Portal',
    custom_css TEXT,
    custom_footer TEXT,
    powered_by_visible BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### 2. **Executed Migration**
```bash
podman exec -i openidx-postgres psql -U openidx -d openidx < 010_add_tenant_branding.sql
```

### 3. **Rebuilding Identity Service**
```bash
cd /home/cmit/openidx/deployments/docker
podman-compose build --no-cache identity-service
podman-compose up -d --force-recreate identity-service
```

## Expected Result

After the rebuild completes, the branding endpoint should return the default branding configuration:

```json
{
  "logo_url": "",
  "favicon_url": "",
  "primary_color": "#1e40af",
  "secondary_color": "#3b82f6",
  "background_color": "#f8fafc",
  "background_image_url": "",
  "login_page_title": "Sign In",
  "login_page_message": "",
  "portal_title": "OpenIDX Portal",
  "custom_css": "",
  "custom_footer": "",
  "powered_by_visible": true
}
```

## Route Information

The branding endpoint is registered as a **public route** (no authentication required):

```go
// File: internal/identity/service.go:2670
public := router.Group("/api/v1/identity")
{
    public.GET("/branding", svc.handleGetLoginBranding)
    // ... other public routes
}
```

## Testing

Once the rebuild completes, test with:

```bash
# Direct to service
curl "http://localhost:8001/api/v1/identity/branding?domain=openidx.tdv.org"

# Through APISIX
curl "http://localhost:8088/api/v1/identity/branding?domain=openidx.tdv.org"
```

## Related Files

- Migration: `/home/cmit/openidx/deployments/docker/010_add_tenant_branding.sql`
- Handler: `/home/cmit/openidx/internal/identity/handlers_tenant.go`
- Service: `/home/cmit/openidx/internal/identity/service.go`
- Main: `/home/cmit/openidx/cmd/identity-service/main.go`
