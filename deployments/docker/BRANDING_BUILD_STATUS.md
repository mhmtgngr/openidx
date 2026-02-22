# Branding Endpoint - Current Status

## Issue Summary

The frontend is getting a 404 error when accessing:
```
GET /api/v1/identity/branding?domain=openidx.tdv.org
```

This causes:
```
TypeError: Cannot read properties of undefined (reading 'digest')
```

## What Has Been Done

1. ✅ **Database table created** - `tenant_branding` table exists in PostgreSQL
2. ✅ **Default branding data added** - Inserted default branding for org_id 00000000-0000-0000-0000-000000000000
3. ✅ **Branding handler exists** - `handleGetLoginBranding` function exists in `internal/identity/handlers_tenant.go`
4. ✅ **Route is registered** - Line 2670 in `internal/identity/service.go` registers the route

## Current Problem

The identity service container is running an **old cached image** from before the branding feature was added. Attempting to rebuild fails due to compilation errors.

### Build Errors

The identity service has conflicting model definitions:

1. **`internal/identity/models.go`** - New SCIM-compatible models with:
   - `User` struct with `UserName` (not `Username`)
   - `Group` struct with `DisplayName`
   - Nested structures like `Name`, `Emails`, etc.

2. **`internal/identity/service.go`** - Old duplicate definitions with:
   - `User` struct with `Username`, `Email`, `FirstName`, `LastName`
   - `Group` struct with `Name`, `Description`
   - Flat field structure

3. **Code throughout the codebase** references the old field names:
   - `user.Username` (should be `user.UserName`)
   - `user.Email` (should be from `user.Emails[0].Value`)
   - `user.FirstName` (should be from `user.Name.GivenName`)
   - etc.

### Compilation Errors When Building

```
internal/identity/service.go:62:6: User redeclared in this block
	internal/identity/models.go:11:6: other declaration of User
internal/identity/service.go:150:6: Group redeclared in this block
	internal/identity/models.go:107:6: other declaration of Group
internal/identity/service.go:536:19: user.Username undefined
	(type User has no field or method Username, but does have field UserName)
internal/identity/service.go:536:35: user.Email undefined
	(type User has no field or method Email)
...and many more throughout the codebase
```

## Solutions

### Option 1: Fix the Build (Recommended but Time-Consuming)

1. Remove duplicate `User` and `Group` structs from `internal/identity/service.go`
2. Update all references throughout the codebase to use SCIM-compatible field names
3. Add helper methods to maintain backward compatibility
4. Rebuild the identity service

**Estimated effort**: 2-4 hours of refactoring

### Option 2: Use Existing Container with Direct Database Workaround (Quick Fix)

Since the branding endpoint is simple (just reads from `tenant_branding` table), we could:

1. Create a simple standalone service that provides just the branding endpoint
2. Or temporarily add branding data to the frontend config
3. Or use a proxy that returns the branding data

**Estimated effort**: 30 minutes

### Option 3: Revert to Working Commit (Fastest)

Find the last commit where the build worked and use that for the identity service:

```bash
git log --oneline --all | grep -i "branding\|tenant" | head -10
```

Then rebuild from that commit.

**Estimated effort**: 15 minutes

## Recommended Path Forward

1. **Immediate**: Use Option 2 or 3 to get the branding working quickly
2. **Short-term**: Fix the SCIM model migration properly (Option 1)
3. **Long-term**: Ensure builds don't break when adding new features

## Testing Branding Endpoint

Once the service is running with the branding code:

```bash
# Direct to service
curl "http://localhost:8001/api/v1/identity/branding?domain=openidx.tdv.org"

# Through APISIX
curl "http://localhost:8088/api/v1/identity/branding?domain=openidx.tdv.org"
```

Expected response:
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

## Files Involved

- `internal/identity/models.go` - SCIM-compatible models (NEW)
- `internal/identity/service.go` - Old duplicate models + business logic
- `internal/identity/handlers_tenant.go` - Branding handler (EXISTS)
- `internal/identity/repository.go` - Database queries
- `deployments/docker/010_add_tenant_branding.sql` - Database migration (DONE)
