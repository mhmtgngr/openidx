# Identity Service Build Fix - Implementation Guide

## Current Status

❌ **Build Status**: FAILED
❌ **Branding Endpoint**: 404 Error
✅ **Database Table**: Created
✅ **Handler Code**: Exists
✅ **Route Registration**: Exists

## Root Cause

The identity service cannot build due to **duplicate type definitions**:

```
internal/identity/models.go:11:6: type User declared (SCIM-compatible)
internal/identity/service.go:62:6: type User declared (legacy flat structure)
ERROR: User redeclared in this block
```

## Why This Exists

1. **Phase 17** added SCIM 2.0 support with proper nested structures (models.go)
2. **Existing code** uses flat database schema (service.go)
3. **Both files** define `User` and `Group` types with different schemas
4. **Go compiler** cannot handle duplicate type definitions in same package

## The Fix

### Option A: Full SCIM Migration (Recommended - 6-8 hours)

**Step 1: Remove Duplicate Types** (5 minutes)
```bash
# Delete lines 61-87 from service.go (User struct)
# Delete lines 122-134 from service.go (Group struct)
```

**Step 2: Create Conversion Layer** (1 hour)
```go
// File: internal/identity/conversion.go
package identity

// UserDB matches database schema for SQL scanning
type UserDB struct {
    ID       string `db:"id"`
    Username string `db:"username"`
    Email    string `db:"email"`
    FirstName string `db:"first_name"`
    LastName  string `db:"last_name"`
    // ... all other flat fields
}

// ToUser converts flat DB struct to SCIM User
func (u *UserDB) ToUser() User {
    return User{
        ID: u.ID,
        UserName: u.Username,
        Emails: []Email{{Value: u.Email, Primary: boolPtr(true)}},
        Name: &Name{
            GivenName: &u.FirstName,
            FamilyName: &u.LastName,
        },
        // ... map other fields
    }
}
```

**Step 3: Update All Service Methods** (3-4 hours)

For each method that interacts with users:

```go
// BEFORE (doesn't work with SCIM User):
func (s *Service) GetUser(ctx context.Context, userID string) (*User, error) {
    var user User
    err := s.db.Pool.QueryRow(ctx, `SELECT id, username, email, first_name, last_name
                                     FROM users WHERE id = $1`, userID).
        Scan(&user.ID, &user.UserName, &user.Emails[0].Value, ...)
}

// AFTER (converts from DB to SCIM):
func (s *Service) GetUser(ctx context.Context, userID string) (*User, error) {
    var dbUser UserDB  // Use flat struct for scanning
    err := s.db.Pool.QueryRow(ctx, `SELECT id, username, email, first_name, last_name
                                     FROM users WHERE id = $1`, userID).
        Scan(&dbUser.ID, &dbUser.Username, &dbUser.Email, &dbUser.FirstName, &dbUser.LastName)

    user := dbUser.ToUser()  // Convert to SCIM
    return &user, nil
}
```

**Methods to Update:**
- `GetUser()` - ~5 locations
- `ListUsers()` - ~3 locations
- `CreateUser()` - ~3 locations
- `UpdateUser()` - ~4 locations
- `DeleteUser()` - ~2 locations
- `AuthenticateUser()` - ~2 locations
- All handler functions that use User type
- Approximately 50-100 methods total

**Step 4: Fix Field References** (2 hours)

Replace direct field access:

```go
// In handlers and other code:
// OLD: user.Username
// NEW: dbUser.Username (in DB ops) or user.UserName (for SCIM)

// OLD: user.Email
// NEW: dbUser.Email (in DB ops) or user.Emails[0].Value (for SCIM)

// OLD: user.FirstName, user.LastName
// NEW: dbUser.FirstName, dbUser.LastName (DB) or user.Name.GivenName, user.Name.FamilyName (SCIM)
```

**Step 5: Test** (30 minutes)
```bash
# Build
cd deployments/docker
podman-compose build identity-service

# Deploy
podman-compose up -d identity-service

# Test branding endpoint
curl "http://localhost:8001/api/v1/identity/branding?domain=openidx.tdv.org"
```

### Option B: Quick Fix Using Alias (30 minutes)

If you need the branding endpoint working immediately without full migration:

**Step 1: Rename Conflicting Types**
```bash
# In service.go, rename the duplicate structs:
type User struct → type LegacyUser struct
type Group struct → type LegacyGroup struct
```

**Step 2: Update References**
```bash
# Replace all User with LegacyUser in service.go only
sed -i 's/\([^.]\)User /\1LegacyUser /g' internal/identity/service.go
```

**Step 3: Add Conversion at API Boundary**
```go
// In handlers that return User:
func (s *Service) handleGetUser(c *gin.Context) {
    var legacyUser LegacyUser
    // ... scan from database ...

    // Convert to SCIM for response
    user := s.legacyToSCIM(legacyUser)
    c.JSON(200, user)
}
```

**Step 4: Build and Test**

This keeps the database operations unchanged but converts to SCIM at the API layer.

### Option C: Revert to Working Commit (15 minutes)

Find and checkout the last commit before SCIM models were added:

```bash
# Find the commit
git log --oneline --all | grep -i "scim\|model\|phase 17"

# Checkout that commit for identity service only
git checkout <commit-hash> -- internal/identity/

# Rebuild
podman-compose build --no-cache identity-service
```

## Recommended Path

**For Production Quality Code**: Choose Option A (Full SCIM Migration)
- Proper separation of concerns
- SCIM 2.0 compliance
- Clean architecture
- Future-proof

**For Quick Fix**: Choose Option B (Alias Approach)
- Minimal code changes
- Keeps database operations intact
- Adds conversion layer at API boundary
- Can refactor to Option A later

## Files That Need Changes

**Option A:**
- `internal/identity/service.go` - Remove duplicates, update ~100 methods
- `internal/identity/conversion.go` - NEW (conversion functions)
- `internal/identity/repository.go` - Update SCIM query methods
- `internal/identity/handlers_*.go` - Update all handlers

**Option B:**
- `internal/identity/service.go` - Rename types, add conversion
- No changes to database operations
- ~10 handlers need conversion added

## Testing Checklist

After fix:

- [ ] Identity service builds without errors
- [ ] Branding endpoint returns 200 with proper JSON
- [ ] User creation works
- [ ] User authentication works
- [ ] User listing works
- [ ] User update works
- [ ] MFA still works
- [ ] All existing tests pass
- [ ] Frontend can login successfully

## Next Steps

Please choose which option you'd like me to implement:

1. **Option A** - Full SCIM migration (I'll implement the complete solution)
2. **Option B** - Quick alias fix (I'll implement the workaround)
3. **Option C** - Revert to working commit (I'll find and checkout)

Let me know and I'll proceed with the implementation.
