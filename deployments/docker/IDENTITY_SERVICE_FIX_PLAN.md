# Identity Service Build Fix - Comprehensive Plan

## Problem Summary

The identity service build is failing due to **duplicate type definitions** and **schema mismatch** between database and SCIM models.

### Root Causes

1. **Duplicate Type Definitions**:
   - `internal/identity/models.go` defines SCIM-compatible `User` and `Group` structs
   - `internal/identity/service.go` defines duplicate `User` and `Group` structs with flat fields
   - Go compiler: "User redeclared in this block"

2. **Schema Mismatch**:
   - **Database schema** (actual PostgreSQL columns):
     ```sql
     username VARCHAR(255)
     email VARCHAR(255)
     first_name VARCHAR(255)
     last_name VARCHAR(255)
     ```

   - **SCIM Model** (from models.go):
     ```go
     UserName string           // SCIM standard
     Emails []Email           {
         Value string
         Primary *bool
     }
     Name *Name {
         GivenName *string
         FamilyName *string
     }
     ```

   - **Legacy Model** (from service.go):
     ```go
     Username string
     Email string
     FirstName string
     LastName string
     ```

3. **Code Dependencies**:
   - ~200+ references to `user.Username`, `user.Email`, `user.FirstName`, `user.LastName` throughout the codebase
   - SQL Scan operations expect flat fields
   - API handlers expect flat field names

## Solution Architecture

### Phase 1: Create Conversion Layer (1-2 hours)

Create `internal/identity/user_conversion.go`:

```go
package identity

// UserDB represents flat database schema for SQL operations
type UserDB struct {
	ID            string     `db:"id"`
	Username      string     `db:"username"`
	Email         string     `db:"email"`
	FirstName     string     `db:"first_name"`
	LastName      string     `db:"last_name"`
	Enabled       bool       `db:"enabled"`
	EmailVerified bool       `db:"email_verified"`
	// ... all other flat fields
}

// ToUser converts UserDB to SCIM User model
func (u *UserDB) ToUser() User {
	user := User{
		ID:       u.ID,
		UserName: u.Username,
		Enabled:  u.Enabled,
		// Map other fields...
	}

	// Convert flat name to nested Name
	user.Name = &Name{
		GivenName:  &u.FirstName,
		FamilyName: &u.LastName,
	}

	// Convert flat email to Emails array
	user.Emails = []Email{{
		Value:   u.Email,
		Primary: boolPtr(true),
	}}

	return user
}

// FromUser converts SCIM User to UserDB for database operations
func FromUser(user User) UserDB {
	dbUser := UserDB{
		ID:       user.ID,
		Username: user.UserName,
		Enabled:  user.Enabled,
	}

	if user.Name != nil {
		if user.Name.GivenName != nil {
			dbUser.FirstName = *user.Name.GivenName
		}
		if user.Name.FamilyName != nil {
			dbUser.LastName = *user.Name.FamilyName
		}
	}

	if len(user.Emails) > 0 {
		dbUser.Email = user.Emails[0].Value
	}

	return dbUser
}
```

### Phase 2: Update Service Methods (2-3 hours)

For each method in `service.go` that operates on users:

1. **Database Query Methods** - Use UserDB for scanning:
   ```go
   // BEFORE (broken):
   var user User
   err := db.QueryRow(...).Scan(&user.ID, &user.Username, &user.Email, ...)

   // AFTER (fixed):
   var dbUser UserDB
   err := db.QueryRow(...).Scan(&dbUser.ID, &dbUser.Username, &dbUser.Email, ...)
   user := dbUser.ToUser()
   ```

2. **API Handler Methods** - Use User (SCIM) for responses:
   ```go
   // Returns SCIM-compatible JSON
   c.JSON(200, user)
   ```

### Phase 3: Remove Duplicate Types (5 minutes)

Delete lines 61-87 and 122-134 from `internal/identity/service.go`:
- Remove duplicate `User` struct
- Remove duplicate `Group` struct
- Add type alias if needed: `type UserDB = models.User` (but use custom conversion)

### Phase 4: Fix Compilation Errors (1-2 hours)

Update all field references:
- `user.Username` → `dbUser.Username` (in DB operations)
- `user.Email` → `dbUser.Email` (in DB operations)
- Keep `user.UserName` for SCIM model in API responses

### Phase 5: Test and Verify (30 minutes)

1. Build identity service: `podman-compose build identity-service`
2. Test branding endpoint: `curl "http://localhost:8001/api/v1/identity/branding?domain=openidx.tdv.org"`
3. Test user CRUD operations
4. Verify database queries work correctly

## Estimated Effort

- **Phase 1**: 1-2 hours
- **Phase 2**: 2-3 hours
- **Phase 3**: 5 minutes
- **Phase 4**: 1-2 hours
- **Phase 5**: 30 minutes
- **Total**: 5-8 hours

## Alternative Quick Fix (Workaround)

If you need the branding endpoint working immediately without full refactoring:

1. Create a separate simple service just for branding
2. Add branding data to frontend config
3. Use database view or stored procedure
4. Time: 30-60 minutes

## Files to Modify

1. `internal/identity/service.go` - Remove duplicate types, update methods
2. `internal/identity/user_conversion.go` - NEW: Conversion functions
3. `internal/identity/handlers_tenant.go` - Already correct (uses proper queries)
4. `internal/identity/models.go` - No changes needed (SCIM models are correct)
5. `internal/identity/repository.go` - May need updates for SCIM queries

## Database Schema (Current)

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    enabled BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    password_hash VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    -- ... other fields
);
```

## Recommendations

1. **Do NOT** change the database schema - it's working correctly
2. **DO** create conversion layer between flat DB schema and nested SCIM models
3. **DO** keep existing SQL queries using flat column names
4. **DO** convert to/from SCIM models at API boundaries
5. **DO NOT** try to change all 200+ field references at once - do it incrementally

## Testing Checklist

After fix is complete:

- [ ] Identity service builds successfully
- [ ] Branding endpoint returns proper JSON
- [ ] User creation works
- [ ] User listing works
- [ ] User update works
- [ ] User deletion works
- [ ] Authentication still works
- [ ] MFA still works
- [ ] All database queries succeed
- [ ] No data loss or corruption

## Next Steps

Choose one of:

1. **Implement Full Fix** - Follow the 5-phase plan above (5-8 hours)
2. **Quick Workaround** - Create temporary branding-only service (30-60 minutes)
3. **Rollback** - Revert to commit before SCIM models were added

Let me know which approach you'd prefer to take.
