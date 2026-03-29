# Go Reference

This section contains auto-generated documentation from Go source code comments.

## Generating Reference Documentation

To regenerate these documents from the source code:

```bash
# Install godoc2md
go install github.com/davecheney/godoc2md@latest

# Generate documentation for a package
cd internal/identity
godoc2md github.com/openidx/openidx/internal/identity > ../../docs/docs/reference/identity.md

# Or generate all at once using the script
./scripts/generate-docs.sh
```

## Available Documentation

| Package | Description | Documentation |
|---------|-------------|---------------|
| `internal/identity` | User and identity management | [Identity Service](identity.md) |
| `internal/governance` | Access reviews and policies | [Governance Service](governance.md) |
| `internal/provisioning` | SCIM 2.0 provisioning | [Provisioning Service](provisioning.md) |
| `internal/audit` | Audit logging and reporting | [Audit Service](audit.md) |
| `internal/oauth` | OAuth/OIDC authorization server | [OAuth Service](oauth.md) |
| `internal/common/middleware` | HTTP middleware | [Middleware](middleware.md) |
| `internal/common/database` | Database utilities | [Database](database.md) |

## Package Documentation Index

### Identity Package

The identity package provides user management, authentication, and session handling.

```go
import "github.com/openidx/openidx/internal/identity"
```

### Governance Package

The governance package handles access reviews, certification campaigns, and policy evaluation.

```go
import "github.com/openidx/openidx/internal/governance"
```

### Provisioning Package

The provisioning package implements SCIM 2.0 for automated user lifecycle management.

```go
import "github.com/openidx/openidx/internal/provisioning"
```

### Audit Package

The audit package provides comprehensive event logging and compliance reporting.

```go
import "github.com/openidx/openidx/internal/audit"
```

### OAuth Package

The oauth package implements OAuth 2.0 and OpenID Connect protocols.

```go
import "github.com/openidx/openidx/internal/oauth"
```

### Common Packages

Shared utilities used across all services.

- `middleware` - HTTP middleware for auth, logging, rate limiting
- `database` - Database connection pooling and migrations
- `logger` - Structured logging with zap
- `config` - Configuration loading from environment and files
- `errors` - Standardized error handling

## Go Doc Online

Full package documentation is available at:

```
https://pkg.go.dev/github.com/openidx/openidx
```

## Contributing to Documentation

When adding new functions or types, follow these conventions for godoc comments:

```go
// Service provides identity management operations.
// It handles user CRUD, authentication, sessions, and MFA.
type Service struct {
    db    *database.DB
    cache *redis.Client
    log   *zap.Logger
}

// CreateUser creates a new user with the given details.
// The password will be hashed using bcrypt before storage.
// Returns the created user ID or an error if validation fails.
//
// Example:
//   id, err := s.CreateUser(ctx, CreateUserRequest{
//       Username: "jdoe",
//       Email:    "jane@example.com",
//       Password: "secure-password",
//   })
func (s *Service) CreateUser(ctx context.Context, req CreateUserRequest) (string, error) {
    // ...
}
```

Documentation comments:
1. Start with the function/type name
2. Use complete sentences
3. Provide context about what the function does
4. Document parameters and return values
5. Include usage examples when helpful
6. Use backticks for code references
7. Keep comments concise but informative
