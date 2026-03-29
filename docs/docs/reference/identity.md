# identity

`import "github.com/openidx/openidx/internal/identity"`

Package identity provides user, group, and organization management with SCIM 2.0-compatible models, MFA enrollment, and directory integration. Runs as the Identity Service on port **8001**.

## Service

```go
type Service struct { /* unexported fields */ }

func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service
func (s *Service) RegisterRoutes(r *gin.Engine)
```

The `Service` struct holds database, cache, and config dependencies. Routes are registered under `/api/v1/identity/`.

## Key Types

```go
type User struct {
    ID, UserName string; Active, Enabled bool
    Name *Name; Emails []Email; Groups, Roles []string
    PasswordHash *string; FailedLoginCount int; LockedUntil *time.Time
    CreatedAt, UpdatedAt time.Time; DeletedAt *time.Time
    Meta *Meta
}

type Group struct {
    ID, DisplayName string; Members []Member
    OrganizationID *string; Attributes map[string]string
}

type Organization struct { ID, Name, Domain string }
type Role struct { ID, Name, Description string; IsComposite bool }
type Session struct { ID, UserID, ClientID, IPAddress string; ExpiresAt time.Time }
```

## MFA Types

```go
type MFATOTP struct { ID, UserID string; Secret string; Enabled bool }
type MFABackupCode struct { ID, UserID, CodeHash string; Used bool }
type MFAPolicy struct { ID, Name string; RequiredMethods []string; GracePeriodHours int }
type TOTPEnrollment struct { Secret, QRCodeURL, ManualKey string }
```

## Repository Interface

```go
type Repository interface {
    CreateUser(ctx context.Context, user *User) error
    GetUser(ctx context.Context, id string) (*User, error)
    GetUserByUsername(ctx context.Context, username string) (*User, error)
    UpdateUser(ctx context.Context, user *User) error
    DeleteUser(ctx context.Context, id string) error
    ListUsers(ctx context.Context, filter UserFilter) (*ListResponse, error)
    CreateGroup(ctx context.Context, group *Group) error
    GetGroup(ctx context.Context, id string) (*Group, error)
    // ... additional user, group, and organization CRUD methods
    Ping(ctx context.Context) error
}

type PostgreSQLRepository struct { /* unexported fields */ }
func NewPostgreSQLRepository(pool *pgxpool.Pool, baseURL string) *PostgreSQLRepository
```

## Context Helpers

```go
func ContextWithActorID(ctx context.Context, actorID string) context.Context
```
