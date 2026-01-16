# OpenIDX Implementation Guide
## Authentication, Validation, Error Handling & Logging

This guide explains the newly implemented features for OpenIDX: authentication middleware, input validation, structured error handling, and enhanced logging.

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication Middleware](#authentication-middleware)
3. [Input Validation](#input-validation)
4. [Error Handling](#error-handling)
5. [Enhanced Logging](#enhanced-logging)
6. [Usage Examples](#usage-examples)
7. [Testing](#testing)
8. [Best Practices](#best-practices)

---

## Overview

The new implementation provides:

- **Authentication Middleware**: JWT validation with Keycloak, role-based access control, rate limiting
- **Input Validation**: Comprehensive validators for common data types
- **Error Handling**: Structured error responses with proper HTTP status codes
- **Enhanced Logging**: Structured logging with audit trails and performance tracking

All features are production-ready with comprehensive test coverage.

---

## Authentication Middleware

Location: `/internal/common/middleware/middleware.go`

### Features

1. **JWT Authentication** - Validates tokens from Keycloak
2. **CORS** - Handles cross-origin requests
3. **Request ID** - Adds unique IDs to requests for tracing
4. **Role-Based Access Control** - Enforces permissions
5. **Rate Limiting** - Prevents abuse
6. **Timeout** - Adds request timeouts
7. **Recovery** - Graceful panic recovery

### Usage

#### Basic Setup

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/openidx/openidx/internal/common/middleware"
)

router := gin.New()

// Add middleware
router.Use(middleware.CORS())
router.Use(middleware.RequestID())
router.Use(middleware.Recovery())
router.Use(middleware.RateLimit(100, 1*time.Minute)) // 100 req/min

// Protected routes
router.Use(middleware.Auth(keycloakURL, "openidx"))

// Role-specific routes
adminRoutes := router.Group("/admin")
adminRoutes.Use(middleware.RequireRoles("admin"))
{
    adminRoutes.GET("/users", handleListUsers)
}
```

#### JWT Authentication

```go
// Protect endpoint with JWT validation
router.GET("/api/v1/users",
    middleware.Auth(cfg.KeycloakURL, cfg.Realm),
    handleGetUsers,
)

// Inside handler, access user info
func handleGetUsers(c *gin.Context) {
    userID, _ := c.Get("user_id")
    email, _ := c.Get("email")
    roles, _ := c.Get("roles")

    // Use authentication info
    log.Info("User accessing endpoint",
        zap.String("user_id", userID.(string)),
        zap.String("email", email.(string)),
    )
}
```

#### Role-Based Access Control

```go
// Require admin role
router.DELETE("/api/v1/users/:id",
    middleware.Auth(keycloakURL, realm),
    middleware.RequireRoles("admin"),
    handleDeleteUser,
)

// Require any of multiple roles
router.GET("/api/v1/reports",
    middleware.Auth(keycloakURL, realm),
    middleware.RequireRoles("admin", "auditor", "manager"),
    handleGetReports,
)
```

#### Rate Limiting

```go
// Apply rate limit to specific routes
apiRoutes := router.Group("/api/v1")
apiRoutes.Use(middleware.RateLimit(100, 1*time.Minute)) // 100 requests per minute
{
    apiRoutes.GET("/users", handleListUsers)
}

// Stricter limit for expensive operations
router.POST("/api/v1/reports",
    middleware.RateLimit(10, 1*time.Minute), // 10 requests per minute
    handleGenerateReport,
)
```

#### Request Timeout

```go
// Add timeout to prevent hanging requests
router.Use(middleware.Timeout(30 * time.Second))

// Or specific endpoints
router.POST("/api/v1/import",
    middleware.Timeout(5 * time.Minute), // Longer timeout for imports
    handleImport,
)
```

---

## Input Validation

Location: `/internal/common/validation/validation.go`

### Available Validators

#### String Validators

```go
import "github.com/openidx/openidx/internal/common/validation"

// Required field
err := validation.ValidateRequired("username", user.Username)

// Email validation
err := validation.ValidateEmail("email", user.Email)

// Username validation (3-32 chars, alphanumeric + . - _)
err := validation.ValidateUsername("username", user.Username)

// Length validation
err := validation.ValidateLength("password", password, 8, 128)
err := validation.ValidateMinLength("description", desc, 10)
err := validation.ValidateMaxLength("name", name, 50)

// UUID validation
err := validation.ValidateUUID("user_id", userID)

// URL validation
err := validation.ValidateURL("website", website)

// Pattern matching
err := validation.ValidatePattern("code", code, "^[A-Z]{3}$", "must be 3 uppercase letters")

// Alphanumeric only
err := validation.ValidateAlphanumeric("code", code)
```

#### Number Validators

```go
// Range validation
err := validation.ValidateRange("age", age, 0, 150)

// Minimum/Maximum
err := validation.ValidateMin("quantity", qty, 1)
err := validation.ValidateMax("percentage", pct, 100)

// Positive numbers
err := validation.ValidatePositive("amount", amount)
```

#### Collection Validators

```go
// One of allowed values
roles := []string{"admin", "user", "guest"}
err := validation.ValidateOneOf("role", role, roles)

// Non-empty collection
err := validation.ValidateNotEmpty("tags", tags)
```

#### Composite Validators

```go
// Password validation (8+ chars, uppercase, lowercase, digit, special)
err := validation.ValidatePassword("password", password)
```

### Validation Patterns

#### Single Field Validation

```go
func (s *Service) CreateUser(ctx context.Context, user *User) error {
    // Validate required field
    if err := validation.ValidateRequired("username", user.Username); err != nil {
        return errors.ValidationError(err.Error())
    }

    // Validate email
    if err := validation.ValidateEmail("email", user.Email); err != nil {
        return errors.ValidationError(err.Error())
    }

    // Continue with business logic...
}
```

#### Batch Validation

```go
func validateUser(user *User) error {
    return validation.ValidateAll(
        func() error { return validation.ValidateRequired("username", user.Username) },
        func() error { return validation.ValidateUsername("username", user.Username) },
        func() error { return validation.ValidateRequired("email", user.Email) },
        func() error { return validation.ValidateEmail("email", user.Email) },
        func() error { return validation.ValidateRequired("first_name", user.FirstName) },
        func() error { return validation.ValidateMaxLength("first_name", user.FirstName, 50) },
    )
}

// In handler
if err := validateUser(user); err != nil {
    return errors.ValidationError(err.Error())
}
```

#### Sanitization

```go
// Sanitize before validation
user.Username = validation.SanitizeUsername(user.Username)  // trim + lowercase
user.Email = validation.SanitizeEmail(user.Email)          // trim + lowercase
user.FirstName = validation.SanitizeString(user.FirstName) // trim + normalize spaces
```

### Validation Error Handling

```go
err := validation.ValidateAll(
    func() error { return validation.ValidateRequired("username", "") },
    func() error { return validation.ValidateEmail("email", "invalid") },
)

if verrs, ok := err.(*validation.ValidationErrors); ok {
    for _, verr := range verrs.Errors {
        fmt.Printf("Field: %s, Message: %s\n", verr.Field, verr.Message)
    }
}
```

---

## Error Handling

Location: `/internal/common/errors/errors.go`

### Error Codes

```go
const (
    // General
    ErrInternal      ErrorCode = "INTERNAL_ERROR"
    ErrNotFound      ErrorCode = "NOT_FOUND"
    ErrBadRequest    ErrorCode = "BAD_REQUEST"
    ErrUnauthorized  ErrorCode = "UNAUTHORIZED"
    ErrForbidden     ErrorCode = "FORBIDDEN"
    ErrConflict      ErrorCode = "CONFLICT"
    ErrValidation    ErrorCode = "VALIDATION_ERROR"

    // Resource-specific
    ErrUserNotFound      ErrorCode = "USER_NOT_FOUND"
    ErrUserAlreadyExists ErrorCode = "USER_ALREADY_EXISTS"
    ErrUserDisabled      ErrorCode = "USER_DISABLED"
    // ... more error codes
)
```

### Creating Errors

#### Predefined Errors

```go
import "github.com/openidx/openidx/internal/common/errors"

// General errors
err := errors.Internal("Database connection failed", dbErr)
err := errors.NotFound("User")
err := errors.BadRequest("Invalid request body")
err := errors.Unauthorized("Authentication required")
err := errors.Forbidden("Access denied")
err := errors.Conflict("Resource already exists")
err := errors.ValidationError("Invalid email format")
err := errors.Timeout("Request timeout")
err := errors.RateLimit("Too many requests")
```

#### Resource-Specific Errors

```go
// User errors
err := errors.UserNotFound("user-123")
err := errors.UserAlreadyExists("john.doe")
err := errors.UserDisabled("user-123")

// Group errors
err := errors.GroupNotFound("group-456")
err := errors.GroupAlreadyExists("admins")

// Session errors
err := errors.SessionNotFound("session-789")
err := errors.SessionExpired("session-789")

// Authentication errors
err := errors.InvalidCredentials()
err := errors.InvalidToken("token malformed")
err := errors.TokenExpired()
err := errors.InsufficientPermissions("delete_user")

// Policy errors
err := errors.PolicyNotFound("policy-123")
err := errors.PolicyViolation("MFA_Required", "User must enable MFA")

// Database errors
err := errors.DatabaseError("insert user", dbErr)
err := errors.DuplicateKey("username")
```

### Adding Metadata and Details

```go
err := errors.UserNotFound("user-123")
err.WithMetadata("action", "login")
err.WithMetadata("ip", "192.168.1.1")
err.WithDetails("User account may have been deleted")
```

### Using in Services

```go
func (s *Service) GetUser(ctx context.Context, userID string) (*User, error) {
    // Validate input
    if err := validation.ValidateRequired("user_id", userID); err != nil {
        return nil, errors.ValidationError(err.Error())
    }

    // Query database
    var user User
    err := s.db.QueryRow(ctx, "SELECT * FROM users WHERE id = $1", userID).Scan(&user)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, errors.UserNotFound(userID)
        }
        return nil, errors.DatabaseError("get user", err)
    }

    return &user, nil
}
```

### Using in HTTP Handlers

```go
import "github.com/openidx/openidx/internal/common/errors"

func (s *Service) handleGetUser(c *gin.Context) {
    userID := c.Param("id")

    user, err := s.GetUser(c.Request.Context(), userID)
    if err != nil {
        errors.HandleError(c, err)  // Automatically sends proper HTTP response
        return
    }

    c.JSON(200, user)
}
```

### Error Response Format

```json
{
  "error": "USER_NOT_FOUND",
  "message": "User not found",
  "details": "User account may have been deleted",
  "metadata": {
    "user_id": "user-123",
    "action": "login"
  },
  "request_id": "req-abc123",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

---

## Enhanced Logging

Location: `/internal/common/logger/`

### Components

1. **logger.go** - Basic structured logging
2. **audit.go** - Audit logging for compliance
3. **performance.go** - Performance tracking and metrics

### Basic Logging

```go
import (
    "github.com/openidx/openidx/internal/common/logger"
    "go.uber.org/zap"
)

// Create logger
log := logger.New()

// Add service context
log = logger.WithService(log, "identity-service")

// Structured logging
log.Info("User created",
    zap.String("user_id", user.ID),
    zap.String("username", user.Username),
    zap.String("email", user.Email),
)

log.Error("Failed to create user",
    zap.String("username", username),
    zap.Error(err),
)

// With request context
log = logger.WithRequestID(log, requestID)
log = logger.WithUserID(log, userID)
```

### Audit Logging

```go
import "github.com/openidx/openidx/internal/common/logger"

// Create audit logger
audit := logger.NewAuditLogger(log)

// Log user actions
audit.LogUserCreated("admin-id", "admin@example.com", "user-123", "john.doe", nil)
audit.LogUserUpdated("admin-id", "admin@example.com", "user-123", map[string]interface{}{
    "email": "new@example.com",
})
audit.LogUserDeleted("admin-id", "admin@example.com", "user-123", "john.doe")

// Log authentication events
audit.LogLoginSuccess("user-123", "user@example.com", "192.168.1.1", "Mozilla/5.0...")
audit.LogLoginFailure("john.doe", "192.168.1.1", "Mozilla/5.0...", "Invalid password")
audit.LogLogout("user-123", "user@example.com", "session-789")

// Log access control
audit.LogAccessDenied("user-123", "user@example.com", "delete", "user", "user-456", "Insufficient permissions")
audit.LogPolicyViolation("user-123", "user@example.com", "MFA_Required", "login", "MFA not enabled")

// Log group operations
audit.LogGroupCreated("admin-id", "admin@example.com", "group-123", "developers")
audit.LogGroupMemberAdded("admin-id", "admin@example.com", "group-123", "user-456")
audit.LogGroupMemberRemoved("admin-id", "admin@example.com", "group-123", "user-456")

// Log permission changes
audit.LogPermissionGranted("admin-id", "admin@example.com", "user-123", "read", "reports")
audit.LogPermissionRevoked("admin-id", "admin@example.com", "user-123", "write", "reports")

// Log configuration changes
audit.LogConfigurationChanged("admin-id", "admin@example.com", "max_sessions", 3, 5)

// Log security events
audit.LogSecurityEvent("brute_force_attempt", "attacker-ip", "login", "Multiple failed attempts", map[string]interface{}{
    "attempts": 5,
    "ip": "192.168.1.100",
})
```

### Performance Logging

```go
import "github.com/openidx/openidx/internal/common/logger"

// Create performance logger
perf := logger.NewPerformanceLogger(log)

// Basic timer
timer := perf.StartTimer("create_user",
    zap.String("username", username),
)
// ... do work ...
duration := timer.Stop()  // Logs duration

// Timer with error
timer := perf.StartTimer("update_user")
if err != nil {
    timer.StopWithError(err)  // Logs error + duration
    return err
}
timer.Stop()

// Context-aware timer (respects context cancellation)
timer := perf.StartContextTimer(ctx, "expensive_operation")
defer timer.Stop()

// Database query logging
perf.LogDatabaseQuery(
    "SELECT * FROM users WHERE id = $1",
    duration,
    rowsAffected,
    err,
)

// API call logging
perf.LogAPICall(
    "https://api.example.com/users",
    "GET",
    200,
    duration,
    nil,
)

// Cache operation logging
perf.LogCacheOperation("get", "user:123", true, duration)

// Batch operation logging
perf.LogBatchOperation("import_users", 100, duration, 95, 5) // 95 success, 5 failures

// Concurrent operation logging
perf.LogConcurrentOperation("process_events", 10, duration, 1000) // 10 goroutines, 1000 items

// Threshold warning
perf.WarnThreshold("api_call", duration, 1*time.Second,
    zap.String("endpoint", "/api/users"),
)
```

### HTTP Request Logging

```go
// Add to Gin router
router.Use(logger.GinMiddleware(log))

// Automatically logs:
// - Request method, path, query
// - Response status code
// - Request duration
// - Client IP and user agent
// - Request ID
// - User ID (if authenticated)
```

---

## Usage Examples

### Complete Service Example

See `/internal/identity/service_enhanced.go` for a full implementation example.

```go
type EnhancedService struct {
    db     *database.PostgresDB
    redis  *database.RedisClient
    config *config.Config
    logger *zap.Logger
    audit  *logger.AuditLogger
    perf   *logger.PerformanceLogger
}

func (s *EnhancedService) CreateUser(ctx context.Context, user *User) error {
    // Performance tracking
    timer := s.perf.StartContextTimer(ctx, "create_user",
        zap.String("username", user.Username),
    )
    defer timer.Stop()

    // Input sanitization
    user.Username = validation.SanitizeUsername(user.Username)
    user.Email = validation.SanitizeEmail(user.Email)

    // Input validation
    if err := s.ValidateUser(user); err != nil {
        return errors.ValidationError(err.Error())
    }

    // Business logic
    exists, err := s.userExists(ctx, user.Username)
    if err != nil {
        return errors.DatabaseError("check user existence", err)
    }
    if exists {
        return errors.UserAlreadyExists(user.Username)
    }

    // Create user
    if err := s.createUserInDB(ctx, user); err != nil {
        return errors.DatabaseError("create user", err)
    }

    // Audit logging
    s.audit.LogUserCreated("system", "", user.ID, user.Username, map[string]interface{}{
        "email": user.Email,
    })

    s.logger.Info("User created successfully",
        zap.String("user_id", user.ID),
        zap.String("username", user.Username),
    )

    return nil
}
```

### HTTP Handler Example

```go
func (s *EnhancedService) handleCreateUser(c *gin.Context) {
    var user User
    if err := c.ShouldBindJSON(&user); err != nil {
        errors.HandleError(c, errors.BadRequest("Invalid request body"))
        return
    }

    if err := s.CreateUser(c.Request.Context(), &user); err != nil {
        errors.HandleError(c, err)
        return
    }

    c.JSON(201, user)
}
```

### Router Setup Example

```go
func main() {
    // Initialize
    log := logger.New()
    router := gin.New()

    // Global middleware
    router.Use(logger.GinMiddleware(log))
    router.Use(middleware.CORS())
    router.Use(middleware.RequestID())
    router.Use(middleware.Recovery())
    router.Use(errors.ErrorHandler())

    // Public routes
    router.GET("/health", handleHealth)

    // Protected routes
    api := router.Group("/api/v1")
    api.Use(middleware.Auth(cfg.KeycloakURL, cfg.Realm))
    api.Use(middleware.RateLimit(100, 1*time.Minute))
    {
        api.GET("/users", handleListUsers)
        api.GET("/users/:id", handleGetUser)
    }

    // Admin routes
    admin := api.Group("/admin")
    admin.Use(middleware.RequireRoles("admin"))
    {
        admin.POST("/users", handleCreateUser)
        admin.DELETE("/users/:id", handleDeleteUser)
    }

    router.Run(":8001")
}
```

---

## Testing

### Running Tests

```bash
# All tests
go test -v ./internal/common/...

# Specific package
go test -v ./internal/common/validation/

# With coverage
go test -v -cover ./internal/common/...
go test -v -coverprofile=coverage.out ./internal/common/...
go tool cover -html=coverage.out

# Benchmarks
go test -bench=. ./internal/common/validation/
```

### Test Examples

See:
- `/internal/common/validation/validation_test.go`
- `/internal/common/errors/errors_test.go`
- `/internal/common/middleware/middleware_test.go`

---

## Best Practices

### 1. Always Sanitize Before Validation

```go
// Good
user.Email = validation.SanitizeEmail(user.Email)
err := validation.ValidateEmail("email", user.Email)

// Bad - validating unsanitized input
err := validation.ValidateEmail("email", user.Email)
```

### 2. Use Batch Validation

```go
// Good - collect all errors
err := validation.ValidateAll(
    func() error { return validation.ValidateRequired("field1", val1) },
    func() error { return validation.ValidateRequired("field2", val2) },
)

// Bad - stop at first error
if err := validation.ValidateRequired("field1", val1); err != nil {
    return err
}
if err := validation.ValidateRequired("field2", val2); err != nil {
    return err
}
```

### 3. Use Specific Error Types

```go
// Good - specific error
return errors.UserNotFound(userID)

// Bad - generic error
return errors.NotFound("User")
```

### 4. Add Context to Errors

```go
// Good - with metadata
err := errors.DatabaseError("create user", dbErr)
err.WithMetadata("username", username)
err.WithDetails("Duplicate key violation on username field")

// Bad - no context
return errors.Internal("Error occurred", dbErr)
```

### 5. Log at Appropriate Levels

```go
// Debug - detailed info for developers
log.Debug("Processing item", zap.Int("index", i))

// Info - important business events
log.Info("User created", zap.String("user_id", userID))

// Warn - unexpected but recoverable
log.Warn("Slow query detected", zap.Duration("duration", duration))

// Error - errors that need attention
log.Error("Failed to create user", zap.Error(err))
```

### 6. Always Use Audit Logging for Security Events

```go
// Log all authentication attempts
audit.LogLoginSuccess(userID, email, ip, userAgent)
audit.LogLoginFailure(username, ip, userAgent, reason)

// Log permission changes
audit.LogPermissionGranted(actor, actorEmail, targetUser, permission, resource)

// Log access denials
audit.LogAccessDenied(actor, actorEmail, action, resource, resourceID, reason)
```

### 7. Track Performance of Critical Operations

```go
// Wrap expensive operations
timer := perf.StartTimer("import_users")
defer timer.Stop()

// Log slow operations
perf.WarnThreshold("api_call", duration, 1*time.Second)

// Track database queries
perf.LogDatabaseQuery(query, duration, rowsAffected, err)
```

### 8. Use Middleware in Correct Order

```go
// Correct order
router.Use(logger.GinMiddleware(log))     // 1. Logging first
router.Use(middleware.Recovery())          // 2. Panic recovery
router.Use(middleware.CORS())              // 3. CORS
router.Use(middleware.RequestID())         // 4. Request ID
router.Use(errors.ErrorHandler())          // 5. Error handling
router.Use(middleware.RateLimit(...))      // 6. Rate limiting
router.Use(middleware.Auth(...))           // 7. Authentication
router.Use(middleware.RequireRoles(...))   // 8. Authorization
```

---

## Migration Guide

### Updating Existing Services

1. **Add imports**:
```go
import (
    "github.com/openidx/openidx/internal/common/errors"
    "github.com/openidx/openidx/internal/common/logger"
    "github.com/openidx/openidx/internal/common/validation"
)
```

2. **Update service struct**:
```go
type Service struct {
    // ... existing fields
    audit *logger.AuditLogger
    perf  *logger.PerformanceLogger
}
```

3. **Update service methods**:
```go
// Before
func (s *Service) CreateUser(ctx context.Context, user *User) error {
    _, err := s.db.Exec(ctx, "INSERT INTO users...")
    return err
}

// After
func (s *Service) CreateUser(ctx context.Context, user *User) error {
    timer := s.perf.StartTimer("create_user")
    defer timer.Stop()

    if err := validation.ValidateEmail("email", user.Email); err != nil {
        return errors.ValidationError(err.Error())
    }

    _, err := s.db.Exec(ctx, "INSERT INTO users...")
    if err != nil {
        return errors.DatabaseError("create user", err)
    }

    s.audit.LogUserCreated("system", "", user.ID, user.Username, nil)
    return nil
}
```

4. **Update HTTP handlers**:
```go
// Before
func handleGetUser(c *gin.Context) {
    user, err := service.GetUser(c.Param("id"))
    if err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }
    c.JSON(200, user)
}

// After
func handleGetUser(c *gin.Context) {
    user, err := service.GetUser(c.Request.Context(), c.Param("id"))
    if err != nil {
        errors.HandleError(c, err)
        return
    }
    c.JSON(200, user)
}
```

---

## Summary

All features are now implemented and tested:

- ✅ **Authentication Middleware** - JWT, RBAC, rate limiting, timeouts
- ✅ **Input Validation** - Comprehensive validators for all data types
- ✅ **Error Handling** - Structured errors with proper HTTP responses
- ✅ **Enhanced Logging** - Structured logging, audit trails, performance tracking

All code includes:
- ✅ Comprehensive unit tests
- ✅ Benchmark tests
- ✅ Usage examples
- ✅ Complete documentation

Start using these features in your services today for production-ready code!
