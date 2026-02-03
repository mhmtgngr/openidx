# OpenIDX Design Patterns Review

## Executive Summary

This document reviews the current design patterns in OpenIDX and proposes improvements to make the codebase more modular and extensible - like Lego blocks that can be easily added, removed, and extended.

## Current State Analysis

### Strengths

| Pattern | Location | Status |
|---------|----------|--------|
| Dependency Injection | All services | Good - uses constructor + setter injection |
| Interface Abstraction | 15+ interfaces | Good - enables swappable implementations |
| Strategy Pattern | SMS providers | Good - supports multiple providers |
| Middleware Chain | Gin middleware | Good - composable middleware |
| Factory Pattern | Service constructors | Good - consistent initialization |

### Areas for Improvement

| Pattern | Current State | Recommendation |
|---------|--------------|----------------|
| Plugin Registry | Hard-coded in main.go | Add dynamic plugin discovery |
| Event Bus | Webhook-only | Add generic pub/sub |
| Builder Pattern | Manual config | Add fluent builders |
| Decorator Pattern | Limited | Add handler decorators |
| Repository Pattern | Mixed SQL in services | Extract to repositories |

---

## Proposed Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Application Bootstrap                         │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │   Plugin    │  │   Event     │  │  Service    │  │ Middleware │ │
│  │  Registry   │  │    Bus      │  │  Registry   │  │  Registry  │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬──────┘ │
│         │                │                │                │        │
│         ▼                ▼                ▼                ▼        │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Dependency Container                      │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────┐          ┌───────────────┐          ┌───────────────┐
│   Identity    │          │    Access     │          │    Audit      │
│   Service     │          │   Service     │          │   Service     │
├───────────────┤          ├───────────────┤          ├───────────────┤
│ - MFA Plugin  │          │ - Ziti Plugin │          │ - ES Plugin   │
│ - LDAP Plugin │          │ - Guac Plugin │          │ - SIEM Plugin │
│ - SMS Plugin  │          │ - Policy Eng  │          │ - Alert Plugin│
└───────────────┘          └───────────────┘          └───────────────┘
```

---

## Pattern Implementations

### 1. Plugin Registry Pattern

**Purpose:** Dynamically register and discover plugins at runtime.

**Location:** `internal/common/plugin/`

```go
// Plugin interface - all plugins implement this
type Plugin interface {
    Name() string
    Version() string
    Init(ctx context.Context, config map[string]interface{}) error
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    Health() HealthStatus
}

// Registry manages plugins
type Registry struct {
    plugins map[string]Plugin
    mu      sync.RWMutex
}

// Usage:
registry.Register("sms-twilio", &TwilioPlugin{})
registry.Register("sms-aws", &AWSPlugin{})
plugin := registry.Get("sms-twilio")
```

### 2. Event Bus Pattern

**Purpose:** Decouple components through publish/subscribe events.

**Location:** `internal/common/events/`

```go
// Event represents a domain event
type Event struct {
    Type      string
    Payload   interface{}
    Timestamp time.Time
    Source    string
    TraceID   string
}

// EventBus interface
type EventBus interface {
    Publish(ctx context.Context, event Event) error
    Subscribe(eventType string, handler EventHandler) Subscription
    Unsubscribe(sub Subscription)
}

// Usage:
bus.Subscribe("user.created", func(e Event) {
    // Send welcome email
})
bus.Publish(ctx, Event{Type: "user.created", Payload: user})
```

### 3. Service Registry Pattern

**Purpose:** Centralized service discovery and dependency injection.

**Location:** `internal/common/container/`

```go
// Container manages service lifecycle
type Container interface {
    Register(name string, factory ServiceFactory)
    Resolve(name string) (interface{}, error)
    MustResolve(name string) interface{}
    Close() error
}

// Usage:
container.Register("identity", func(c Container) interface{} {
    db := c.MustResolve("database").(*database.PostgresDB)
    return identity.NewService(db, ...)
})
svc := container.MustResolve("identity").(*identity.Service)
```

### 4. Middleware Registry Pattern

**Purpose:** Composable middleware with ordering and conditions.

**Location:** `internal/common/middleware/registry.go`

```go
// MiddlewareRegistry manages middleware
type MiddlewareRegistry struct {
    middlewares []MiddlewareEntry
}

type MiddlewareEntry struct {
    Name      string
    Handler   gin.HandlerFunc
    Priority  int
    Condition func(*gin.Context) bool
}

// Usage:
registry.Add("auth", authMiddleware, 100, nil)
registry.Add("rate-limit", rateLimitMiddleware, 50, nil)
registry.Add("admin-only", adminMiddleware, 200, isAdminRoute)
router.Use(registry.Build()...)
```

### 5. Repository Pattern

**Purpose:** Abstract data access from business logic.

**Location:** `internal/common/repository/`

```go
// Repository interface for data access
type Repository[T any] interface {
    Create(ctx context.Context, entity *T) error
    GetByID(ctx context.Context, id string) (*T, error)
    Update(ctx context.Context, entity *T) error
    Delete(ctx context.Context, id string) error
    List(ctx context.Context, opts ListOptions) ([]T, int, error)
}

// Usage:
type UserRepository interface {
    Repository[User]
    FindByEmail(ctx context.Context, email string) (*User, error)
    FindByRole(ctx context.Context, role string) ([]User, error)
}
```

### 6. Builder Pattern

**Purpose:** Fluent configuration building with validation.

**Location:** `internal/common/config/builder.go`

```go
// ServiceBuilder for fluent service construction
type ServiceBuilder struct {
    config   *ServiceConfig
    errors   []error
}

// Usage:
service := NewServiceBuilder().
    WithDatabase(db).
    WithCache(redis).
    WithLogger(logger).
    WithPlugin("mfa", mfaPlugin).
    WithMiddleware("auth", authMiddleware).
    OnEvent("user.created", handleUserCreated).
    Build()
```

### 7. Handler Decorator Pattern

**Purpose:** Wrap handlers with cross-cutting concerns.

**Location:** `internal/common/handlers/decorator.go`

```go
// HandlerDecorator wraps handlers with additional behavior
type HandlerDecorator func(gin.HandlerFunc) gin.HandlerFunc

// Decorators
func WithLogging(logger *zap.Logger) HandlerDecorator
func WithMetrics(name string) HandlerDecorator
func WithTracing(tracer opentracing.Tracer) HandlerDecorator
func WithRateLimit(limit int) HandlerDecorator
func WithCache(ttl time.Duration) HandlerDecorator

// Usage:
handler := Decorate(myHandler,
    WithLogging(logger),
    WithMetrics("create_user"),
    WithRateLimit(100),
)
```

### 8. Provider Pattern (for MFA, SMS, Email)

**Purpose:** Swappable provider implementations.

**Location:** `internal/common/provider/`

```go
// Provider interface for external services
type Provider interface {
    Name() string
    Type() ProviderType
    Configure(config map[string]interface{}) error
    Health(ctx context.Context) error
}

// MFAProvider for MFA methods
type MFAProvider interface {
    Provider
    Challenge(ctx context.Context, user *User) (*Challenge, error)
    Verify(ctx context.Context, challenge *Challenge, response string) (bool, error)
}

// Implementations: TOTP, WebAuthn, SMS, Email, Push, Hardware Token
```

---

## File Structure

```
internal/
├── common/
│   ├── plugin/
│   │   ├── plugin.go       # Plugin interface
│   │   ├── registry.go     # Plugin registry
│   │   └── loader.go       # Dynamic plugin loader
│   ├── events/
│   │   ├── event.go        # Event types
│   │   ├── bus.go          # Event bus interface
│   │   ├── memory_bus.go   # In-memory implementation
│   │   └── redis_bus.go    # Redis-backed implementation
│   ├── container/
│   │   ├── container.go    # DI container interface
│   │   └── simple.go       # Simple container implementation
│   ├── repository/
│   │   ├── repository.go   # Generic repository interface
│   │   ├── postgres.go     # PostgreSQL implementation
│   │   └── cached.go       # Cache-wrapped repository
│   ├── handlers/
│   │   ├── decorator.go    # Handler decorators
│   │   └── response.go     # Standard response helpers
│   └── provider/
│       ├── provider.go     # Provider interface
│       ├── mfa.go          # MFA provider interface
│       ├── sms.go          # SMS provider interface
│       └── email.go        # Email provider interface
```

---

## Migration Guide

### Phase 1: Core Infrastructure (Week 1)
1. Implement Plugin Registry
2. Implement Event Bus
3. Implement Service Container

### Phase 2: Refactor Services (Week 2)
1. Extract repositories from services
2. Convert to plugin-based architecture
3. Add event publishing to key operations

### Phase 3: Provider Abstraction (Week 3)
1. Standardize MFA providers
2. Standardize notification providers
3. Add provider health checks

### Phase 4: Handler Improvements (Week 4)
1. Implement handler decorators
2. Add middleware registry
3. Standardize error handling

---

## Example: Adding a New MFA Provider

With the new architecture, adding a new MFA provider is simple:

```go
// 1. Implement the interface
type BiometricMFAProvider struct {
    config BiometricConfig
}

func (p *BiometricMFAProvider) Name() string { return "biometric" }
func (p *BiometricMFAProvider) Type() ProviderType { return MFAProviderType }

func (p *BiometricMFAProvider) Challenge(ctx context.Context, user *User) (*Challenge, error) {
    // Generate biometric challenge
}

func (p *BiometricMFAProvider) Verify(ctx context.Context, challenge *Challenge, response string) (bool, error) {
    // Verify biometric response
}

// 2. Register the plugin
func init() {
    plugin.Register("mfa-biometric", &BiometricMFAProvider{})
}

// 3. Configure in config.yaml
mfa:
  providers:
    - name: biometric
      enabled: true
      config:
        timeout: 30s
```

---

## Benefits

| Benefit | Description |
|---------|-------------|
| **Modularity** | Each component is self-contained and testable |
| **Extensibility** | Add new features without modifying core code |
| **Testability** | Easy to mock interfaces for unit tests |
| **Maintainability** | Clear boundaries between components |
| **Scalability** | Components can be deployed independently |
| **Flexibility** | Swap implementations at runtime |

---

## Conclusion

By implementing these patterns, OpenIDX will become a truly modular platform where:

- New MFA methods can be added as plugins
- New identity providers can be registered dynamically
- Events flow through a central bus for loose coupling
- Services are composed from reusable building blocks
- Configuration is validated and type-safe
- Testing is simplified with clear interfaces

The goal is to make OpenIDX like **Lego blocks** - each piece fits together cleanly, and you can build whatever you need by combining the right pieces.
