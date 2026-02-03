# OpenIDX Design Pattern Examples

This document shows how to use the design patterns implemented in OpenIDX.

## Table of Contents

1. [Plugin Registry](#plugin-registry)
2. [Event Bus](#event-bus)
3. [Service Container](#service-container)
4. [Handler Decorators](#handler-decorators)
5. [Middleware Registry](#middleware-registry)
6. [Provider Interfaces](#provider-interfaces)
7. [Putting It All Together](#putting-it-all-together)

---

## Plugin Registry

The plugin registry allows dynamic registration of components.

### Creating a Plugin

```go
package myplugin

import (
    "context"
    "github.com/openidx/openidx/internal/common/plugin"
)

type MyMFAPlugin struct {
    config map[string]interface{}
}

func (p *MyMFAPlugin) Name() string    { return "my-mfa" }
func (p *MyMFAPlugin) Version() string { return "1.0.0" }
func (p *MyMFAPlugin) Type() plugin.PluginType { return plugin.PluginTypeMFA }

func (p *MyMFAPlugin) Init(ctx context.Context, config map[string]interface{}) error {
    p.config = config
    // Initialize your plugin
    return nil
}

func (p *MyMFAPlugin) Start(ctx context.Context) error {
    // Start any background workers
    return nil
}

func (p *MyMFAPlugin) Stop(ctx context.Context) error {
    // Clean shutdown
    return nil
}

func (p *MyMFAPlugin) Health() plugin.HealthStatus {
    return plugin.HealthStatus{
        Healthy: true,
        Message: "Plugin is running",
    }
}
```

### Registering and Using Plugins

```go
package main

import (
    "context"
    "github.com/openidx/openidx/internal/common/plugin"
)

func main() {
    // Create registry
    registry := plugin.NewRegistry()

    // Register plugin
    registry.Register(&MyMFAPlugin{})

    // Or use factory for lazy loading
    registry.RegisterFactory("lazy-mfa", func() plugin.Plugin {
        return &MyMFAPlugin{}
    })

    // Initialize with config
    ctx := context.Background()
    registry.Init(ctx, "my-mfa", map[string]interface{}{
        "timeout": "30s",
        "retries": 3,
    })

    // Start plugin
    registry.Start(ctx, "my-mfa")

    // Get plugin
    p, _ := registry.Get("my-mfa")

    // Get all MFA plugins
    mfaPlugins := registry.GetByType(plugin.PluginTypeMFA)

    // Lifecycle hooks
    registry.OnInit(func(ctx context.Context, p plugin.Plugin) error {
        log.Printf("Initializing plugin: %s", p.Name())
        return nil
    })

    // Stop all when done
    defer registry.StopAll(ctx)
}
```

---

## Event Bus

The event bus enables loose coupling through publish/subscribe.

### Publishing Events

```go
package identity

import (
    "context"
    "github.com/openidx/openidx/internal/common/events"
)

func (s *Service) CreateUser(ctx context.Context, user *User) error {
    // Create user in database
    if err := s.db.CreateUser(user); err != nil {
        return err
    }

    // Publish event (async - doesn't block)
    events.PublishAsync(ctx, events.NewEvent(
        events.EventUserCreated,
        "identity-service",
        map[string]interface{}{
            "user_id": user.ID,
            "email":   user.Email,
        },
    ).WithUserID(user.ID))

    return nil
}
```

### Subscribing to Events

```go
package notifications

import (
    "context"
    "github.com/openidx/openidx/internal/common/events"
)

func SetupEventHandlers(emailService *EmailService) {
    // Subscribe to user created events
    events.Subscribe(events.EventUserCreated, func(ctx context.Context, e events.Event) error {
        email := e.Payload["email"].(string)
        return emailService.SendWelcomeEmail(ctx, email)
    })

    // Subscribe to all login events with filter
    events.Global().SubscribeWithFilter(
        events.EventUserLogin,
        func(ctx context.Context, e events.Event) error {
            // Log suspicious logins
            return logSuspiciousLogin(ctx, e)
        },
        func(e events.Event) bool {
            // Only handle high-risk logins
            riskScore, _ := e.Payload["risk_score"].(int)
            return riskScore > 70
        },
    )

    // Subscribe to all events for audit
    events.SubscribeAll(func(ctx context.Context, e events.Event) error {
        return auditLogger.Log(e)
    })
}
```

---

## Service Container

The container manages dependency injection.

### Registering Services

```go
package main

import (
    "github.com/openidx/openidx/internal/common/container"
    "github.com/openidx/openidx/internal/common/database"
    "github.com/openidx/openidx/internal/identity"
)

func main() {
    c := container.NewBuilder().
        // Register database (singleton)
        Register("database", func(c container.Container) (interface{}, error) {
            return database.NewPostgres(cfg.DatabaseURL)
        }).
        // Register cache (singleton)
        Register("cache", func(c container.Container) (interface{}, error) {
            return database.NewRedis(cfg.RedisURL)
        }).
        // Register identity service with dependencies
        Register("identity", func(c container.Container) (interface{}, error) {
            db := c.MustResolve("database").(*database.PostgresDB)
            cache := c.MustResolve("cache").(*database.RedisClient)
            return identity.NewService(db, cache, cfg, logger), nil
        }).
        // Register with tags for discovery
        Register("email-sender", func(c container.Container) (interface{}, error) {
            return email.NewSMTPSender(cfg.SMTP)
        }, container.WithTags("notification", "email")).
        MustBuild()

    // Resolve services
    identitySvc := c.MustResolve("identity").(*identity.Service)

    // Resolve by tag
    notifiers, _ := c.ResolveByTag("notification")

    // Create scoped container for request
    requestScope := c.CreateScope()
    defer requestScope.Close()
}
```

---

## Handler Decorators

Decorators add cross-cutting concerns to handlers.

### Basic Usage

```go
package api

import (
    "github.com/gin-gonic/gin"
    "github.com/openidx/openidx/internal/common/handlers"
)

func SetupRoutes(router *gin.Engine, svc *Service, logger *zap.Logger) {
    // Simple decoration
    router.GET("/users", handlers.Decorate(
        svc.handleListUsers,
        handlers.WithLogging(logger),
        handlers.WithMetrics("list_users"),
    ))

    // Chain multiple decorators
    secureHandler := handlers.Chain(
        handlers.WithRecovery(logger),
        handlers.WithLogging(logger),
        handlers.WithMetrics("create_user"),
        handlers.WithRateLimit(handlers.NewSimpleRateLimiter(100, time.Minute)),
        handlers.WithRoles("admin"),
    )

    router.POST("/users", secureHandler(svc.handleCreateUser))

    // Use preset chains
    router.GET("/profile", handlers.Decorate(
        svc.handleGetProfile,
        handlers.StandardAPI(logger, "get_profile"),
    ))

    router.DELETE("/users/:id", handlers.Decorate(
        svc.handleDeleteUser,
        handlers.AdminAPI(logger, "delete_user"),
    ))
}
```

### Custom Decorators

```go
// Custom decorator for tenant isolation
func WithTenant(tenantResolver func(*gin.Context) string) handlers.Decorator {
    return func(handler gin.HandlerFunc) gin.HandlerFunc {
        return func(c *gin.Context) {
            tenant := tenantResolver(c)
            if tenant == "" {
                c.JSON(400, gin.H{"error": "tenant required"})
                c.Abort()
                return
            }
            c.Set("tenant_id", tenant)
            handler(c)
        }
    }
}

// Usage
router.GET("/data", handlers.Decorate(
    svc.handleGetData,
    WithTenant(func(c *gin.Context) string {
        return c.GetHeader("X-Tenant-ID")
    }),
    handlers.WithLogging(logger),
))
```

---

## Middleware Registry

The middleware registry manages middleware composition.

### Setup

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/openidx/openidx/internal/common/middleware"
)

func setupMiddleware(router *gin.Engine, cfg *Config) {
    // Create registry
    mw := middleware.NewBuilder()

    // Add middlewares with priorities
    mw.Use("recovery", gin.Recovery(),
        middleware.WithPriority(middleware.PriorityRecovery))

    mw.Use("security", middleware.SecurityHeaders(cfg.IsProduction),
        middleware.WithPriority(middleware.PrioritySecurity))

    mw.Use("logging", logger.GinMiddleware(log),
        middleware.WithPriority(middleware.PriorityLogging))

    mw.Use("metrics", middleware.PrometheusMetrics("api"),
        middleware.WithPriority(middleware.PriorityMetrics))

    // Conditional middleware
    mw.UseIf("rate-limit", rateLimitMiddleware,
        middleware.NotPublic,  // Don't rate limit public endpoints
        middleware.WithPriority(middleware.PriorityRateLimit))

    mw.UseIf("auth", middleware.Auth(cfg.JWKSURL),
        middleware.NotPublic,
        middleware.WithPriority(middleware.PriorityAuth))

    // Group-specific middleware
    mw.Use("admin-only", adminMiddleware,
        middleware.WithGroups("admin"),
        middleware.WithPriority(middleware.PriorityAuthorization))

    // Apply to router
    mw.Apply(router)

    // Or apply to specific groups
    adminGroup := router.Group("/admin")
    mw.Build().ApplyToGroup(adminGroup, "admin")
}
```

### Dynamic Middleware Control

```go
// Disable middleware at runtime
registry := middleware.GlobalRegistry()
registry.Disable("rate-limit")  // Disable rate limiting
registry.Enable("rate-limit")   // Re-enable

// Change priority
registry.SetPriority("logging", middleware.PriorityFirst)

// List all middlewares
for _, entry := range registry.List() {
    fmt.Printf("%s: priority=%d enabled=%v\n",
        entry.Name, entry.Priority, entry.Enabled)
}
```

---

## Provider Interfaces

Providers enable swappable implementations.

### Implementing an SMS Provider

```go
package sms

import (
    "context"
    "github.com/openidx/openidx/internal/common/provider"
)

type TwilioProvider struct {
    client *twilio.Client
}

func (p *TwilioProvider) Name() string { return "twilio" }
func (p *TwilioProvider) Type() provider.ProviderType { return provider.ProviderTypeSMS }

func (p *TwilioProvider) Configure(config map[string]interface{}) error {
    accountSid := config["account_sid"].(string)
    authToken := config["auth_token"].(string)
    p.client = twilio.NewClient(accountSid, authToken)
    return nil
}

func (p *TwilioProvider) Health(ctx context.Context) provider.HealthStatus {
    // Check Twilio API
    start := time.Now()
    _, err := p.client.Account.Get()
    return provider.HealthStatus{
        Healthy:     err == nil,
        Latency:     time.Since(start),
        LastChecked: time.Now(),
    }
}

func (p *TwilioProvider) Send(ctx context.Context, msg provider.SMSMessage) (*provider.SMSResult, error) {
    result, err := p.client.Messages.Create(&twilio.MessageParams{
        To:   msg.To,
        From: msg.From,
        Body: msg.Body,
    })
    if err != nil {
        return nil, err
    }
    return &provider.SMSResult{
        MessageID: result.Sid,
        Status:    result.Status,
    }, nil
}

func (p *TwilioProvider) SendOTP(ctx context.Context, phone, code string) (*provider.SMSResult, error) {
    return p.Send(ctx, provider.SMSMessage{
        To:   phone,
        Body: fmt.Sprintf("Your verification code is: %s", code),
    })
}
```

### Using Providers

```go
package main

import (
    "github.com/openidx/openidx/internal/common/provider"
    "github.com/openidx/openidx/internal/sms"
)

func main() {
    // Register providers
    provider.Register(&sms.TwilioProvider{})
    provider.Register(&sms.AWSProvider{})

    // Configure provider
    twilioProvider := provider.GetSMS("twilio")
    twilioProvider.Configure(map[string]interface{}{
        "account_sid": os.Getenv("TWILIO_ACCOUNT_SID"),
        "auth_token":  os.Getenv("TWILIO_AUTH_TOKEN"),
    })

    // Use provider
    result, err := twilioProvider.SendOTP(ctx, "+1234567890", "123456")

    // Health check all providers
    health := provider.Global().Health(ctx)
    for name, status := range health {
        log.Printf("%s: healthy=%v latency=%v", name, status.Healthy, status.Latency)
    }
}
```

---

## Putting It All Together

Here's how to bootstrap an application using all patterns:

```go
package main

import (
    "context"
    "github.com/gin-gonic/gin"
    "github.com/openidx/openidx/internal/common/container"
    "github.com/openidx/openidx/internal/common/events"
    "github.com/openidx/openidx/internal/common/handlers"
    "github.com/openidx/openidx/internal/common/middleware"
    "github.com/openidx/openidx/internal/common/plugin"
    "github.com/openidx/openidx/internal/common/provider"
)

func main() {
    ctx := context.Background()

    // 1. Setup event bus
    eventBus := events.NewMemoryBus()
    events.SetGlobalBus(eventBus)

    // 2. Setup DI container
    c := container.NewBuilder().
        RegisterInstance("config", cfg).
        Register("database", newDatabase).
        Register("cache", newCache).
        Register("identity", newIdentityService).
        Register("audit", newAuditService).
        MustBuild()

    // 3. Register plugins
    pluginRegistry := plugin.NewRegistry()
    pluginRegistry.Register(&TOTPPlugin{})
    pluginRegistry.Register(&WebAuthnPlugin{})
    pluginRegistry.Register(&SMSPlugin{})

    pluginRegistry.InitAll(ctx, map[string]map[string]interface{}{
        "totp":     {"issuer": "OpenIDX"},
        "webauthn": {"rpID": "localhost"},
        "sms":      {"provider": "twilio"},
    })
    pluginRegistry.StartAll(ctx)
    defer pluginRegistry.StopAll(ctx)

    // 4. Register providers
    provider.Register(&sms.TwilioProvider{})
    provider.Register(&email.SMTPProvider{})

    // 5. Setup event handlers
    events.Subscribe(events.EventUserCreated, handleUserCreated)
    events.Subscribe(events.EventUserLogin, handleUserLogin)
    events.Subscribe(events.EventSecurityAlert, handleSecurityAlert)

    // 6. Setup router with middleware
    router := gin.New()

    mw := middleware.NewBuilder().
        Use("recovery", gin.Recovery(), middleware.WithPriority(10)).
        Use("logging", logMiddleware, middleware.WithPriority(20)).
        Use("metrics", metricsMiddleware, middleware.WithPriority(30)).
        UseIf("auth", authMiddleware, middleware.NotPublic, middleware.WithPriority(50)).
        Build()

    mw.Apply(router)

    // 7. Register routes with decorators
    identitySvc := c.MustResolve("identity").(*identity.Service)

    api := router.Group("/api/v1")
    {
        // Public endpoints
        api.POST("/login", identitySvc.handleLogin)

        // Protected endpoints with decorators
        api.GET("/users", handlers.Decorate(
            identitySvc.handleListUsers,
            handlers.StandardAPI(logger, "list_users"),
        ))

        api.POST("/users", handlers.Decorate(
            identitySvc.handleCreateUser,
            handlers.AdminAPI(logger, "create_user"),
        ))
    }

    // 8. Start server
    router.Run(":8080")
}

// Event handlers
func handleUserCreated(ctx context.Context, e events.Event) error {
    // Send welcome email
    emailProvider := provider.GetEmail("smtp")
    return emailProvider.SendTemplate(ctx, "welcome",
        []string{e.Payload["email"].(string)},
        e.Payload)
}

func handleUserLogin(ctx context.Context, e events.Event) error {
    // Log to audit
    auditSvc := container.MustResolve("audit").(*audit.Service)
    return auditSvc.Log(ctx, e)
}

func handleSecurityAlert(ctx context.Context, e events.Event) error {
    // Send alert notification
    return notifyAdmins(ctx, e)
}
```

---

## Summary

These patterns make OpenIDX:

| Pattern | Benefit |
|---------|---------|
| **Plugin Registry** | Add new features without code changes |
| **Event Bus** | Decouple components, async processing |
| **Service Container** | Manage dependencies cleanly |
| **Handler Decorators** | Add behaviors without modifying handlers |
| **Middleware Registry** | Compose middleware flexibly |
| **Provider Interfaces** | Swap implementations easily |

Together, they create a **Lego-like architecture** where:

- Components are self-contained
- Dependencies are explicit
- Extensions are plug-and-play
- Testing is straightforward
- Configuration is centralized
