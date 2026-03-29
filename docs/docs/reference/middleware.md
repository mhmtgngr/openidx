# middleware

`import "github.com/openidx/openidx/internal/common/middleware"`

Package middleware provides reusable Gin HTTP middleware for authentication, rate limiting, security headers, CSRF protection, request validation, and structured logging.

## Authentication (JWT / JWKS)

```go
type JWKSKey struct { Kid, Kty, Alg, Use, N, E string }
type JWKS struct { Keys []JWKSKey }
```

JWT validation fetches RSA public keys from the configured JWKS endpoint. Keys are cached globally with a 1-hour TTL and refreshed automatically on cache miss.

## Rate Limiting

```go
type RateLimitConfig struct {
    Requests int; Window time.Duration          // Default tier
    AuthRequests int; AuthWindow time.Duration  // Stricter tier for auth paths
    PerUser bool                                // Track per-user limits when user_id is in context
}

func DistributedRateLimit(redisClient *redis.Client, cfg RateLimitConfig, logger *zap.Logger) gin.HandlerFunc
```

Uses Redis sliding window counters. Auth-sensitive paths (`/oauth/login`, `/oauth/token`, etc.) receive a stricter limit. Health, metrics, and readiness endpoints are exempt. Fails open if Redis is unavailable.

## Security Headers

```go
type SecurityConfig struct {
    HSTSEnabled, CSPEnabled bool
    FrameOptions string  // "DENY", "SAMEORIGIN", or "ALLOW-FROM <uri>"
    CSPCustom string
}

func DefaultSecurityConfig() SecurityConfig
func SecurityHeaders(cfg SecurityConfig) gin.HandlerFunc
```

Sets `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, and `Permissions-Policy` headers. HSTS and CSP are opt-in via configuration.

## CSRF Protection

```go
type CSRFConfig struct { Enabled bool; TrustedDomain string; SessionCookieNames []string }
func CSRFProtection(cfg CSRFConfig, logger *zap.Logger) gin.HandlerFunc
```

Validates `Origin`/`Referer` headers on state-changing requests that include cookie-based sessions. Bearer-token-only requests are not affected.

## Request Validation

```go
type JSONSchema struct {
    Type string; Required []string; Properties map[string]*JSONSchema
    MinLength, MaxLength *int; Minimum, Maximum *float64
    Pattern, Format string; Enum []interface{}
}
type ValidationRule struct { Required bool; Validators []Validator }
type ValidationError struct { Field, Message string; Value interface{} }
type ValidationErrors struct { Errors []ValidationError }
```

## Structured Logging

```go
type LoggingConfig struct {
    LogBody, LogQueryParams bool
    SanitizeFields []string; MinDuration time.Duration
    EnableTracing bool
}
var DefaultSanitizedFields []string  // "password", "token", "secret", "api_key", etc.
```

Sensitive fields listed in `SanitizeFields` are automatically redacted from logged request bodies and query parameters.
