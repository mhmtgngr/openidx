# Prometheus Metrics for OpenIDX

This package provides comprehensive Prometheus metrics collection for all OpenIDX services.

## Available Metrics

### HTTP Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `openidx_http_requests_total` | Counter | service, method, path, status | Total HTTP requests |
| `openidx_http_request_duration_seconds` | Histogram | service, method, path | Request latency |
| `openidx_http_requests_in_flight` | Gauge | service | Requests currently being processed |
| `openidx_http_response_size_bytes` | Histogram | service, method, path | Response size |
| `openidx_http_errors_total` | Counter | service, method, path, status_code | Error responses (4xx/5xx) |

### Runtime Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `openidx_process_goroutines` | Gauge | service | Number of goroutines |
| `openidx_process_memory_bytes` | Gauge | service, type | Memory usage (heap, stack, sys) |
| `openidx_process_gc_stats` | Gauge | service, stat | GC statistics |

### Database Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `openidx_db_query_duration_seconds` | Histogram | service, operation, table | Query duration |
| `openidx_db_connections` | Gauge | service, state | Connection pool stats |
| `openidx_cache_operations_total` | Counter | service, operation, outcome | Cache hits/misses |

### Business Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `openidx_business_users_total` | Gauge | service | Total users |
| `openidx_business_active_users` | Gauge | service | Active users |
| `openidx_business_mfa_enrollments` | Gauge | service, method | MFA enrollments |
| `openidx_business_failed_logins_total` | Counter | service, reason | Failed logins |
| `openidx_business_successful_logins_total` | Counter | service, method | Successful logins |
| `openidx_business_access_reviews_total` | Gauge | service, status | Access reviews |
| `openidx_business_audit_events_total` | Counter | service, event_type | Audit events |
| `openidx_business_policy_violations_total` | Counter | service, policy_type, severity | Policy violations |

### Authentication & Security Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `openidx_auth_attempts_total` | Counter | method, outcome | Auth attempts |
| `openidx_active_sessions` | Gauge | service | Active sessions |
| `openidx_token_operations_total` | Counter | operation, outcome | Token operations |
| `openidx_mfa_verifications_total` | Counter | method, outcome | MFA attempts |
| `openidx_mfa_challenge_duration_seconds` | Histogram | method | MFA completion time |
| `openidx_risk_score` | Histogram | service, decision | Risk scores |

## Usage

### Basic HTTP Metrics Middleware

```go
import "github.com/openidx/openidx/internal/metrics"

// In your service main.go
router := gin.New()
router.Use(metrics.Middleware("identity-service"))
router.GET("/metrics", metrics.Handler())
```

### Database Metrics

```go
import "github.com/openidx/openidx/internal/metrics"

// Wrap your database pool
tracedDB := metrics.NewTracedPool(pool, "identity-service")
tracedDB.StartPoolStatsCollector(ctx)

// Use tracedDB instead of pool for queries
```

### Cache Metrics

```go
import "github.com/openidx/openidx/internal/metrics"

// Wrap your Redis client
tracedRedis := metrics.NewTracedRedisClient(redis.Client, "identity-service")

// Use tracedRedis for all Redis operations
```

### Service-Specific Metrics

#### Identity Service

```go
import "github.com/openidx/openidx/internal/metrics"

collector := metrics.NewIdentityMetricsCollector("identity-service", db, redis)
collector.Start(ctx)

// Record events
collector.RecordLoginAttempt(true, "password", "")
collector.RecordMFALogin("totp", true, time.Second*2)
collector.RecordSessionCreated()
```

#### OAuth Service

```go
import "github.com/openidx/openidx/internal/metrics"

collector := metrics.NewOAuthMetricsCollector("oauth-service", db)
collector.Start(ctx)

// Record events
collector.RecordTokenIssued(metrics.GrantTypeAuthorizationCode)
collector.RecordAuthorizationApproved()
```

#### Governance Service

```go
import "github.com/openidx/openidx/internal/metrics"

collector := metrics.NewGovernanceMetricsCollector("governance-service", db)
collector.Start(ctx)

// Record events
collector.RecordAccessReviewCreated("user_access")
collector.RecordReviewDecision("approve")
```

#### Audit Service

```go
import "github.com/openidx/openidx/internal/metrics"

collector := metrics.NewAuditMetricsCollector("audit-service", db)
collector.Start(ctx)

// Record events
collector.RecordAuditEvent(metrics.EventTypeUserLogin)
collector.RecordComplianceReportGenerated("sox", true, time.Minute*5)
```

## Querying Metrics in Prometheus

### Request rate by service
```promql
rate(openidx_http_requests_total[5m])
```

### Error rate by service
```promql
rate(openidx_http_errors_total[5m])
```

### P95 latency
```promql
histogram_quantile(0.95, rate(openidx_http_request_duration_seconds_bucket[5m]))
```

### Active sessions
```promql
openidx_active_sessions
```

### Failed login rate
```promql
rate(openidx_business_failed_logins_total[5m])
```

### MFA verification success rate
```promql
rate(openidx_mfa_verifications_total{outcome="success"}[5m]) /
rate(openidx_mfa_verifications_total[5m])
```

## Grafana Dashboard

Key panels to include:
1. Request rate and error rate by service
2. P50, P95, P99 latency by endpoint
3. Database query duration by operation
4. Cache hit rate
5. Active sessions and goroutines
6. Memory usage and GC stats
7. Login success/failure rates
8. MFA verification rates
