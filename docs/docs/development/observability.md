# Observability

OpenIDX includes built-in observability with Prometheus metrics and Grafana dashboards.

## Metrics

Every service exposes a `/metrics` endpoint in Prometheus format. The metrics middleware (`internal/common/middleware/metrics.go`) automatically instruments all HTTP handlers.

### HTTP Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `openidx_http_requests_total` | Counter | service, method, path, status | Total HTTP requests |
| `openidx_http_request_duration_seconds` | Histogram | service, method, path | Request latency |
| `openidx_http_requests_in_flight` | Gauge | service | Concurrent requests |
| `openidx_http_response_size_bytes` | Histogram | service, method, path | Response body size |

### Auth Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `openidx_auth_attempts_total` | Counter | method, outcome | Authentication attempts |
| `openidx_active_sessions` | Gauge | service | Active user sessions |
| `openidx_token_operations_total` | Counter | operation, outcome | Token operations |

### Querying

```promql
# Request rate per service
sum(rate(openidx_http_requests_total[5m])) by (service)

# Error rate
sum(rate(openidx_http_requests_total{status=~"5.."}[5m]))
  /
sum(rate(openidx_http_requests_total[5m])) * 100

# P99 latency
histogram_quantile(0.99,
  sum(rate(openidx_http_request_duration_seconds_bucket[5m])) by (le)
)

# Auth failure rate
sum(rate(openidx_auth_attempts_total{outcome="failure"}[5m]))
```

## Prometheus

Prometheus scrapes all services every 15 seconds.

- **URL**: [http://localhost:9090](http://localhost:9090)
- **Config**: `deployments/docker/prometheus/prometheus.yml`

### Scrape Targets

| Job | Target |
|-----|--------|
| identity-service | `identity-service:8001` |
| governance-service | `governance-service:8002` |
| provisioning-service | `provisioning-service:8003` |
| audit-service | `audit-service:8004` |
| admin-api | `admin-api:8005` |
| oauth-service | `oauth-service:8006` |
| gateway-service | `gateway-service:8080` |

## Grafana

Grafana is pre-configured with Prometheus as a datasource and two dashboards.

- **URL**: [http://localhost:3001](http://localhost:3001)
- **Username**: `admin`
- **Password**: `GRAFANA_ADMIN_PASSWORD` from `.env`

### Dashboards

**OpenIDX Overview** — System-wide health:

- Total request rate and error rate
- Latency percentiles (P50, P95, P99)
- Per-service request rates and error rates
- In-flight requests and response sizes

**OpenIDX Auth Metrics** — Authentication focus:

- Auth attempts by method and outcome
- Token operations (issue, refresh, validate, revoke)
- Active session count
- OAuth and Identity service endpoint latency
- Error rates by endpoint

### Adding Custom Dashboards

Place JSON dashboard files in `deployments/docker/grafana/dashboards/`. They are auto-loaded by the provisioning configuration.
