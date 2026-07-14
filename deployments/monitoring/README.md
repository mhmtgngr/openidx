# OpenIDX observability

Roadmap item #8. The services already export **metrics** and emit **traces** —
this directory adds the collection/alerting side so you can *see* it.

## What's already in the code (no change needed)
- **RED metrics** on every service via `metrics.Middleware` → `openidx_http_requests_total{service,method,path,status}`, `openidx_http_request_duration_seconds` (histogram), `openidx_http_errors_total`, `openidx_http_requests_in_flight`.
- **Process/runtime gauges**: `openidx_process_goroutines`, `openidx_process_memory_bytes`, GC stats.
- **DB pool gauges** (activated by this change): `openidx_db_connections{service,state}` where `state` ∈ `total|idle|acquired|acquire_count|max` — started via `StartPoolStatsCollector` in each DB-backed service's `main`.
- **Tracing**: OTLP gRPC export is wired (`tracing.Init` in every service); it's a no-op until `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
- Every service serves `GET /metrics`.

## Stand it up
```bash
podman compose -f deployments/monitoring/docker-compose.yml up -d
# Prometheus  → http://127.0.0.1:9090   (scrapes :8001-8008/metrics + APISIX)
# Grafana     → http://127.0.0.1:3001   (add Prometheus http://127.0.0.1:9090 as a datasource)
# OTel        → gRPC 127.0.0.1:4317     (receives traces)
```

## Activate tracing
Set on the services (common.env for :8001-8006/8008, run-access.sh for :8007) and restart:
```
OTEL_EXPORTER_OTLP_ENDPOINT=127.0.0.1:4317
```
A slow request's trace then shows *which* hop hurt (OPA / Guacamole / Ziti / DB).

## SLO alerts (`alerts.yml`)
| Alert | Fires when |
|-------|-----------|
| `OpenIDXServiceDown` | a service's scrape fails > 2m |
| `OpenIDXHighErrorRate` | > 5% 5xx over 5m (per service) |
| `OpenIDXHighLatencyP99` | p99 request latency > 1s over 10m |
| `OpenIDXDBPoolSaturation` | in-use conns > 80% of the pool max (ties to roadmap #9) |
| `OpenIDXGoroutineLeak` | > 5000 goroutines for 15m |

Wire alerts to a receiver (Alertmanager / webhook) as a follow-up. Tune the
thresholds once you've watched a week of baseline.

> Note: the **DB pool gauges** require the services to be running the build that
> includes this change (they start the collector at boot). Metrics/RED and
> tracing were already present.
