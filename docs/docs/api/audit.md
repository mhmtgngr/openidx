# Audit Service API

Base URL: `http://localhost:8004`

The Audit Service provides event logging, compliance reporting, and data export.

## Who may read the trail

Every read, report, export, scheduled-report and stream route needs a role
that holds `audit:read` in `internal/auth/roles.go`: `super_admin`, `admin`,
`operator`, `auditor` or `compliance_reader`. Any other caller, including a
machine credential that holds none of them, gets 403 with
`"code": "audit_reader_required"`. The live stream (`GET /api/v1/audit/stream`)
applies the same rule to the token it is opened with. The webhook routes
need `admin` or `super_admin`; the ingest route below takes the internal
service token.

Outside production with no `OAUTH_JWKS_URL`, the service mounts no
authentication on these routes (it logs a warning at start-up) and the role
check is off with it. In production it refuses to start without one.

## Audit Events

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/audit/events` | List events (filtered, paginated) |
| POST | `/api/v1/audit/events` | Log an event (OpenIDX services only; see below) |
| GET | `/api/v1/audit/events/:id` | Get event details |

`POST /api/v1/audit/events` is how OpenIDX's own services write to the trail.
It needs the internal service token in `X-Internal-Token` (the value of
`INTERNAL_SERVICE_TOKEN`) and answers 401 without it, even to an
administrator's access token. The shipped edges (APISIX, the Helm ingress, the
lite install's nginx and the gateway service) do not route it at all.

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `event_type` | string | Filter by type |
| `category` | string | Filter by category |
| `outcome` | string | Filter by outcome |
| `actor_id` | string | Filter by actor |
| `target_id` | string | Filter by target |
| `start_time` | datetime | Start of time range |
| `end_time` | datetime | End of time range |
| `offset` | integer | Pagination offset (default: 0) |
| `limit` | integer | Page size (default: 50) |

### Event Types

`authentication`, `authorization`, `user_management`, `group_management`, `role_management`, `configuration`, `data_access`, `system`

### Categories

`security`, `compliance`, `operational`, `access`

### Outcomes

`success`, `failure`, `pending`

## Statistics

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/audit/statistics?period=30d` | Aggregated statistics |

Periods: `24h`, `7d`, `30d`, `90d`

## Compliance Reports

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/audit/reports` | List reports |
| POST | `/api/v1/audit/reports` | Generate report |
| GET | `/api/v1/audit/reports/:id` | Get report with findings |
| GET | `/api/v1/audit/reports/:id/download` | Download as PDF |

### Supported Frameworks

- `soc2` — SOC 2 Type II
- `iso27001` — ISO 27001
- `gdpr` — General Data Protection Regulation
- `hipaa` — Health Insurance Portability and Accountability Act
- `pci_dss` — Payment Card Industry Data Security Standard
- `custom` — Custom framework

## Export

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/audit/export` | Export events (CSV or JSON) |

## Webhook subscriptions

Where the organization's audit events are to be delivered. These routes need
the `admin` or `super_admin` role; any other caller gets `403`. A URL that
names or resolves to an internal address is refused with `400` unless an
operator allowed it with `OIDX_OUTBOUND_ALLOWLIST`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/audit/webhooks` | List the organization's subscriptions |
| POST | `/api/v1/audit/webhooks` | Register one (`url`, `secret`, `enabled`, `filters`) |
| DELETE | `/api/v1/audit/webhooks/:id` | Delete one |
| POST | `/api/v1/audit/webhooks/:id/test` | Send it a test event |
