# Audit Service API

Base URL: `http://localhost:8004`

The Audit Service provides event logging, compliance reporting, and data export.

## Audit Events

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/audit/events` | List events (filtered, paginated) |
| POST | `/api/v1/audit/events` | Log an event |
| GET | `/api/v1/audit/events/:id` | Get event details |

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
