# API Reference

OpenIDX exposes REST APIs across 6 services. All APIs use JSON and follow consistent conventions.

## Authentication

Most endpoints require a Bearer token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

Obtain tokens via the [OAuth/OIDC Service](oauth.md).

Public endpoints (health checks, OIDC discovery, SCIM discovery) do not require authentication.

## Common Patterns

### Pagination

List endpoints support offset-based pagination:

```
GET /api/v1/identity/users?offset=0&limit=20
```

The total count is returned in the `X-Total-Count` response header.

### Error Responses

Errors return a JSON object with an `error` field:

```json
{
  "error": "resource not found"
}
```

Standard HTTP status codes are used:

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 204 | No Content (successful delete) |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 409 | Conflict |
| 429 | Rate Limited |
| 500 | Internal Server Error |

### Health Checks

Every service exposes:

- `GET /health` — Liveness check (always responds if the process is running)
- `GET /ready` — Readiness check (verifies database connectivity)
- `GET /metrics` — Prometheus metrics

## OpenAPI Specifications

Machine-readable OpenAPI 3.0 specs are available in the repository:

```
api/openapi/
├── identity-service.yaml
├── governance-service.yaml
├── provisioning-service.yaml
├── audit-service.yaml
├── admin-api.yaml
└── oauth-service.yaml
```

## Services

| Service | Base URL | Documentation |
|---------|----------|---------------|
| Identity | `http://localhost:8001` | [Identity Service](identity.md) |
| OAuth/OIDC | `http://localhost:8006` | [OAuth/OIDC](oauth.md) |
| Governance | `http://localhost:8002` | [Governance](governance.md) |
| Provisioning | `http://localhost:8003` | [Provisioning (SCIM)](provisioning.md) |
| Audit | `http://localhost:8004` | [Audit](audit.md) |
| Admin | `http://localhost:8005` | [Admin API](admin.md) |
