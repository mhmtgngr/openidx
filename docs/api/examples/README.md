# OpenIDX API Examples

This directory contains code examples for interacting with the OpenIDX API in various programming languages.

## Available Examples

| Language | File | Description |
|----------|------|-------------|
| **cURL** | `curl.sh` | Shell script examples using curl for API requests |
| **JavaScript/TypeScript** | `javascript.ts` | Browser and Node.js examples with full client library |
| **Python** | `python.py` | Python client with both sync and async support |
| **Go** | `go.go` | Go client with type-safe structs and contexts |

## Quick Start

### Authentication

All examples start with obtaining an OAuth 2.0 access token:

```bash
# cURL
curl -X POST http://localhost:8006/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "your_client_id",
    "client_secret": "your_client_secret"
  }'
```

### Making Requests

Once authenticated, include the access token in the Authorization header:

```bash
curl -X GET http://localhost:8001/api/v1/identity/users \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Service Endpoints

| Service | Base URL | Port | Description |
|---------|----------|------|-------------|
| Identity Service | `/api/v1/identity` | 8001 | User, group, and role management |
| OAuth Service | `/oauth` | 8006 | OAuth 2.0 authorization server |
| Governance Service | `/api/v1/governance` | 8002 | Access reviews and policies |
| Provisioning Service | `/scim/v2` | 8003 | SCIM 2.0 provisioning |
| Audit Service | `/api/v1/audit` | 8004 | Audit logs and reporting |
| Admin API | `/api/v1` | 8005 | Dashboard and settings |
| Access Service | `/api/v1/access` | 8007 | Zero Trust access proxy |

## Common Operations

### List Users

- **cURL**: See `curl.sh` - `List Users` section
- **JavaScript**: `identity.listUsers({ limit: 10 })`
- **Python**: `identity.list_users(limit=10)`
- **Go**: `client.ListUsers(ctx, 0, 10)`

### Create User

- **cURL**: See `curl.sh` - `Create User` section
- **JavaScript**: `identity.createUser(userData)`
- **Python**: `identity.create_user(userData)`
- **Go**: `client.CreateUser(ctx, &CreateUserRequest{...})`

### Query Audit Events

- **cURL**: See `curl.sh` - `Audit Service` section
- **JavaScript**: `audit.queryEvents({ limit: 50 })`
- **Python**: `audit.query_events(limit=50)`
- **Go**: `audit.QueryEvents(ctx, &QueryEventsParams{...})`

## SCIM 2.0 Examples

The provisioning service supports SCIM 2.0 for user provisioning:

### Create SCIM User

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "user@example.com",
  "name": {
    "givenName": "John",
    "familyName": "Doe"
  },
  "emails": [{
    "primary": true,
    "value": "user@example.com",
    "type": "work"
  }],
  "active": true
}
```

### Update SCIM User (PATCH)

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{
    "op": "replace",
    "path": "active",
    "value": false
  }]
}
```

## Error Handling

All API errors follow this format:

```json
{
  "error": "error_code",
  "message": "Human-readable error message",
  "status": 400,
  "details": {}
}
```

## Rate Limiting

API responses include rate limit headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 99
X-RateLimit-Reset: 1640995200
```

## Pagination

List endpoints support pagination via query parameters:

| Parameter | Default | Max | Description |
|-----------|---------|-----|-------------|
| `offset` | 0 | - | Starting index |
| `limit` | 20 | 100 | Items per page |
| `count` (SCIM) | 100 | - | SCIM count parameter |
| `startIndex` (SCIM) | 1 | - | SCIM start index |

## Support

For more information, see:
- [Main Documentation](../)
- [OpenAPI Specifications](../../api/openapi/)
- [GitHub Issues](https://github.com/openidx/openidx/issues)
