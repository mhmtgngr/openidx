# OpenIDX OpenAPI 3.0 Documentation

This directory contains comprehensive OpenAPI 3.0 specifications for all OpenIDX Zero Trust Access Platform services.

## Available Specifications

### Individual Service Specifications

Each service has its own OpenAPI specification file:

| File | Service | Port | Description |
|------|---------|------|-------------|
| `identity-service.yaml` | Identity Service | 8001 | User, group, role, MFA, and identity provider management |
| `governance-service.yaml` | Governance Service | 8002 | Access reviews, certification campaigns, and policy management |
| `provisioning-service.yaml` | Provisioning Service | 8003 | SCIM 2.0 user and group provisioning, plus automation rules |
| `audit-service.yaml` | Audit Service | 8004 | Audit event logging, compliance reporting, and export |
| `admin-api.yaml` | Admin API | 8005 | Dashboard, system settings, application management, directory integrations |
| `oauth-service.yaml` | OAuth/OIDC Service | 8006 | OAuth 2.0 authorization server with OpenID Connect and SAML 2.0 support |
| `access-service.yaml` | Access Service | 8007 | Zero Trust access proxy with route management, session control, OpenZiti network overlay |
| `portal-service.yaml` | Self-Service Portal | 8001 | Self-service portal for application access and group membership requests |
| `notifications-service.yaml` | Notifications Service | 8001 | User notification management and preferences |
| `organization-service.yaml` | Organization Service | 8005 | Organization and member management |

### Consolidated Specification

`openidx.yaml` provides a unified view of all services with cross-references to individual service specifications.

## Using the Specifications

### Viewing the Documentation

1. **Swagger UI**: Copy any `.yaml` file content to [editor.swagger.io](https://editor.swagger.io/) to view interactive documentation
2. **Redoc**: Use [redocly.com](https://redocly.com/) for beautiful API documentation
3. **VS Code**: Install the "OpenAPI (Swagger) Editor" extension

### Validating the Specifications

```bash
# Using npm (if installed)
npm install -g @apidevtools/swagger-cli
swagger-cli validate path/to/service.yaml

# Using Docker
docker run --rm -v ${PWD}:/work -w /work openapitools/openapi-style-cli validate path/to/service.yaml
```

### Generating Client SDKs

```bash
# Using OpenAPI Generator
docker run --rm -v ${PWD}:/local -w /local openapitools/openapi-generator-cli generate \
  -i path/to/service.yaml \
  -g python \
  -o ./generated/python
```

## Authentication

Most endpoints require Bearer token authentication using JWT tokens issued by the OAuth Service:

```
Authorization: Bearer <your-jwt-token>
```

### Public Endpoints

The following endpoints do not require authentication:
- Password reset: `POST /api/v1/identity/users/forgot-password`
- Email verification: `POST /api/v1/identity/verify-email`
- Invitation acceptance: `POST /api/v1/identity/invitations/{token}/accept`
- Login branding: `GET /api/v1/identity/branding`
- OIDC Discovery: `GET /.well-known/openid-configuration`
- JWKS: `GET /.well-known/jwks.json`

## API Response Format

All API responses follow this standard format:

### Success Response
```json
{
  "data": { ... },
  "meta": {
    "total": 100,
    "page": 1,
    "per_page": 20
  }
}
```

### Error Response
```json
{
  "error": "error_code",
  "message": "Human-readable error message",
  "status": 400,
  "details": { ... }
}
```

## Pagination

List endpoints support pagination via query parameters:

- `offset`: Starting index (default: 0)
- `limit`: Number of items to return (default: 20, max: 100)

The total count is returned in the `X-Total-Count` response header.

## Rate Limiting

All endpoints are subject to rate limiting. Rate limit headers are included in responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 99
X-RateLimit-Reset: 1640995200
```

## Service Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     API Gateway (APISIX)                        │
└─────────────────────────────────────────────────────────────────┘
                                │
    ┌───────────────────────────┼───────────────────────┐
    │                           │                       │
┌───▼───┐  ┌───────▼───────┐  ┌───▼───┐  ┌───────▼─────┐
│Identity│  │  Governance  │  │Provis-│  │    Audit   │
│Service │  │   Service    │  │ioning │  │   Service  │
└────────┘  └──────────────┘  └───────┘  └────────────┘
    │               │              │             │
    └───────────────┼──────────────┴─────────────┘
                    │
         ┌──────────▼──────────┐
         │  Policy Engine (OPA)│
         └─────────────────────┘
                    │
    ┌───────────────┼───────────────┐
    │               │               │
┌───▼───┐     ┌─────▼─────┐   ┌─────▼─────┐
│Postgres│    │   Redis   │   │Elasticsearch│
└────────┘    └───────────┘   └────────────┘
```

## Common Data Types

### UUID Format
All resource IDs use UUID v4 format:
```
550e8400-e29b-41d4-a716-446655440000
```

### Date-Time Format
All timestamps use ISO 8601 format in UTC:
```
2024-01-15T10:30:00Z
```

## Support

For questions or issues with the API documentation, please open an issue on [GitHub](https://github.com/openidx/openidx/issues).
