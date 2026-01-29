# Provisioning Service API (SCIM 2.0)

Base URL: `http://localhost:8003`

The Provisioning Service implements SCIM 2.0 (RFC 7643/7644) for automated user and group lifecycle management.

## SCIM Users

| Method | Path | Description |
|--------|------|-------------|
| GET | `/scim/v2/Users` | List users |
| POST | `/scim/v2/Users` | Create user |
| GET | `/scim/v2/Users/:id` | Get user |
| PUT | `/scim/v2/Users/:id` | Replace user |
| PATCH | `/scim/v2/Users/:id` | Patch user |
| DELETE | `/scim/v2/Users/:id` | Delete user |

Content type: `application/scim+json`

### Filtering

```
GET /scim/v2/Users?filter=userName eq "john"&startIndex=1&count=20
```

## SCIM Groups

| Method | Path | Description |
|--------|------|-------------|
| GET | `/scim/v2/Groups` | List groups |
| POST | `/scim/v2/Groups` | Create group |
| GET | `/scim/v2/Groups/:id` | Get group |
| PUT | `/scim/v2/Groups/:id` | Replace group |
| PATCH | `/scim/v2/Groups/:id` | Patch group |
| DELETE | `/scim/v2/Groups/:id` | Delete group |

## SCIM Discovery

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/scim/v2/Schemas` | List schemas | None |
| GET | `/scim/v2/Schemas/:id` | Get schema | None |
| GET | `/scim/v2/ResourceTypes` | List resource types | None |
| GET | `/scim/v2/ServiceProviderConfig` | Provider capabilities | None |

## Provisioning Rules

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/provisioning/rules` | List rules |
| POST | `/api/v1/provisioning/rules` | Create rule |
| GET | `/api/v1/provisioning/rules/:id` | Get rule |
| PUT | `/api/v1/provisioning/rules/:id` | Update rule |
| DELETE | `/api/v1/provisioning/rules/:id` | Delete rule |

### Rule Triggers

- `user_created` — When a new user is provisioned
- `user_updated` — When user attributes change
- `user_deleted` — When a user is deprovisioned
- `group_membership` — When group membership changes
- `attribute_change` — When specific attributes change
- `scheduled` — Time-based triggers
