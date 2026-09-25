# SCIM 2.0 Provisioning - OpenIDX

## What is SCIM 2.0?

**SCIM (System for Cross-domain Identity Management) 2.0** is an open standard that makes it easier to automate the exchange of user identity information between IT systems.

### Key Benefits

✅ **Automated Provisioning** - Automatically create user accounts across applications
✅ **Deprovisioning** - Remove access when users leave
✅ **Synchronization** - Keep user data consistent everywhere
✅ **Standard Protocol** - Works with Okta, Azure AD, OneLogin, and more
✅ **Less manual work** - Joiner, mover and leaver changes stop being tickets

## Use Cases

### 1. HR System → OpenIDX
When HR hires a new employee, SCIM automatically:
- Creates the user account in OpenIDX
- Sets up email and profile information
- Assigns appropriate groups/roles
- Provisions access to all applications

### 2. OpenIDX → Applications
When a user is created in OpenIDX, SCIM automatically:
- Provisions accounts to Slack, GitHub, AWS, etc.
- Syncs profile changes to all applications
- Grants role-based access

### 3. Offboarding
When an employee leaves:
- SCIM deactivates accounts everywhere
- Removes group memberships
- Revokes application access
- Maintains audit trail

## Architecture

```
┌─────────────┐
│   HR System │
│  (Workday)  │
└──────┬──────┘
       │ SCIM 2.0
       │ Push/Sync
┌──────▼──────────────────────┐
│      OpenIDX                │
│  (Identity Provider)        │
└──────┬──────────────────────┘
       │ SCIM 2.0
       │ Provision
       ├─────────────┬──────────────┬──────────────┐
       │             │              │              │
┌──────▼──────┐ ┌───▼───┐   ┌─────▼─────┐ ┌─────▼─────┐
│    Slack    │ │GitHub │   │    AWS    │ │  Salesforce│
└─────────────┘ └───────┘   └───────────┘ └───────────┘
```

## SCIM 2.0 Endpoints

### Service Discovery

```bash
# Get SCIM capabilities
GET /scim/v2/ServiceProviderConfig

# Get resource types
GET /scim/v2/ResourceTypes

# Get schemas
GET /scim/v2/Schemas
```

`/ServiceProviderConfig` states only what the server does:

| Feature | Supported |
| --- | --- |
| `patch` | yes |
| `filter` | yes, `maxResults` 200 (see [Filtering](#filtering)) |
| `bulk` | no |
| `sort` | no (`sortBy` is ignored) |
| `etag` | no (no `ETag` header, no `meta.version`, `If-Match` is not checked) |
| `changePassword` | no (a `password` attribute is not read) |
| authentication | OAuth 2.0 bearer token issued by OpenIDX |

`/ResourceTypes` answers a `ListResponse` of the User and Group resource types,
and `/ResourceTypes/User` and `/ResourceTypes/Group` answer one each.

### Protocol behavior

- Every response has the media type `application/scim+json`. Requests may use
  `application/scim+json` or `application/json`.
- `POST` answers `201 Created` with a `Location` header and the stored
  resource. `meta.location` is the same URI.
- `DELETE` answers `204 No Content` with no body.
- An unknown id, or an id that is not a UUID, answers `404` for every method.
- A `userName`, email or group `displayName` already in use answers
  `409` with `scimType` `uniqueness`.
- A body that is not JSON answers `400` with `scimType` `invalidSyntax`.
- `externalId` is stored for Users and Groups and returned as sent.
- A user created without `active` is active. A `PUT` without `active` keeps the
  current value.
- A group `PUT` without `members` removes every member. A group `PATCH` changes
  members only when one of its operations names `members`.
- `GET /Groups?excludedAttributes=members` lists groups without their members.

### User Management

```bash
# List users
GET /scim/v2/Users?startIndex=1&count=100

# Create user
POST /scim/v2/Users
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "john.doe@example.com",
  "name": {
    "givenName": "John",
    "familyName": "Doe"
  },
  "emails": [{
    "value": "john.doe@example.com",
    "type": "work",
    "primary": true
  }],
  "active": true
}

# Get user
GET /scim/v2/Users/{id}

# Update user (replace)
PUT /scim/v2/Users/{id}

# Update user (partial)
PATCH /scim/v2/Users/{id}
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "replace",
      "path": "active",
      "value": false
    }
  ]
}

# Delete user
DELETE /scim/v2/Users/{id}
```

### Group Management

```bash
# List groups
GET /scim/v2/Groups?startIndex=1&count=100

# Create group
POST /scim/v2/Groups
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "displayName": "Engineering Team",
  "members": []
}

# Get group
GET /scim/v2/Groups/{id}

# Update group
PUT /scim/v2/Groups/{id}

# Add members to group
PATCH /scim/v2/Groups/{id}
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "add",
      "path": "members",
      "value": [
        {
          "value": "user-id-123",
          "type": "User"
        }
      ]
    }
  ]
}

# Delete group
DELETE /scim/v2/Groups/{id}
```

## SCIM User Schema

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "uuid",
  "externalId": "external-system-id",
  "userName": "john.doe@example.com",
  "name": {
    "formatted": "John Doe",
    "familyName": "Doe",
    "givenName": "John",
    "middleName": "M",
    "honorificPrefix": "Mr.",
    "honorificSuffix": "Jr."
  },
  "displayName": "John Doe",
  "emails": [
    {
      "value": "john.doe@example.com",
      "type": "work",
      "primary": true
    }
  ],
  "active": true,
  "groups": [
    {
      "value": "group-id-123",
      "display": "Engineering"
    }
  ],
  "meta": {
    "resourceType": "User",
    "created": "2026-01-15T10:00:00Z",
    "lastModified": "2026-01-17T14:30:00Z",
    "location": "/scim/v2/Users/uuid"
  }
}
```

## SCIM Group Schema

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "id": "group-uuid",
  "displayName": "Engineering Team",
  "members": [
    {
      "value": "user-id-1",
      "display": "John Doe",
      "type": "User"
    },
    {
      "value": "user-id-2",
      "display": "Jane Smith",
      "type": "User"
    }
  ],
  "meta": {
    "resourceType": "Group",
    "created": "2026-01-15T10:00:00Z",
    "lastModified": "2026-01-17T14:30:00Z"
  }
}
```

## PATCH Operations

SCIM supports three PATCH operations. The `op` value is not case-sensitive, so
`Replace` (as Microsoft Entra ID sends it) works. An operation without a
`path` applies its `value` object attribute by attribute.

The paths this server supports are:

| Resource | Paths |
| --- | --- |
| Users | `active`, `userName`, `displayName`, `externalId`, `name`, `name.givenName`, `name.familyName`, `emails`, `emails[type eq "work"].value` (any type) |
| Groups | `displayName`, `externalId`, `members`, `members[value eq "<id>"]` (remove only) |

`active` accepts a JSON boolean or the strings `"True"` and `"False"`, which
Microsoft Entra ID sends. Any other path answers `400` with `scimType`
`invalidPath`. A value of the wrong type answers `400` with `invalidValue`,
and a `remove` without a path answers `400` with `noTarget`. The server
does not answer `200` to a change it did not make.

The operations in one request apply in order. If any operation is refused, the
request changes nothing, including the operations before the refused one.

### 1. Add
Adds a new value to an attribute.

```json
{
  "op": "add",
  "path": "emails",
  "value": [{
    "value": "john.secondary@example.com",
    "type": "personal"
  }]
}
```

### 2. Replace
Replaces an existing attribute value.

```json
{
  "op": "replace",
  "path": "active",
  "value": false
}
```

### 3. Remove
Removes an attribute value.

```json
{
  "op": "remove",
  "path": "emails",
  "value": [{
    "value": "old.email@example.com"
  }]
}
```

## Query Parameters

### Pagination

```bash
# Get users with pagination
GET /scim/v2/Users?startIndex=1&count=50
```

- `startIndex`: 1-based index of the first result (default: 1). A value
  below 1 is treated as 1.
- `count`: Maximum number of results to return (default: 100, at most 200). A
  negative value is treated as 0, which returns only `totalResults`.

A value that is not an integer answers `400` with `scimType` `invalidValue`.

### Filtering

One filter form is supported: a single equality test on one attribute, with a
double-quoted value.

```bash
# Filter users by username
GET /scim/v2/Users?filter=userName eq "john.doe@example.com"

# Filter users by external ID (Entra ID / Okta existence checks)
GET /scim/v2/Users?filter=externalId eq "00u1a2b3c4d5"

# Filter groups by display name
GET /scim/v2/Groups?filter=displayName eq "Engineering"
```

The only operator is `eq`. The attribute must be one of the filterable
attributes below; the value must be in double quotes (`"`), not single quotes.

| Resource | Filterable attributes | Matching |
| --- | --- | --- |
| Users | `userName`, `email`, `emails.value`, `externalId` | case-insensitive except `externalId` |
| Groups | `displayName`, `externalId` | case-insensitive except `externalId` |

Anything else — `ne`, `co`, `sw`, `ew`, `gt`, `lt`, `pr`, an `and`/`or`/`not`
composition, parentheses, or an attribute outside the table — is answered with
**400 `invalidFilter`**. That is deliberate, and it is the safer of the two
behaviours available: an identity provider issues
`GET /Users?filter=userName eq "x"` as an existence check before it creates or
deprovisions an account, so a filter the server quietly ignored would return the
whole page and let the IdP conclude the user is absent (creating a duplicate) or
present (skipping a deprovision). A loud 400 is a configuration error somebody
fixes; a silent superset is an account that outlives an employee.

This is enough for the provisioning flows Okta and Microsoft Entra ID actually
perform. If you need a richer filter, open an issue describing the IdP and the
exact expression it sends rather than assuming an operator works: every filter
expression printed in this documentation is checked against the parser by
`TestEveryDocumentedSCIMFilterIsOneTheProductAccepts`, so what is written here
is what the server answers.

## Error Responses

SCIM uses standard HTTP status codes and error responses:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "400",
  "scimType": "invalidValue",
  "detail": "Invalid email address format"
}
```

The SCIM error types this server answers with:
- `invalidFilter` - the filter is not one the server supports (400)
- `invalidPath` - the PATCH path is not one the server supports (400)
- `invalidValue` - a value is missing or of the wrong type (400)
- `invalidSyntax` - the request body is not a SCIM resource (400)
- `noTarget` - a PATCH `remove` has no path (400)
- `uniqueness` - `userName`, email or group `displayName` is already in use (409)

`404` and `500` responses carry the same envelope without a `scimType`. A
`401` from the bearer-token check is a plain JSON `{"error": "..."}` object,
not a SCIM error envelope.

## Integration Examples

### Okta Integration

1. In Okta Admin Console:
   - Go to Applications → Add Application
   - Select SCIM 2.0 Test App (OAuth Bearer Token)
   - Set SCIM Base URL: `https://openidx.example.com/scim/v2`
   - Set OAuth Bearer Token

2. Configure provisioning:
   - Enable Create Users
   - Enable Update User Attributes
   - Enable Deactivate Users

### Azure AD Integration

1. In Azure Portal:
   - Go to Enterprise Applications → New Application
   - Select "Non-gallery application"
   - Go to Provisioning → Set provisioning mode to Automatic

2. Configure:
   - Tenant URL: `https://openidx.example.com/scim/v2`
   - Secret Token: Your OAuth token
   - Test Connection

### OneLogin Integration

1. In OneLogin Admin Portal:
   - Applications → Add App
   - Search for "SCIM"
   - Select "SCIM Provisioner with SAML"

2. Configure:
   - SCIM Base URL: `https://openidx.example.com/scim/v2`
   - SCIM Bearer Token: Your token

## Testing

### Compliance tests

`internal/provisioning/scim_compliance_testdb_test.go` tests the SCIM server
against RFC 7643 and RFC 7644. It runs the real routes, including the
bearer-token middleware, against a migrated PostgreSQL, and runs in the
`internal/provisioning` job of the unit test matrix. The requests use the
shapes Microsoft Entra ID and Okta send.

| Test | What it checks |
| --- | --- |
| `TestSCIMServerDiscoveryIsRFC7644` | `/ServiceProviderConfig` claims only what the server does; `/ResourceTypes` and `/Schemas` are RFC 7644 §4 responses; a request with no token, or a token signed by another key, is refused |
| `TestSCIMServerUsersAreRFC7644` | create (201, `Location`, the stored representation), read, replace, delete (204, then 404); 404 for unknown ids; 409 `uniqueness`; 400 for bodies it cannot store; every PATCH form in the table above, including Entra's string booleans and refusals with `invalidPath`, `invalidValue` and `noTarget` |
| `TestSCIMServerFilteringAndPagination` | each supported filter matches exactly the right users; an unsupported filter is `invalidFilter`; paging visits every user exactly once; `startIndex` and `count` are clamped as RFC 7644 §3.4.2.4 says |
| `TestSCIMServerGroupsAreRFC7644` | group create with members, read, list, filter, member add, remove by value and by `members[value eq "..."]`, replace, and delete; deleting a user removes it from its groups; no `ETag` or `meta.version` is sent, because none is claimed |
| `TestSCIMOutboundProvisionsToATarget` | outbound provisioning to a mock target; see [Outbound SCIM Provisioning](OUTBOUND_SCIM.md#tests) |

### Interoperability

These tests reproduce the request shapes of Microsoft Entra ID and Okta. They
are not a certification run against either service, and CI does not use a live
identity provider.

## Security

- SCIM endpoints require an OAuth 2.0 bearer token issued by OpenIDX.
- Requests are scoped to the caller's tenant.
- Serve SCIM over TLS only.

## Best Practices

1. **Always use pagination** - Don't retrieve all users at once
2. **Use PATCH for updates** - More efficient than PUT
3. **Handle rate limits** - Implement exponential backoff
4. **Log all operations** - Maintain audit trail
5. **Test in sandbox** - Verify integration before production
6. **Monitor sync errors** - Set up alerts for failures
7. **Use filters** - Reduce data transfer

## Monitoring

Key metrics to track:
- SCIM operation success rate
- Average response time
- Number of provisioned users
- Sync failures
- API rate limit hits

## Support

For SCIM integration support:
- 💬 Questions: [GitHub Discussions](https://github.com/mhmtgngr/openidx/discussions)
- 🐛 Bugs: [GitHub Issues](https://github.com/mhmtgngr/openidx/issues)
- What to expect: [SUPPORT.md](https://github.com/mhmtgngr/openidx/blob/main/SUPPORT.md)

## Standards implemented

OpenIDX implements the parts of RFC 7643 (SCIM Core Schema) and RFC 7644
(SCIM Protocol) described on this page: the User and Group resources, the
discovery endpoints, create, read, replace, PATCH and delete, `eq` filtering on
the attributes listed under [Filtering](#filtering), and pagination. It does
not implement bulk operations, sorting, ETags, `/Me`, or password change. The
compliance tests above check each supported part, and the
[maturity matrix](https://github.com/mhmtgngr/openidx#feature-maturity) has
the current level.

---

**Ready to automate your user provisioning?** 🚀

Start with the test script or integrate with your identity provider today!
