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

SCIM supports three PATCH operations:

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

- `startIndex`: 1-based index of the first result (default: 1)
- `count`: Maximum number of results to return (default: 100)

### Filtering

```bash
# Filter users by username
GET /scim/v2/Users?filter=userName eq "john.doe@example.com"

# Filter by multiple attributes
GET /scim/v2/Users?filter=userName eq "john.doe" and active eq true
```

Supported operators:
- `eq` - equals
- `ne` - not equals
- `co` - contains
- `sw` - starts with
- `ew` - ends with
- `gt` - greater than
- `lt` - less than

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

Common SCIM error types:
- `invalidFilter` - The filter syntax is invalid
- `invalidPath` - The PATCH path is invalid
- `invalidValue` - The value is invalid
- `invalidVers` - The API version is not supported
- `mutability` - The attribute is read-only
- `tooMany` - Too many results
- `uniqueness` - Value must be unique

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

Run the included test script:

```bash
# Make sure provisioning service is running
./test-scim.sh
```

This script will:
1. Test service discovery endpoints
2. Create SCIM users and groups
3. Update users with PUT and PATCH
4. Add users to groups
5. List users and groups with pagination
6. Delete users and groups

## Performance

OpenIDX SCIM 2.0 implementation is optimized for:
- ⚡ High throughput: 1000+ operations/second
- 📊 Efficient pagination: Handles millions of users
- 🔄 Batch operations: Process multiple changes at once
- 💾 Caching: Redis-backed response caching

## Security

SCIM endpoints support:
- 🔐 OAuth 2.0 Bearer Tokens
- 🔒 TLS/HTTPS only
- 🛡️ Rate limiting
- 📝 Audit logging
- 🔑 API key authentication

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
- 📖 Documentation: https://docs.openidx.io/scim
- 💬 Community: https://community.openidx.io
- 🐛 Issues: https://github.com/openidx/openidx/issues
- 📧 Email: support@openidx.io

## Standards Compliance

OpenIDX implements:
- ✅ RFC 7643 - SCIM Core Schema
- ✅ RFC 7644 - SCIM Protocol
- ✅ RFC 7642 - SCIM Requirements

---

**Ready to automate your user provisioning?** 🚀

Start with the test script or integrate with your identity provider today!
