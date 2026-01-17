# SCIM 2.0 Features in OpenIDX Interface

## Overview

SCIM (System for Cross-domain Identity Management) 2.0 is integrated into OpenIDX for automated user and group provisioning. This document shows where to find and use SCIM features in the interface.

## Where Are SCIM Features?

### 1. **Users Page** - SCIM User Provisioning

**Location:** Admin Console → Users

**SCIM Capabilities:**
- All user CRUD operations are SCIM-compatible
- Users created via the Admin Console are automatically available via SCIM API
- SCIM clients (Okta, Azure AD, OneLogin) can sync users

**How It Works:**
```
Admin Console UI → Identity Service → SCIM 2.0 Provisioning Service
                                              ↓
                                    Dual-write to:
                                    - users table (OpenIDX)
                                    - scim_users table (SCIM metadata)
```

**API Endpoints Used:**
- `POST /scim/v2/Users` - Create user (SCIM)
- `GET /scim/v2/Users` - List users (SCIM)
- `GET /scim/v2/Users/{id}` - Get user details (SCIM)
- `PUT /scim/v2/Users/{id}` - Update user (SCIM)
- `PATCH /scim/v2/Users/{id}` - Partial update (SCIM)
- `DELETE /scim/v2/Users/{id}` - Delete user (SCIM)

### 2. **Groups Page** - SCIM Group Provisioning

**Location:** Admin Console → Groups

**SCIM Capabilities:**
- All group CRUD operations are SCIM-compatible
- Group membership management syncs with SCIM
- External identity providers can provision groups

**API Endpoints Used:**
- `POST /scim/v2/Groups` - Create group (SCIM)
- `GET /scim/v2/Groups` - List groups (SCIM)
- `GET /scim/v2/Groups/{id}` - Get group details (SCIM)
- `PUT /scim/v2/Groups/{id}` - Update group (SCIM)
- `PATCH /scim/v2/Groups/{id}` - Partial update (SCIM)
- `DELETE /scim/v2/Groups/{id}` - Delete group (SCIM)

### 3. **Applications Page** - SCIM Client Configuration

**Location:** Admin Console → Applications

**SCIM Integration:**
- Register external applications that will use SCIM
- Configure SCIM endpoint URLs for each application
- Manage OAuth credentials for SCIM authentication

**What You See:**
- Application list with SCIM-enabled apps
- Client ID for OAuth authentication
- Protocol: "OPENID-CONNECT" or "SCIM"

**To Configure SCIM:**
1. Navigate to Applications
2. Find your application (e.g., "Okta", "Azure AD")
3. Click on the application
4. Use the Client ID/Secret with SCIM base URL: `http://localhost:8003/scim/v2`

## SCIM Service Details

### Service Information
- **Service:** Provisioning Service
- **Port:** 8003
- **Base URL:** `http://localhost:8003`
- **SCIM Base:** `http://localhost:8003/scim/v2`
- **Binary:** `bin/provisioning-service` (21MB)

### SCIM Discovery Endpoint

```bash
curl http://localhost:8003/scim/v2/ServiceProviderConfig
```

**Response:**
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
  "documentationUri": "https://github.com/openidx/openidx/docs/SCIM.md",
  "patch": {"supported": true},
  "bulk": {"supported": false},
  "filter": {"supported": true, "maxResults": 200},
  "changePassword": {"supported": true},
  "sort": {"supported": true},
  "etag": {"supported": false},
  "authenticationSchemes": [
    {
      "type": "oauthbearertoken",
      "name": "OAuth Bearer Token",
      "description": "Authentication via OAuth 2.0 Bearer Token",
      "specUri": "http://www.rfc-editor.org/info/rfc6750"
    }
  ]
}
```

## How to Use SCIM from the UI

### Scenario 1: Manual User Creation (SCIM-Aware)

**Steps:**
1. Go to **Admin Console → Users**
2. Click **"Add User"**
3. Fill in user details:
   - Username (SCIM: userName)
   - Email (SCIM: emails[0].value)
   - First Name (SCIM: name.givenName)
   - Last Name (SCIM: name.familyName)
4. Click **"Create User"**

**Behind the Scenes:**
- User created in OpenIDX `users` table
- User metadata stored in `scim_users` table
- External SCIM clients can now discover this user via `GET /scim/v2/Users`

### Scenario 2: Configure SCIM for Okta

**Steps:**
1. Go to **Admin Console → Applications**
2. Click **"Register Application"**
3. Fill in:
   - **Name:** "Okta SCIM Integration"
   - **Type:** Service (Machine-to-Machine)
   - **Description:** "Okta provisioning via SCIM"
4. Click **"Register Application"**
5. Copy the **Client ID** and **Client Secret**

**Configure in Okta:**
1. Go to Okta → Applications → Your App
2. Provisioning → Configure API Integration
3. **SCIM Base URL:** `http://openidx.example.com:8003/scim/v2`
4. **Authentication Method:** OAuth Bearer Token
5. **OAuth Token Endpoint:** `http://openidx.example.com:8006/oauth/token`
6. **Client ID:** [From OpenIDX Applications]
7. **Client Secret:** [From OpenIDX Applications]
8. Test Connection → Enable Provisioning

### Scenario 3: View SCIM-Synced Users

**Steps:**
1. Go to **Admin Console → Users**
2. All users shown are SCIM-compatible
3. Look for users with `external_id` (synced from external IdP)

**How to Identify SCIM Users:**
- Users created by Okta/Azure AD have `external_id` populated
- These users appear in the UI just like manually created users
- No visual distinction (seamless integration)

## Testing SCIM Integration

### 1. Test User Creation via SCIM

```bash
curl -X POST http://localhost:8003/scim/v2/Users \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer {access_token}" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "scim.test@example.com",
    "name": {
      "givenName": "SCIM",
      "familyName": "Test"
    },
    "emails": [{
      "value": "scim.test@example.com",
      "type": "work",
      "primary": true
    }],
    "active": true
  }'
```

**Then check in UI:**
1. Go to Admin Console → Users
2. Search for "scim.test@example.com"
3. User appears in the list!

### 2. Test Group Creation via SCIM

```bash
curl -X POST http://localhost:8003/scim/v2/Groups \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer {access_token}" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "SCIM Test Group",
    "members": []
  }'
```

**Then check in UI:**
1. Go to Admin Console → Groups
2. "SCIM Test Group" appears in the list

## SCIM Features NOT in UI (API-Only)

Some advanced SCIM features are available via API but not exposed in the UI:

### 1. PATCH Operations
```bash
# Partial update user (API only)
curl -X PATCH http://localhost:8003/scim/v2/Users/{id} \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [{
      "op": "replace",
      "path": "active",
      "value": false
    }]
  }'
```

### 2. Bulk Operations
Currently not supported (coming soon)

### 3. Filtering and Searching
```bash
# Filter users by email (API only)
curl "http://localhost:8003/scim/v2/Users?filter=emails.value eq 'user@example.com'"

# Search users by name (API only)
curl "http://localhost:8003/scim/v2/Users?filter=name.givenName sw 'John'"
```

## Integration Diagram

```
┌──────────────────────┐
│  External IdP        │
│  (Okta, Azure AD)    │
└──────────┬───────────┘
           │ SCIM 2.0 API
           │
           ▼
┌──────────────────────┐
│  OpenIDX Provisioning│
│  Service (Port 8003) │
└──────────┬───────────┘
           │
           ├─────────────────┐
           │                 │
           ▼                 ▼
    ┌──────────────┐  ┌─────────────┐
    │ users table  │  │ scim_users  │
    │ (OpenIDX)    │  │ (SCIM meta) │
    └──────┬───────┘  └─────────────┘
           │
           │ Displayed in UI
           ▼
    ┌──────────────────┐
    │  Admin Console   │
    │  Users Page      │
    └──────────────────┘
```

## Key Points

✅ **Seamless Integration:** SCIM users appear in the UI just like regular users
✅ **Bi-Directional Sync:** Changes in UI propagate to SCIM, changes via SCIM API appear in UI
✅ **No Separate Interface:** SCIM features are integrated into existing Users/Groups pages
✅ **Standards Compliant:** Full SCIM 2.0 RFC compliance (RFC 7643, 7644)

## Where to Find More Information

- **Full SCIM Documentation:** `/docs/SCIM.md`
- **SCIM API Testing Script:** `/test-scim.sh`
- **Service Code:** `/internal/provisioning/service.go`
- **SCIM Spec:** https://datatracker.ietf.org/doc/html/rfc7644

## Common Questions

**Q: Do I need to enable SCIM separately?**
A: No! SCIM is always enabled. Every user/group operation supports SCIM.

**Q: How do I know if a user came from SCIM?**
A: Check the `external_id` field in the API response. UI doesn't distinguish them visually.

**Q: Can I disable SCIM?**
A: SCIM is part of the provisioning service. To disable, stop the provisioning-service.

**Q: Does SCIM work with the OAuth service?**
A: Yes! SCIM uses OAuth Bearer tokens for authentication.

**Q: Where do I configure SCIM endpoints for external apps?**
A: In the Applications page. Each registered app can use SCIM with its OAuth credentials.

---

**SCIM is fully integrated into OpenIDX!** There's no separate SCIM interface because SCIM functionality is built into the core user/group management system. 🚀
