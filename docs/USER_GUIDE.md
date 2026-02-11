# OpenIDX User Guide

A practical guide to testing and using OpenIDX - the open-source Zero Trust Access Platform.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Admin Console Overview](#admin-console-overview)
3. [User Management](#user-management)
4. [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
5. [Applications & SSO](#applications--sso)
6. [Access Policies](#access-policies)
7. [Zero Trust Network Access (ZTNA)](#zero-trust-network-access-ztna)
8. [Session Management](#session-management)
9. [Audit & Compliance](#audit--compliance)
10. [API Examples](#api-examples)

---

## Getting Started

### Prerequisites

- Docker and Docker Compose installed
- Modern web browser (Chrome, Firefox, Edge)
- For ZTNA testing: OpenZiti client or BrowZer

### Starting OpenIDX

```bash
cd openidx/deployments/docker
docker compose up -d
```

### Default URLs

| Service | URL | Description |
|---------|-----|-------------|
| Admin Console | http://localhost:3000 | Web UI for administration |
| API Gateway | http://localhost:8088 | Main API endpoint |
| OAuth Server | http://localhost:8006 | OAuth/OIDC endpoints |
| OAuth (TLS) | https://oauth.localtest.me:8446 | HTTPS OAuth for BrowZer |
| BrowZer | https://browzer.localtest.me | Zero Trust browser access |

### Default Admin Credentials

```
Email: admin@openidx.local
Password: Admin123!
```

---

## Admin Console Overview

### Logging In

1. Open http://localhost:3000
2. Enter admin credentials
3. You'll see the Dashboard with system overview

### Navigation Sections

- **Dashboard** - System health and statistics
- **Identity** - Users, Groups, Roles, Service Accounts
- **Applications** - OAuth clients, Identity Providers
- **Network & Access** - Proxy Routes, Ziti Network, Devices
- **Governance** - Policies, Access Reviews, Sessions
- **Security & MFA** - Risk Policies, Hardware Tokens, MFA Settings
- **Audit & Reports** - Audit Logs, Analytics, Compliance

---

## User Management

### Create a New User

1. Navigate to **Identity > Users**
2. Click **Add User**
3. Fill in the form:
   ```
   Email: testuser@example.com
   First Name: Test
   Last Name: User
   Password: TestUser123!
   ```
4. Click **Create**

### Try It - API Example

```bash
# Create user via API
curl -X POST http://localhost:8088/api/v1/identity/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "email": "apiuser@example.com",
    "first_name": "API",
    "last_name": "User",
    "password": "ApiUser123!"
  }'

# List all users
curl http://localhost:8088/api/v1/identity/users \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Create a Group

1. Navigate to **Identity > Groups**
2. Click **Add Group**
3. Enter:
   ```
   Name: Engineering
   Description: Engineering team members
   ```
4. Click **Create**
5. Click the group, then **Add Members** to add users

### Assign Roles

1. Navigate to **Identity > Roles**
2. View existing roles or create new ones
3. Roles control what users can do in the system

---

## Multi-Factor Authentication (MFA)

### Enable TOTP (Authenticator App)

1. Log in as the test user
2. Go to **My Profile** (click avatar > My Profile)
3. Find **Two-Factor Authentication** section
4. Click **Set Up TOTP**
5. Scan QR code with Google Authenticator, Authy, or similar
6. Enter the 6-digit code to verify
7. Save your backup codes!

### Test MFA Login

1. Log out
2. Log in with username/password
3. You'll be prompted for the TOTP code
4. Enter the code from your authenticator app

### WebAuthn/Passkey Setup

1. Go to **My Profile**
2. Find **Security Keys** section
3. Click **Register Security Key**
4. Follow browser prompts (touch your YubiKey or use fingerprint)
5. Name the key (e.g., "My YubiKey")

### Try It - MFA API

```bash
# Check MFA status
curl http://localhost:8088/api/v1/identity/users/me/mfa \
  -H "Authorization: Bearer YOUR_TOKEN"

# Start TOTP setup
curl -X POST http://localhost:8088/api/v1/identity/users/me/mfa/totp/setup \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Applications & SSO

### Register an OAuth Application

1. Navigate to **Applications > Applications**
2. Click **Add Application**
3. Fill in:
   ```
   Name: My Test App
   Type: Web Application
   Redirect URIs: http://localhost:8080/callback
   Grant Types: authorization_code, refresh_token
   ```
4. Save the **Client ID** and **Client Secret**

### Test OAuth Flow

```bash
# 1. Open in browser - Authorization request
open "http://localhost:8006/oauth/authorize?client_id=YOUR_CLIENT_ID&response_type=code&redirect_uri=http://localhost:8080/callback&scope=openid%20profile%20email"

# 2. After login, you'll get a code in the redirect URL
# 3. Exchange code for tokens
curl -X POST http://localhost:8006/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_HERE" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "redirect_uri=http://localhost:8080/callback"
```

### Configure External Identity Provider

1. Navigate to **Applications > Identity Providers**
2. Click **Add Provider**
3. For Google:
   ```
   Name: Google
   Type: OIDC
   Issuer URL: https://accounts.google.com
   Client ID: (from Google Console)
   Client Secret: (from Google Console)
   ```

---

## Access Policies

### Create an Access Policy

1. Navigate to **Governance > Policies**
2. Click **Add Policy**
3. Example - Require MFA for Admin Access:
   ```
   Name: Admin MFA Required
   Description: Admins must use MFA
   Resource: admin/*
   Effect: Allow
   Conditions:
     - mfa_verified = true
     - role contains "admin"
   ```

### Create a Risk Policy

1. Navigate to **Security & MFA > Risk Policies**
2. Click **Add Policy**
3. Example - Block High Risk Logins:
   ```
   Name: Block Impossible Travel
   Priority: 10
   Conditions:
     - impossible_travel: true
   Actions:
     - deny: true
     - notify_admin: true
   ```

### Try It - Policy API

```bash
# List policies
curl http://localhost:8088/api/v1/governance/policies \
  -H "Authorization: Bearer YOUR_TOKEN"

# Create policy
curl -X POST http://localhost:8088/api/v1/governance/policies \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "name": "Test Policy",
    "description": "Test access policy",
    "resource": "api/*",
    "effect": "allow",
    "conditions": {"authenticated": true}
  }'
```

---

## Zero Trust Network Access (ZTNA)

### Understanding Proxy Routes

Proxy routes allow secure access to internal applications without VPN.

### Create a Proxy Route

1. Navigate to **Network & Access > Proxy Routes**
2. Click **Add Route**
3. Example - Proxy to internal app:
   ```
   Name: Internal Dashboard
   Path Prefix: /internal
   Upstream URL: http://internal-app:8080
   Require Authentication: Yes
   Allowed Roles: ["employee", "admin"]
   ```

### Test with BrowZer (Zero Trust Browser)

1. Ensure BrowZer is running: `docker ps | grep browzer`
2. Open https://browzer.localtest.me
3. Log in with your OpenIDX credentials
4. Access internal services through the zero-trust overlay

### Ziti Network Management

1. Navigate to **Network & Access > Ziti Network**
2. View:
   - **Services** - Available Ziti services
   - **Identities** - Enrolled devices/users
   - **Policies** - Service access policies

---

## Session Management

### View Active Sessions

1. Navigate to **Governance > Sessions**
2. See all active user sessions with:
   - User info
   - Device/browser details
   - IP address and location
   - Risk score
   - Session duration

### Revoke a Session

1. Find the session in the list
2. Click the **Revoke** button
3. Enter a reason (optional)
4. Confirm

### Bulk Revoke User Sessions

1. Click **Revoke All** next to a user's session
2. This terminates all sessions for that user

### Try It - Session API

```bash
# List all sessions
curl http://localhost:8088/api/v1/sessions?active_only=true \
  -H "Authorization: Bearer YOUR_TOKEN"

# Revoke a session
curl -X DELETE http://localhost:8088/api/v1/sessions/SESSION_ID \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"reason": "Security concern"}'
```

---

## Audit & Compliance

### View Audit Logs

1. Navigate to **Audit & Reports > Audit Logs**
2. Filter by:
   - Date range
   - Event type (login, logout, user.created, etc.)
   - User
   - Resource

### Common Event Types

| Event | Description |
|-------|-------------|
| `user.login` | User logged in |
| `user.login.failed` | Failed login attempt |
| `user.logout` | User logged out |
| `user.created` | New user created |
| `user.updated` | User profile updated |
| `mfa.enabled` | MFA was enabled |
| `session.revoked` | Session was terminated |
| `policy.evaluated` | Access policy was checked |

### Login Analytics

1. Navigate to **Audit & Reports > Login Analytics**
2. View:
   - Login trends (daily/hourly)
   - Success/failure rates
   - Geographic distribution
   - Risk score distribution
   - Top failed login attempts

### Generate Compliance Report

1. Navigate to **Audit & Reports > Compliance**
2. Select report type:
   - SOC 2
   - GDPR
   - HIPAA
3. Set date range
4. Click **Generate**
5. Download PDF or view online

### Try It - Audit API

```bash
# Query audit logs
curl "http://localhost:8088/api/v1/audit/events?event_type=user.login&limit=10" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Get login analytics
curl "http://localhost:8088/api/v1/identity/analytics/logins?period=7d" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## API Examples

### Authentication

**Method 1: Client Credentials (for service-to-service)**

```bash
# Get service account token
curl -X POST http://localhost:8006/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=test-client" \
  -d "client_secret=test-secret" \
  -d "scope=openid"

# Response: {"access_token":"eyJ...", "token_type":"Bearer", "expires_in":3600}
```

**Method 2: User Token (via Admin Console)**

1. Open http://localhost:3000 in your browser
2. Log in with `admin@openidx.local` / `Admin123!`
3. Open DevTools (F12) > Application > Local Storage > http://localhost:3000
4. Copy the `token` value

**Method 3: Authorization Code Flow (standard OIDC)**

```bash
# 1. Open this URL in browser:
open "http://localhost:8006/oauth/authorize?client_id=admin-console&response_type=code&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20email&state=test123"

# 2. Log in and authorize
# 3. Get the 'code' from redirect URL
# 4. Exchange for token:
curl -X POST http://localhost:8006/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTH_CODE" \
  -d "client_id=admin-console" \
  -d "redirect_uri=http://localhost:3000/callback"
```

**Using the Token**

```bash
export TOKEN="eyJhbGciOiJS..."
curl http://localhost:8088/api/v1/identity/users/me \
  -H "Authorization: Bearer $TOKEN"
```

### User CRUD Operations

```bash
# Create user
curl -X POST http://localhost:8088/api/v1/identity/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"new@example.com","first_name":"New","last_name":"User","password":"Password123!"}'

# Get user
curl http://localhost:8088/api/v1/identity/users/USER_ID \
  -H "Authorization: Bearer $TOKEN"

# Update user
curl -X PUT http://localhost:8088/api/v1/identity/users/USER_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"first_name":"Updated"}'

# Delete user
curl -X DELETE http://localhost:8088/api/v1/identity/users/USER_ID \
  -H "Authorization: Bearer $TOKEN"
```

### Group Management

```bash
# Create group
curl -X POST http://localhost:8088/api/v1/identity/groups \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Developers","description":"Development team"}'

# Add user to group
curl -X POST http://localhost:8088/api/v1/identity/groups/GROUP_ID/members \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"USER_ID"}'
```

### Access Reviews

```bash
# Create access review
curl -X POST http://localhost:8088/api/v1/governance/reviews \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q1 Access Review",
    "description": "Quarterly access certification",
    "scope": "all_users",
    "due_date": "2024-03-31"
  }'

# List reviews
curl http://localhost:8088/api/v1/governance/reviews \
  -H "Authorization: Bearer $TOKEN"
```

---

## Troubleshooting

### Common Issues

**Can't log in:**
- Check credentials
- Ensure services are running: `docker ps`
- Check logs: `docker logs openidx-identity-service`

**401 Unauthorized on API:**
- Token may be expired - get a new one
- Check if endpoint requires admin role

**500 Internal Server Error:**
- Check service logs: `docker logs openidx-<service-name>`
- Database may need migrations

**BrowZer not working:**
- Restart TLS proxy: `docker restart openidx-oauth-tls-proxy`
- Check BrowZer logs: `docker logs openidx-browzer-bootstrapper`

### Useful Commands

```bash
# View all logs
docker compose logs -f

# Restart all services
docker compose restart

# Reset database (warning: deletes data)
docker compose down -v
docker compose up -d

# Check service health
docker ps --format "table {{.Names}}\t{{.Status}}"
```

---

## Quick Test Checklist

- [ ] Log in to admin console
- [ ] Create a test user
- [ ] Create a group and add user
- [ ] Enable TOTP MFA for test user
- [ ] Log in as test user with MFA
- [ ] Create an OAuth application
- [ ] Test OAuth authorization flow
- [ ] Create an access policy
- [ ] View audit logs
- [ ] Check login analytics
- [ ] Test session revocation
- [ ] (Optional) Test BrowZer access

---

## Support

- GitHub Issues: https://github.com/openidx/openidx/issues
- Documentation: https://docs.openidx.io

