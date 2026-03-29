# API Examples

Practical examples for common OpenIDX API operations.

## Setup

All examples assume:

```bash
export OPENIDX_BASE_URL="http://localhost:8006"  # OAuth Service
export IDENTITY_BASE_URL="http://localhost:8001"  # Identity Service
export ADMIN_BASE_URL="http://localhost:8005"     # Admin API
export AUDIT_BASE_URL="http://localhost:8004"     # Audit Service
export GOVERNANCE_BASE_URL="http://localhost:8002" # Governance Service
export PROVISIONING_BASE_URL="http://localhost:8003/scim/v2" # SCIM

# Your access token
export TOKEN="your-access-token"
```

## OAuth / OIDC Examples

### Register a New OAuth Client

```bash
curl -X POST "$ADMIN_BASE_URL/api/v1/applications" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Application",
    "redirect_uris": ["https://myapp.example.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scopes": ["openid", "profile", "email"],
    "token_endpoint_auth_method": "client_secret_post"
  }'
```

Response:

```json
{
  "id": "app-123",
  "client_id": "s6BhdRkqt3",
  "client_secret": "7Fjfp0ZBr1KtDRbnfVdmIw",
  "name": "My Application",
  "redirect_uris": ["https://myapp.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid", "profile", "email"]
}
```

### Initiate Authorization Code Flow

```bash
# Construct the authorization URL
AUTH_URL="$OPENIDX_BASE_URL/oauth/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https://myapp.example.com/callback&scope=openid+profile+email&state=xyz"

# Open in browser or follow redirects
curl -L "$AUTH_URL"
```

### Exchange Authorization Code for Tokens

```bash
curl -X POST "$OPENIDX_BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_FROM_REDIRECT" \
  -d "redirect_uri=https://myapp.example.com/callback" \
  -d "client_id=s6BhdRkqt3" \
  -d "client_secret=7Fjfp0ZBr1KtDRbnfVdmIw"
```

### Refresh Access Token

```bash
curl -X POST "$OPENIDX_BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=REFRESH_TOKEN" \
  -d "client_id=s6BhdRkqt3" \
  -d "client_secret=7Fjfp0ZBr1KtDRbnfVdmIw"
```

## Identity Service Examples

### Create a New User

```bash
curl -X POST "$IDENTITY_BASE_URL/api/v1/identity/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "jdoe",
    "email": "jane.doe@example.com",
    "first_name": "Jane",
    "last_name": "Doe",
    "password": "SecurePassword123!",
    "groups": ["developers"]
  }'
```

Response:

```json
{
  "id": "user-123",
  "username": "jdoe",
  "email": "jane.doe@example.com",
  "first_name": "Jane",
  "last_name": "Doe",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### List Users with Pagination

```bash
curl "$IDENTITY_BASE_URL/api/v1/identity/users?offset=0&limit=20" \
  -H "Authorization: Bearer $TOKEN"
```

### Search Users

```bash
# Search by email
curl "$IDENTITY_BASE_URL/api/v1/identity/users?search=jane@example.com" \
  -H "Authorization: Bearer $TOKEN"

# Search by name
curl "$IDENTITY_BASE_URL/api/v1/identity/users?search=Jane" \
  -H "Authorization: Bearer $TOKEN"
```

### Get User Details

```bash
curl "$IDENTITY_BASE_URL/api/v1/identity/users/user-123" \
  -H "Authorization: Bearer $TOKEN"
```

### Update User

```bash
curl -X PUT "$IDENTITY_BASE_URL/api/v1/identity/users/user-123" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "Jane",
    "last_name": "Smith",
    "email": "jane.smith@example.com"
  }'
```

### Enroll User in TOTP MFA

```bash
# Generate TOTP secret
curl -X POST "$IDENTITY_BASE_URL/api/v1/identity/users/user-123/mfa/totp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Phone"}'

# Verify and enable TOTP (user provides code from authenticator app)
curl -X POST "$IDENTITY_BASE_URL/api/v1/identity/users/user-123/mfa/totp/verify" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
```

### Get User Sessions

```bash
curl "$IDENTITY_BASE_URL/api/v1/identity/users/user-123/sessions" \
  -H "Authorization: Bearer $TOKEN"
```

### Revoke User Session

```bash
curl -X DELETE "$IDENTITY_BASE_URL/api/v1/identity/users/user-123/sessions/session-456" \
  -H "Authorization: Bearer $TOKEN"
```

## Governance Service Examples

### Create an Access Review Campaign

```bash
curl -X POST "$GOVERNANCE_BASE_URL/api/v1/governance/reviews" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q1 2024 Access Review",
    "description": "Quarterly review of access rights",
    "start_date": "2024-04-01T00:00:00Z",
    "end_date": "2024-04-30T23:59:59Z",
    "reviewers": ["manager-123", "manager-456"],
    "scope": {
      "type": "all_access",
      "filters": {"groups": ["admins", "developers"]}
    }
  }'
```

### Submit Access Review Decision

```bash
curl -X POST "$GOVERNANCE_BASE_URL/api/v1/governance/reviews/review-123/items/item-456/decision" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "approve",
    "comment": "Access is still required for current project"
  }'
```

### List Policies

```bash
curl "$GOVERNANCE_BASE_URL/api/v1/governance/policies" \
  -H "Authorization: Bearer $TOKEN"
```

### Create a Policy

```bash
curl -X POST "$GOVERNANCE_BASE_URL/api/v1/governance/policies" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Separation of Duties",
    "type": "separation_of_duty",
    "description": "Prevent users from having conflicting roles",
    "rules": [
      {
        "if": {"groups": ["payment-admins"]},
        "then": {"cannot_have_groups": ["payment-auditors"]}
      }
    ]
  }'
```

## SCIM Provisioning Examples

### List Users (SCIM)

```bash
curl "$PROVISIONING_BASE_URL/Users" \
  -H "Authorization: Bearer $TOKEN"
```

### Create User (SCIM)

```bash
curl -X POST "$PROVISIONING_BASE_URL/Users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "bjensen@example.com",
    "name": {
      "givenName": "Barbara",
      "familyName": "Jensen"
    },
    "emails": [{
      "value": "bjensen@example.com",
      "primary": true
    }],
    "active": true
  }'
```

### Get User (SCIM)

```bash
curl "$PROVISIONING_BASE_URL/Users/user-123" \
  -H "Authorization: Bearer $TOKEN"
```

### Update User (SCIM)

```bash
curl -X PUT "$PROVISIONING_BASE_URL/Users/user-123" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "id": "user-123",
    "userName": "bjensen@example.com",
    "name": {
      "givenName": "Barbara",
      "familyName": "Smith"
    },
    "emails": [{
      "value": "barbara.smith@example.com",
      "primary": true
    }],
    "active": true
  }'
```

### List Groups (SCIM)

```bash
curl "$PROVISIONING_BASE_URL/Groups" \
  -H "Authorization: Bearer $TOKEN"
```

### Create Group (SCIM)

```bash
curl -X POST "$PROVISIONING_BASE_URL/Groups" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Developers",
    "members": [
      {"value": "user-123", "display": "Barbara Jensen"}
    ]
  }'
```

## Audit Service Examples

### Query Audit Events

```bash
curl "$AUDIT_BASE_URL/api/v1/audit/events?limit=50&offset=0" \
  -H "Authorization: Bearer $TOKEN"
```

### Filter Audit Events

```bash
# Events by user
curl "$AUDIT_BASE_URL/api/v1/audit/events?user_id=user-123" \
  -H "Authorization: Bearer $TOKEN"

# Events by type
curl "$AUDIT_BASE_URL/api/v1/audit/events?event_type=user.login" \
  -H "Authorization: Bearer $TOKEN"

# Events in date range
curl "$AUDIT_BASE_URL/api/v1/audit/events?start_date=2024-01-01T00:00:00Z&end_date=2024-01-31T23:59:59Z" \
  -H "Authorization: Bearer $TOKEN"
```

### Generate Compliance Report

```bash
curl -X POST "$AUDIT_BASE_URL/api/v1/audit/reports" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "report_type": "soc2",
    "start_date": "2024-01-01T00:00:00Z",
    "end_date": "2024-01-31T23:59:59Z",
    "format": "csv"
  }'
```

### Get Audit Statistics

```bash
curl "$AUDIT_BASE_URL/api/v1/audit/statistics" \
  -H "Authorization: Bearer $TOKEN"
```

## Admin API Examples

### Get Dashboard Statistics

```bash
curl "$ADMIN_BASE_URL/api/v1/dashboard" \
  -H "Authorization: Bearer $TOKEN"
```

### Get System Settings

```bash
curl "$ADMIN_BASE_URL/api/v1/settings" \
  -H "Authorization: Bearer $TOKEN"
```

### Update System Settings

```bash
curl -X PUT "$ADMIN_BASE_URL/api/v1/settings" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mfa_policy": {
      "enforced": true,
      "methods": ["totp", "webauthn"]
    },
    "password_policy": {
      "min_length": 12,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_numbers": true,
      "require_symbols": true
    }
  }'
```

### Create API Key

```bash
curl -X POST "$ADMIN_BASE_URL/api/v1/apikeys" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Monitoring Service",
    "scopes": ["audit.read"],
    "expires_at": "2025-12-31T23:59:59Z"
  }'
```

## Code Examples

### Python Example

```python
import requests

class OpenIDXClient:
    def __init__(self, base_url, client_id, client_secret):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None

    def authenticate(self):
        """OAuth client credentials flow"""
        response = requests.post(
            f"{self.base_url}/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }
        )
        response.raise_for_status()
        self.access_token = response.json()["access_token"]

    def get_user(self, user_id):
        """Get user by ID"""
        response = requests.get(
            f"{self.base_url}/api/v1/identity/users/{user_id}",
            headers={"Authorization": f"Bearer {self.access_token}"}
        )
        response.raise_for_status()
        return response.json()

    def create_user(self, username, email, first_name, last_name, password):
        """Create a new user"""
        response = requests.post(
            f"{self.base_url}/api/v1/identity/users",
            headers={"Authorization": f"Bearer {self.access_token}"},
            json={
                "username": username,
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "password": password
            }
        )
        response.raise_for_status()
        return response.json()

# Usage
client = OpenIDXClient(
    base_url="http://localhost:8006",
    client_id="your-client-id",
    client_secret="your-client-secret"
)
client.authenticate()
user = client.create_user(
    username="jdoe",
    email="jane@example.com",
    first_name="Jane",
    last_name="Doe",
    password="SecurePassword123!"
)
print(f"Created user: {user['id']}")
```

### Go Example

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
)

type OpenIDXClient struct {
    BaseURL    string
    HTTPClient *http.Client
    Token      string
}

func (c *OpenIDXClient) Authenticate(clientID, clientSecret string) error {
    payload := map[string]string{
        "grant_type":    "client_credentials",
        "client_id":     clientID,
        "client_secret": clientSecret,
    }

    body, _ := json.Marshal(payload)
    resp, err := http.Post(
        c.BaseURL+"/oauth/token",
        "application/json",
        bytes.NewBuffer(body),
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    var result struct {
        AccessToken string `json:"access_token"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return err
    }

    c.Token = result.AccessToken
    return nil
}

func (c *OpenIDXClient) GetUser(userID string) (map[string]interface{}, error) {
    req, _ := http.NewRequest(
        "GET",
        c.BaseURL+"/api/v1/identity/users/"+userID,
        nil,
    )
    req.Header.Set("Authorization", "Bearer "+c.Token)

    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var user map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
        return nil, err
    }

    return user, nil
}
```

### JavaScript Example

```javascript
class OpenIDXClient {
  constructor(baseUrl, clientId, clientSecret) {
    this.baseUrl = baseUrl;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.accessToken = null;
  }

  async authenticate() {
    const response = await fetch(`${this.baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'client_credentials',
        client_id: this.clientId,
        client_secret: this.clientSecret,
      }),
    });

    const data = await response.json();
    this.accessToken = data.access_token;
  }

  async getUser(userId) {
    const response = await fetch(
      `${this.baseUrl}/api/v1/identity/users/${userId}`,
      {
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
        },
      }
    );
    return response.json();
  }

  async createUser(userData) {
    const response = await fetch(
      `${this.baseUrl}/api/v1/identity/users`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(userData),
      }
    );
    return response.json();
  }
}

// Usage
const client = new OpenIDXClient(
  'http://localhost:8006',
  'your-client-id',
  'your-client-secret'
);

await client.authenticate();
const user = await client.createUser({
  username: 'jdoe',
  email: 'jane@example.com',
  first_name: 'Jane',
  last_name: 'Doe',
  password: 'SecurePassword123!',
});
console.log('Created user:', user.id);
```
