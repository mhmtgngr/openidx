# OpenIDX API Examples - cURL

## Authentication

### Client Credentials Grant
```bash
# Get access token
TOKEN=$(curl -s -X POST http://localhost:8006/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "your_client_id",
    "client_secret": "your_client_secret",
    "scope": "openid profile email"
  }' | jq -r '.access_token')

# Use token in requests
curl -X GET http://localhost:8001/api/v1/identity/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

### Password Grant (Resource Owner)
```bash
# User login
TOKEN=$(curl -s -X POST http://localhost:8006/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "password",
    "username": "user@example.com",
    "password": "your_password",
    "scope": "openid profile email"
  }' | jq -r '.access_token')
```

### PKCE Authorization Code Flow
```bash
# Step 1: Generate code verifier and challenge
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-64)
CODE_CHALLENGE=$(echo -n $CODE_VERIFIER | openssl dgst -sha256 -binary | openssl base64 -A | tr -d '/+=')

# Step 2: Open browser for authorization
open "http://localhost:8006/oauth/authorize?response_type=code&client_id=your_client_id&redirect_uri=http://localhost:3000/callback&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&scope=openid%20profile%20email"

# Step 3: Exchange code for token (after callback)
curl -X POST http://localhost:8006/oauth/token \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"authorization_code\",
    \"code\": \"AUTHORIZATION_CODE_FROM_CALLBACK\",
    \"redirect_uri\": \"http://localhost:3000/callback\",
    \"client_id\": \"your_client_id\",
    \"code_verifier\": \"$CODE_VERIFIER\"
  }"
```

## Identity Service

### List Users
```bash
curl -X GET "http://localhost:8001/api/v1/identity/users?offset=0&limit=20" \
  -H "Authorization: Bearer $TOKEN"
```

### Create User
```bash
curl -X POST http://localhost:8001/api/v1/identity/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "password": "SecurePassword123!",
    "role_id": "ROLE_ID"
  }'
```

### Get User by ID
```bash
curl -X GET "http://localhost:8001/api/v1/identity/users/USER_ID" \
  -H "Authorization: Bearer $TOKEN"
```

### Update User
```bash
curl -X PUT "http://localhost:8001/api/v1/identity/users/USER_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "Jane",
    "last_name": "Smith"
  }'
```

### Delete User
```bash
curl -X DELETE "http://localhost:8001/api/v1/identity/users/USER_ID" \
  -H "Authorization: Bearer $TOKEN"
```

### Get User Sessions
```bash
curl -X GET "http://localhost:8001/api/v1/identity/users/USER_ID/sessions" \
  -H "Authorization: Bearer $TOKEN"
```

### Create Group
```bash
curl -X POST http://localhost:8001/api/v1/identity/groups \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Engineering",
    "description": "Engineering team members"
  }'
```

## Governance Service

### List Access Reviews
```bash
curl -X GET "http://localhost:8002/api/v1/governance/reviews?status=pending" \
  -H "Authorization: Bearer $TOKEN"
```

### Create Access Review
```bash
curl -X POST http://localhost:8002/api/v1/governance/reviews \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q1 2024 Access Review",
    "description": "Quarterly access certification",
    "start_date": "2024-01-01T00:00:00Z",
    "end_date": "2024-01-31T23:59:59Z",
    "reviewer_ids": ["REVIEWER_USER_ID"],
    "scope": {
      "type": "group",
      "group_id": "GROUP_ID"
    }
  }'
```

### Submit Review Decision
```bash
curl -X POST "http://localhost:8002/api/v1/governance/reviews/REVIEW_ID/items/ITEM_ID/decision" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "approve",
    "comment": "Access is still required"
  }'
```

## Provisioning Service (SCIM)

### List Users (SCIM)
```bash
curl -X GET "http://localhost:8003/scim/v2/Users?count=100&startIndex=1" \
  -H "Authorization: Bearer $TOKEN"
```

### Create User (SCIM)
```bash
curl -X POST http://localhost:8003/scim/v2/Users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "scim.user@example.com",
    "name": {
      "givenName": "SCIM",
      "familyName": "User"
    },
    "emails": [{
      "primary": true,
      "value": "scim.user@example.com",
      "type": "work"
    }],
    "active": true
  }'
```

### Update User (SCIM PATCH)
```bash
curl -X PATCH "http://localhost:8003/scim/v2/Users/USER_ID" \
  -H "Authorization: Bearer $TOKEN" \
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

## Audit Service

### Query Audit Events
```bash
curl -X GET "http://localhost:8004/api/v1/audit/events?limit=50&sort=timestamp:desc" \
  -H "Authorization: Bearer $TOKEN"
```

### Generate Compliance Report
```bash
curl -X POST http://localhost:8004/api/v1/audit/reports \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "report_type": "access_activity",
    "format": "csv",
    "start_date": "2024-01-01T00:00:00Z",
    "end_date": "2024-01-31T23:59:59Z",
    "filters": {
      "user_ids": ["USER_ID"],
      "actions": ["login", "logout", "access_granted"]
    }
  }'
```

### Get Audit Statistics
```bash
curl -X GET "http://localhost:8004/api/v1/audit/statistics?period=7d" \
  -H "Authorization: Bearer $TOKEN"
```

## Admin API

### Get Dashboard Stats
```bash
curl -X GET "http://localhost:8005/api/v1/dashboard" \
  -H "Authorization: Bearer $TOKEN"
```

### Create Application
```bash
curl -X POST http://localhost:8005/api/v1/applications \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Application",
    "description": "Internal company app",
    "callback_url": "https://app.example.com/callback",
    "type": "spa",
    "grant_types": ["authorization_code", "refresh_token"]
  }'
```

### Update System Settings
```bash
curl -X PUT http://localhost:8005/api/v1/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "password_policy": {
      "min_length": 12,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_numbers": true,
      "require_special": true
    },
    "session_timeout": 3600
  }'
```

## Access Service

### List Routes
```bash
curl -X GET "http://localhost:8007/api/v1/access/routes" \
  -H "Authorization: Bearer $TOKEN"
```

### Create Route
```bash
curl -X POST http://localhost:8007/api/v1/access/routes \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Internal App Route",
    "source": "app.internal.company.com",
    "destination": "https://internal-app.company.com",
    "policy_id": "POLICY_ID"
  }'
```

## Error Handling

All API errors return a consistent format:

```bash
curl -v "http://localhost:8001/api/v1/identity/users/invalid-id" \
  -H "Authorization: Bearer $TOKEN"
```

Error response:
```json
{
  "error": "not_found",
  "message": "User not found",
  "status": 404,
  "details": {}
}
```

## Rate Limiting

Check rate limit status from headers:
```bash
curl -I "http://localhost:8001/api/v1/identity/users" \
  -H "Authorization: Bearer $TOKEN"

# Headers:
# X-RateLimit-Limit: 100
# X-RateLimit-Remaining: 99
# X-RateLimit-Reset: 1640995200
```
