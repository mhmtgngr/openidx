# OpenIDX Testing Guide

This guide provides comprehensive testing steps for the OpenIDX Zero Trust Access Platform when running locally.

## Prerequisites

Ensure all services are running and healthy:
```bash
docker compose -f deployments/docker/docker-compose.yml ps
```

All services should show "healthy" or "running" status.

## Test URLs

- **Admin Console**: http://localhost:3000
- **Keycloak Admin**: http://localhost:8180
- **API Gateway (APISIX)**: http://localhost:8088
- **Identity Service**: http://localhost:8001
- **Governance Service**: http://localhost:8002
- **Provisioning Service**: http://localhost:8003
- **Audit Service**: http://localhost:8004
- **Admin API**: http://localhost:8005

## 1. Health Check Tests

### 1.1 Service Health Endpoints

Test that all services are responding:

```bash
# Test individual service health
curl -s http://localhost:8001/health | jq
curl -s http://localhost:8002/health | jq
curl -s http://localhost:8003/health | jq
curl -s http://localhost:8004/health | jq
curl -s http://localhost:8005/health | jq

# Test infrastructure health
curl -s http://localhost:9200/_cluster/health | jq
curl -s http://localhost:6379  # Redis (should connect)
```

### 1.2 Database Connectivity

Verify database connections:
```bash
# Test PostgreSQL connection
psql -h localhost -p 5432 -U openidx -d openidx

# Test Redis connection
redis-cli -p 6379 ping
```

## 2. Authentication Tests

### 2.1 Keycloak Admin Access

1. Open browser to http://localhost:8180
2. Login with credentials:
   - Username: `admin`
   - Password: `admin`
3. Verify admin console loads
4. Check realm configuration in "openidx" realm

### 2.2 Admin Console Login

1. Open browser to http://localhost:3000
2. Click "Login" or access protected route
3. Should redirect to Keycloak login
4. Login with admin/admin
5. Should redirect back to admin console with authenticated session

### 2.3 Token Validation

Test JWT token generation and validation:

```bash
# Get access token from Keycloak
curl -X POST http://localhost:8180/realms/openidx/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=admin-console&username=admin&password=admin"

# Validate token with identity service
curl -X POST http://localhost:8001/auth/validate \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## 3. API Gateway (APISIX) Tests

### 3.1 Gateway Health

```bash
# Test APISIX health
curl -s http://localhost:9188/apisix/admin/routes | jq

# Test gateway routing
curl -s http://localhost:8088/actuator/health
```

### 3.2 Rate Limiting Test

Test rate limiting functionality:
```bash
# Send multiple requests quickly
for i in {1..20}; do
  curl -s http://localhost:8088/api/v1/test &
done

# Should see 429 responses after limit
```

### 3.3 Authentication via Gateway

Test authenticated API calls through gateway:
```bash
# Get token first, then make authenticated request
TOKEN=$(curl -s -X POST http://localhost:8180/realms/openidx/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=admin-console&username=admin&password=admin" | jq -r .access_token)

# Test authenticated endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8088/api/v1/users
```

## 4. Identity Management Tests

### 4.1 User CRUD Operations

```bash
# Get users list
curl -X GET http://localhost:8001/users \
  -H "Authorization: Bearer $TOKEN"

# Create new user
curl -X POST http://localhost:8001/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "firstName": "Test",
    "lastName": "User"
  }'

# Get specific user
curl -X GET http://localhost:8001/users/testuser \
  -H "Authorization: Bearer $TOKEN"
```

### 4.2 Group Management

```bash
# List groups
curl -X GET http://localhost:8001/groups \
  -H "Authorization: Bearer $TOKEN"

# Create group
curl -X POST http://localhost:8001/groups \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Group",
    "description": "A test group"
  }'
```

### 4.3 Role Management

```bash
# List roles
curl -X GET http://localhost:8001/roles \
  -H "Authorization: Bearer $TOKEN"

# Assign role to user
curl -X POST http://localhost:8001/users/testuser/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '["user-admin"]'
```

## 5. Governance Service Tests

### 5.1 Policy Management

```bash
# List policies
curl -X GET http://localhost:8002/policies \
  -H "Authorization: Bearer $TOKEN"

# Create access policy
curl -X POST http://localhost:8002/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Policy",
    "description": "Test access policy",
    "rules": [
      {
        "resource": "api/users",
        "action": "read",
        "conditions": {
          "department": "IT"
        }
      }
    ]
  }'
```

### 5.2 Access Reviews

```bash
# List pending access reviews
curl -X GET http://localhost:8002/access-reviews \
  -H "Authorization: Bearer $TOKEN"

# Approve access review
curl -X POST http://localhost:8002/access-reviews/123/approve \
  -H "Authorization: Bearer $TOKEN"
```

## 6. Provisioning Service Tests

### 6.1 Application Provisioning

```bash
# List applications
curl -X GET http://localhost:8003/applications \
  -H "Authorization: Bearer $TOKEN"

# Create application
curl -X POST http://localhost:8003/applications \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test App",
    "description": "A test application",
    "type": "web",
    "url": "https://testapp.example.com"
  }'
```

### 6.2 User Provisioning

```bash
# Provision user to application
curl -X POST http://localhost:8003/provisioning/users/testuser/apps/testapp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "roles": ["viewer"],
    "attributes": {
      "department": "IT"
    }
  }'
```

## 7. Audit Service Tests

### 7.1 Audit Log Queries

```bash
# Get recent audit events
curl -X GET "http://localhost:8004/audit/events?limit=10" \
  -H "Authorization: Bearer $TOKEN"

# Search audit events by user
curl -X GET "http://localhost:8004/audit/events?user=testuser" \
  -H "Authorization: Bearer $TOKEN"

# Get audit events by action
curl -X GET "http://localhost:8004/audit/events?action=login" \
  -H "Authorization: Bearer $TOKEN"
```

### 7.2 Compliance Reports

```bash
# Generate user access report
curl -X POST http://localhost:8004/reports/user-access \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "startDate": "2024-01-01",
    "endDate": "2024-12-31",
    "userId": "testuser"
  }'
```

## 8. Policy Engine (OPA) Tests

### 8.1 Policy Evaluation

```bash
# Test policy evaluation
curl -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": "testuser",
      "resource": "api/users",
      "action": "read",
      "attributes": {
        "department": "IT",
        "role": "user-admin"
      }
    }
  }'
```

### 8.2 Policy Updates

```bash
# Update policy
curl -X PUT http://localhost:8181/v1/policies/authz \
  -H "Content-Type: text/plain" \
  -d 'package authz

default allow = false

allow {
  input.user == "admin"
}

allow {
  input.attributes.role == "user-admin"
  input.action == "read"
}'
```

## 9. Admin Console UI Tests

### 9.1 Dashboard Access

1. Login to http://localhost:3000
2. Verify dashboard loads with user stats
3. Check navigation menu items

### 9.2 User Management UI

1. Navigate to Users section
2. View user list
3. Create new user via UI
4. Edit user details
5. Assign roles/groups to user

### 9.3 Group Management UI

1. Navigate to Groups section
2. Create new group
3. Add users to group
4. Assign group permissions

### 9.4 Application Management UI

1. Navigate to Applications section
2. Register new application
3. Configure SSO settings
4. Test application provisioning

### 9.5 Audit & Reports UI

1. Navigate to Audit Logs
2. Filter events by date/user/action
3. Export audit reports
4. View compliance reports

## 10. Security Tests

### 10.1 Authentication Security

```bash
# Test invalid credentials
curl -X POST http://localhost:8180/realms/openidx/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=admin-console&username=admin&password=wrong"

# Should return 401 Unauthorized
```

### 10.2 Authorization Tests

```bash
# Test unauthorized access
curl -X GET http://localhost:8001/admin/users \
  -H "Authorization: Bearer $USER_TOKEN"

# Should return 403 Forbidden
```

### 10.3 Token Expiration

```bash
# Use expired token
curl -X GET http://localhost:8001/users \
  -H "Authorization: Bearer EXPIRED_TOKEN"

# Should return 401 Unauthorized
```

### 10.4 SQL Injection Prevention

```bash
# Test SQL injection attempts
curl -X GET "http://localhost:8001/users?name=' OR '1'='1" \
  -H "Authorization: Bearer $TOKEN"

# Should sanitize input and return 400 or filtered results
```

## 11. Performance Tests

### 11.1 Load Testing

```bash
# Simple load test with concurrent requests
ab -n 1000 -c 10 -H "Authorization: Bearer $TOKEN" http://localhost:8088/api/v1/users
```

### 11.2 Memory Usage Check

```bash
# Check container resource usage
docker stats openidx-identity-service openidx-governance-service
```

### 11.3 Database Performance

```bash
# Check database connection pool stats
curl -s http://localhost:8001/metrics | grep -i pool
```

## 12. Integration Tests

### 12.1 End-to-End User Workflow

1. Create user via API
2. Assign to group via API
3. Provision to application via API
4. Login via admin console
5. Access protected resources
6. Check audit logs for all actions

### 12.2 SSO Flow Test

1. Login to admin console
2. Access another application
3. Should be automatically logged in (SSO)
4. Logout from one app
5. Should be logged out from all apps

### 12.3 Multi-Tenant Test

1. Create separate realm in Keycloak
2. Configure tenant-specific policies
3. Test user isolation between tenants
4. Verify tenant-specific audit logs

## 13. Troubleshooting

### Common Issues

1. **Services not starting**: Check Docker resource allocation
2. **Authentication failures**: Verify Keycloak realm configuration
3. **API errors**: Check service logs with `docker compose logs <service-name>`
4. **Database connection issues**: Verify PostgreSQL is healthy
5. **UI not loading**: Check browser console for JavaScript errors

### Debug Commands

```bash
# View all service logs
docker compose logs -f

# View specific service logs
docker compose logs identity-service

# Check container resource usage
docker stats

# Test network connectivity
docker network inspect openidx_openidx-network

# Restart specific service
docker compose restart identity-service
```

## 14. Automated Testing

### Unit Tests
```bash
# Run Go service tests
go test ./internal/...

# Run with coverage
go test -cover ./internal/...
```

### Integration Tests
```bash
# Run integration tests
make test-integration

# Run with Docker Compose
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

### API Tests
```bash
# Run API tests with Newman/Postman
newman run tests/postman_collection.json

# Or with curl-based scripts
./scripts/api-tests.sh
```

This comprehensive testing guide ensures all components of the OpenIDX platform are functioning correctly and securely.
