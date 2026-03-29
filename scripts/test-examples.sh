#!/bin/bash
# OpenIDX Test Examples
# Run these examples to test the platform

set -e

BASE_URL="${BASE_URL:-http://localhost:8088}"
OAUTH_URL="${OAUTH_URL:-http://localhost:8006}"

# Test client for API testing
CLIENT_ID="${CLIENT_ID:-test-client}"
CLIENT_SECRET="${CLIENT_SECRET:-test-secret}"

echo "=========================================="
echo "OpenIDX Test Examples"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

success() { echo -e "${GREEN}✓ $1${NC}"; }
error() { echo -e "${RED}✗ $1${NC}"; }
info() { echo -e "${YELLOW}→ $1${NC}"; }

# ==========================================
# 1. Health Check
# ==========================================
echo "1. Health Check"
echo "-------------------------------------------"

info "Checking OAuth service..."
OIDC_CONFIG=$(curl -s "$OAUTH_URL/.well-known/openid-configuration")
if echo "$OIDC_CONFIG" | grep -q "issuer"; then
    success "OAuth service is healthy"
    echo "   Issuer: $(echo "$OIDC_CONFIG" | grep -o '"issuer":"[^"]*"' | cut -d'"' -f4)"
else
    error "OAuth service is not responding"
fi
echo ""

# ==========================================
# 2. Get Access Token (Client Credentials)
# ==========================================
echo "2. Getting Access Token (Client Credentials)"
echo "-------------------------------------------"

info "Getting service account token..."
TOKEN_RESPONSE=$(curl -s -X POST "$OAUTH_URL/oauth/token" \
    --data "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=openid")

if echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
    TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
    success "Got service account token"
    echo "   Token: ${TOKEN:0:50}..."
else
    error "Failed to get token"
    echo "   Response: $TOKEN_RESPONSE"
fi
echo ""

# ==========================================
# 2b. Instructions for User Token
# ==========================================
echo "2b. For User Token (with full permissions):"
echo "-------------------------------------------"
echo "   1. Open http://localhost:3000 in browser"
echo "   2. Log in with admin@openidx.local / Admin123!"
echo "   3. Open DevTools > Application > Local Storage"
echo "   4. Copy the 'token' value"
echo ""
echo "   Or set TOKEN environment variable:"
echo "   export TOKEN=your_token_here"
echo ""

# Check if user provided a token
if [ -n "$USER_TOKEN" ]; then
    TOKEN="$USER_TOKEN"
    success "Using provided user token"
fi
echo ""

# ==========================================
# 3. Get Current User
# ==========================================
echo "3. Get Current User Info"
echo "-------------------------------------------"

info "Fetching current user..."
USER_INFO=$(curl -s "$BASE_URL/api/v1/identity/users/me" \
    -H "Authorization: Bearer $TOKEN")

if echo "$USER_INFO" | grep -q "email"; then
    success "Got user info"
    echo "$USER_INFO" | python3 -m json.tool 2>/dev/null || echo "$USER_INFO"
else
    error "Failed to get user info"
fi
echo ""

# ==========================================
# 4. List Users
# ==========================================
echo "4. List Users"
echo "-------------------------------------------"

info "Fetching users..."
USERS=$(curl -s "$BASE_URL/api/v1/identity/users?limit=5" \
    -H "Authorization: Bearer $TOKEN")

if echo "$USERS" | grep -q "users"; then
    USER_COUNT=$(echo "$USERS" | grep -o '"total":[0-9]*' | cut -d: -f2)
    success "Found $USER_COUNT users"
else
    error "Failed to list users"
fi
echo ""

# ==========================================
# 5. Create Test User
# ==========================================
echo "5. Create Test User"
echo "-------------------------------------------"

TEST_EMAIL="testuser_$(date +%s)@example.com"
info "Creating user: $TEST_EMAIL"

CREATE_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/identity/users" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"$TEST_EMAIL\",
        \"first_name\": \"Test\",
        \"last_name\": \"User\",
        \"password\": \"TestUser123!\"
    }")

if echo "$CREATE_RESPONSE" | grep -q "id"; then
    TEST_USER_ID=$(echo "$CREATE_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    success "Created user with ID: $TEST_USER_ID"
else
    error "Failed to create user"
    echo "   Response: $CREATE_RESPONSE"
fi
echo ""

# ==========================================
# 6. List Groups
# ==========================================
echo "6. List Groups"
echo "-------------------------------------------"

info "Fetching groups..."
GROUPS=$(curl -s "$BASE_URL/api/v1/identity/groups" \
    -H "Authorization: Bearer $TOKEN")

if echo "$GROUPS" | grep -q "groups\|total"; then
    success "Got groups list"
else
    error "Failed to list groups"
fi
echo ""

# ==========================================
# 7. List Roles
# ==========================================
echo "7. List Roles"
echo "-------------------------------------------"

info "Fetching roles..."
ROLES=$(curl -s "$BASE_URL/api/v1/identity/roles" \
    -H "Authorization: Bearer $TOKEN")

if echo "$ROLES" | grep -q "roles\|name"; then
    success "Got roles list"
else
    error "Failed to list roles"
fi
echo ""

# ==========================================
# 8. List Active Sessions
# ==========================================
echo "8. List Active Sessions"
echo "-------------------------------------------"

info "Fetching sessions..."
SESSIONS=$(curl -s "$BASE_URL/api/v1/sessions?active_only=true" \
    -H "Authorization: Bearer $TOKEN")

if echo "$SESSIONS" | grep -q "sessions"; then
    SESSION_COUNT=$(echo "$SESSIONS" | grep -o '"total":[0-9]*' | cut -d: -f2)
    success "Found $SESSION_COUNT active sessions"
else
    error "Failed to list sessions"
fi
echo ""

# ==========================================
# 9. Get Audit Logs
# ==========================================
echo "9. Get Recent Audit Logs"
echo "-------------------------------------------"

info "Fetching audit logs..."
AUDIT=$(curl -s "$BASE_URL/api/v1/audit/events?limit=5" \
    -H "Authorization: Bearer $TOKEN")

if echo "$AUDIT" | grep -q "events\|event_type"; then
    success "Got audit logs"
else
    error "Failed to get audit logs"
fi
echo ""

# ==========================================
# 10. Get OAuth Clients
# ==========================================
echo "10. List OAuth Applications"
echo "-------------------------------------------"

info "Fetching OAuth clients..."
CLIENTS=$(curl -s "$BASE_URL/api/v1/oauth/clients" \
    -H "Authorization: Bearer $TOKEN")

if echo "$CLIENTS" | grep -q "clients\|client_id\|name"; then
    success "Got OAuth clients"
else
    error "Failed to list OAuth clients"
fi
echo ""

# ==========================================
# 11. Get Login Analytics
# ==========================================
echo "11. Get Login Analytics"
echo "-------------------------------------------"

info "Fetching login analytics..."
ANALYTICS=$(curl -s "$BASE_URL/api/v1/identity/analytics/logins?period=7d" \
    -H "Authorization: Bearer $TOKEN")

if echo "$ANALYTICS" | grep -q "analytics\|summary\|total_logins"; then
    success "Got login analytics"
else
    error "Failed to get analytics (may not have data yet)"
fi
echo ""

# ==========================================
# 12. OIDC Discovery
# ==========================================
echo "12. OIDC Discovery Document"
echo "-------------------------------------------"

info "Fetching OIDC configuration..."
OIDC=$(curl -s "$OAUTH_URL/.well-known/openid-configuration")

if echo "$OIDC" | grep -q "issuer"; then
    success "Got OIDC discovery document"
    ISSUER=$(echo "$OIDC" | grep -o '"issuer":"[^"]*"' | cut -d'"' -f4)
    echo "   Issuer: $ISSUER"
else
    error "Failed to get OIDC config"
fi
echo ""

# ==========================================
# Cleanup
# ==========================================
echo "13. Cleanup - Delete Test User"
echo "-------------------------------------------"

if [ -n "$TEST_USER_ID" ]; then
    info "Deleting test user..."
    DELETE_RESPONSE=$(curl -s -X DELETE "$BASE_URL/api/v1/identity/users/$TEST_USER_ID" \
        -H "Authorization: Bearer $TOKEN")
    success "Deleted test user"
fi
echo ""

# ==========================================
# Summary
# ==========================================
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo ""
echo "API Base URL: $BASE_URL"
echo "OAuth URL: $OAUTH_URL"
echo "Admin Console: http://localhost:3000"
echo ""
echo "To get a token for manual testing:"
echo ""
echo "  curl -X POST $OAUTH_URL/oauth/login \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}'"
echo ""
echo "Then use the token:"
echo ""
echo "  curl $BASE_URL/api/v1/identity/users/me \\"
echo "    -H 'Authorization: Bearer YOUR_TOKEN'"
echo ""
