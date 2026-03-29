#!/bin/bash
# OpenIDX Smoke Test - Validates the full stack works end-to-end
# Run after: docker compose up -d
# Requires: curl, jq

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
GATEWAY_URL="${GATEWAY_URL:-http://localhost:8088}"
OAUTH_URL="${OAUTH_URL:-http://localhost:8006}"
TIMEOUT="${TIMEOUT:-120}"

pass() { echo -e "  ${GREEN}PASS${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}FAIL${NC} $1: $2"; FAIL=$((FAIL + 1)); }

echo -e "${BLUE}OpenIDX Smoke Test${NC}"
echo "================================"
echo

# -------------------------------------------------------------------
# Phase 1: Wait for services to be healthy
# -------------------------------------------------------------------
echo -e "${BLUE}Phase 1: Service Health${NC}"

SERVICES=(
    "identity-service:8001"
    "governance-service:8002"
    "provisioning-service:8003"
    "audit-service:8004"
    "admin-api:8005"
    "oauth-service:8006"
    "access-service:8007"
    "gateway-service:8008"
)

DEADLINE=$((SECONDS + TIMEOUT))
for svc in "${SERVICES[@]}"; do
    NAME="${svc%%:*}"
    PORT="${svc##*:}"
    URL="http://localhost:${PORT}/health"

    while true; do
        if curl -sf "$URL" > /dev/null 2>&1; then
            pass "$NAME (port $PORT)"
            break
        fi
        if [ $SECONDS -ge $DEADLINE ]; then
            fail "$NAME" "not healthy after ${TIMEOUT}s"
            break
        fi
        sleep 2
    done
done

echo

# -------------------------------------------------------------------
# Phase 2: OAuth token flow (client_credentials)
# -------------------------------------------------------------------
echo -e "${BLUE}Phase 2: OAuth Token Flow${NC}"

TOKEN_RESPONSE=$(curl -sf -X POST "${OAUTH_URL}/oauth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=api-service&client_secret=api-service-secret&scope=openid api" \
    2>/dev/null || echo "")

if [ -n "$TOKEN_RESPONSE" ] && echo "$TOKEN_RESPONSE" | jq -e '.access_token' > /dev/null 2>&1; then
    ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
    pass "OAuth client_credentials flow"
else
    fail "OAuth client_credentials flow" "no access_token in response"
    ACCESS_TOKEN=""
fi

echo

# -------------------------------------------------------------------
# Phase 3: API calls via gateway
# -------------------------------------------------------------------
echo -e "${BLUE}Phase 3: API Integration${NC}"

if [ -n "$ACCESS_TOKEN" ]; then
    USERS_RESPONSE=$(curl -sf "${GATEWAY_URL}/api/v1/identity/users" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" 2>/dev/null || echo "")

    if [ -n "$USERS_RESPONSE" ]; then
        pass "Identity API - list users via gateway"
    else
        fail "Identity API" "empty response from /api/v1/identity/users"
    fi

    AUDIT_RESPONSE=$(curl -sf "${GATEWAY_URL}/api/v1/audit/events" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" 2>/dev/null || echo "")

    if [ -n "$AUDIT_RESPONSE" ]; then
        pass "Audit API - list events via gateway"
    else
        fail "Audit API" "empty response from /api/v1/audit/events"
    fi

    GOV_RESPONSE=$(curl -sf "${GATEWAY_URL}/api/v1/governance/reviews" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" 2>/dev/null || echo "")

    if [ -n "$GOV_RESPONSE" ]; then
        pass "Governance API - list reviews via gateway"
    else
        fail "Governance API" "empty response from /api/v1/governance/reviews"
    fi

    DISCOVERY=$(curl -sf "${OAUTH_URL}/.well-known/openid-configuration" 2>/dev/null || echo "")

    if [ -n "$DISCOVERY" ] && echo "$DISCOVERY" | jq -e '.issuer' > /dev/null 2>&1; then
        pass "OIDC discovery endpoint"
    else
        fail "OIDC discovery" "no issuer in response"
    fi
else
    fail "API tests" "skipped - no access token"
fi

echo

# -------------------------------------------------------------------
# Phase 4: Admin console
# -------------------------------------------------------------------
echo -e "${BLUE}Phase 4: Admin Console${NC}"

CONSOLE_RESPONSE=$(curl -sf -o /dev/null -w "%{http_code}" "http://localhost:3000/" 2>/dev/null || echo "000")

if [ "$CONSOLE_RESPONSE" = "200" ]; then
    pass "Admin console (port 3000)"
else
    fail "Admin console" "HTTP $CONSOLE_RESPONSE (expected 200)"
fi

echo

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
echo "================================"
TOTAL=$((PASS + FAIL))
echo -e "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${TOTAL} total"
echo

if [ $FAIL -gt 0 ]; then
    echo -e "${RED}SMOKE TEST FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}SMOKE TEST PASSED${NC}"
    exit 0
fi
