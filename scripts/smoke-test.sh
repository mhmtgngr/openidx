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
# Optional: where to write the admin access token this run mints, so a caller
# can reuse it instead of driving the PKCE login a second time (CI hands it to
# tools/contractcheck). Unset by default -- a token on disk is a credential, so
# it is written only when asked for, with owner-only permissions.
SMOKE_TOKEN_OUT="${SMOKE_TOKEN_OUT:-}"

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
# Phase 2: Tokens — the machine grant and the browser login
# -------------------------------------------------------------------
echo -e "${BLUE}Phase 2: Token Flows${NC}"

# --- client_credentials: a service-to-service token, no user behind it ------
TOKEN_RESPONSE=$(curl -sf -X POST "${OAUTH_URL}/oauth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=api-service&client_secret=api-service-secret&scope=openid api" \
    2>/dev/null || echo "")

if [ -n "$TOKEN_RESPONSE" ] && echo "$TOKEN_RESPONSE" | jq -e '.access_token' > /dev/null 2>&1; then
    MACHINE_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
    pass "OAuth client_credentials flow"
else
    fail "OAuth client_credentials flow" "no access_token in response"
    MACHINE_TOKEN=""
fi

# --- authorization_code + PKCE as the seeded admin -------------------------
# This is J1 end to end: /oauth/authorize redirects to the one login UI with a
# login_session, POST /oauth/login exchanges credentials for a code, and
# /oauth/token exchanges the code (with the PKCE verifier) for a token. It is
# also the only way to get a token that CARRIES ROLES — see Phase 3.
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Admin@123}"
CLIENT_ID="${SMOKE_CLIENT_ID:-admin-console}"
REDIRECT_URI="${SMOKE_REDIRECT_URI:-http://localhost:3000/callback}"

urldecode() { python3 -c 'import sys,urllib.parse;print(urllib.parse.unquote(sys.argv[1]))' "$1"; }
urlencode() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

ADMIN_TOKEN=""
VERIFIER=$(head -c 64 /dev/urandom | base64 | tr -d '=+/' | cut -c1-64)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | base64 | tr '+/' '-_' | tr -d '=')

# The login_session arrives in the Location header, percent-encoded. Decoding
# it is not optional: the raw value does not match the Redis key and the login
# endpoint answers "invalid or expired login session".
AUTHORIZE_LOCATION=$(curl -s -o /dev/null -D - \
    "${OAUTH_URL}/oauth/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(urlencode "$REDIRECT_URI")&scope=openid+profile+email&code_challenge=${CHALLENGE}&code_challenge_method=S256" \
    2>/dev/null | tr -d '\r' | awk '/^[Ll]ocation:/{print $2}')

LOGIN_SESSION=""
if [ -n "$AUTHORIZE_LOCATION" ]; then
    LOGIN_SESSION=$(urldecode "$(printf '%s' "$AUTHORIZE_LOCATION" | sed -n 's/.*login_session=\([^&]*\).*/\1/p')")
fi

if [ -n "$LOGIN_SESSION" ]; then
    pass "Authorize redirects to the login UI with a login_session"
else
    fail "Authorize redirect" "no login_session in Location: ${AUTHORIZE_LOCATION:-<none>}"
fi

if [ -n "$LOGIN_SESSION" ]; then
    LOGIN_BODY=$(jq -nc --arg u "$ADMIN_USERNAME" --arg p "$ADMIN_PASSWORD" --arg s "$LOGIN_SESSION" \
        '{username:$u,password:$p,login_session:$s}')
    LOGIN_RESPONSE=$(curl -s -X POST "${OAUTH_URL}/oauth/login" \
        -H 'Content-Type: application/json' -d "$LOGIN_BODY" 2>/dev/null || echo "")
    AUTH_CODE=$(printf '%s' "$LOGIN_RESPONSE" | jq -r 'if .code then .code elif .redirect_url then (.redirect_url | capture("code=(?<c>[^&]+)").c) else empty end' 2>/dev/null || echo "")
    AUTH_CODE=$(urldecode "${AUTH_CODE:-}")

    if [ -n "$AUTH_CODE" ]; then
        ADMIN_TOKEN=$(curl -s -X POST "${OAUTH_URL}/oauth/token" \
            -d "grant_type=authorization_code&code=$(urlencode "$AUTH_CODE")&client_id=${CLIENT_ID}&redirect_uri=$(urlencode "$REDIRECT_URI")&code_verifier=${VERIFIER}" \
            2>/dev/null | jq -r '.access_token // empty' 2>/dev/null || echo "")
    fi

    if [ -n "$ADMIN_TOKEN" ]; then
        pass "Admin login through /oauth/login + PKCE code exchange"
        if [ -n "$SMOKE_TOKEN_OUT" ]; then
            ( umask 077; printf '%s' "$ADMIN_TOKEN" > "$SMOKE_TOKEN_OUT" )
        fi
    else
        fail "Admin login" "no access_token; login said: $(printf '%s' "$LOGIN_RESPONSE" | head -c 200)"
    fi
fi

echo

# -------------------------------------------------------------------
# Phase 3: API calls via the gateway, and the authorization that guards them
# -------------------------------------------------------------------
echo -e "${BLUE}Phase 3: API Integration${NC}"

# Deny-by-default, end to end. This used to read "list users with the
# client_credentials token and expect a body" — which has been impossible since
# the admin API became deny-by-default: that token carries no roles, so the
# answer is 403. The check now asserts the REFUSAL, because a 200 here would
# mean a machine token had reached an admin endpoint.
if [ -n "$MACHINE_TOKEN" ]; then
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "${GATEWAY_URL}/api/v1/identity/users" \
        -H "Authorization: Bearer ${MACHINE_TOKEN}" 2>/dev/null || echo "000")
    if [ "$CODE" = "403" ]; then
        pass "Identity API refuses a role-less client_credentials token (403)"
    else
        fail "Deny-by-default" "machine token got HTTP $CODE from /api/v1/identity/users (expected 403)"
    fi
else
    fail "Deny-by-default check" "skipped - no client_credentials token"
fi

if [ -n "$ADMIN_TOKEN" ]; then
    for probe in \
        "Identity API - list users:/api/v1/identity/users" \
        "Audit API - list events:/api/v1/audit/events" \
        "Governance API - list reviews:/api/v1/governance/reviews"; do
        LABEL="${probe%%:*}"
        PATH_="${probe#*:}"
        CODE=$(curl -s -o /dev/null -w "%{http_code}" "${GATEWAY_URL}${PATH_}" \
            -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || echo "000")
        if [ "$CODE" = "200" ]; then
            pass "$LABEL (via gateway)"
        else
            fail "$LABEL" "HTTP $CODE via ${GATEWAY_URL}${PATH_}"
        fi
    done
else
    fail "Gateway API tests" "skipped - no admin token"
fi

DISCOVERY=$(curl -sf "${OAUTH_URL}/.well-known/openid-configuration" 2>/dev/null || echo "")
if [ -n "$DISCOVERY" ] && echo "$DISCOVERY" | jq -e '.issuer' > /dev/null 2>&1; then
    pass "OIDC discovery endpoint"
else
    fail "OIDC discovery" "no issuer in response"
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
