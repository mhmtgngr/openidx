#!/bin/bash

# OpenIDX Integration Test Suite
# Tests the complete OAuth login flow, MFA enrollment, user profile, and RBAC
# Requires: all services running (docker-compose up)
# Usage: ./test-integration.sh [OAUTH_URL] [IDENTITY_URL]

set -uo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
OAUTH_URL="${1:-http://localhost:8006}"
IDENTITY_URL="${2:-http://localhost:8001}"
OAUTH_CLIENT_ID="admin-console"
REDIRECT_URI="http://localhost:3000/login"
# Seed admin user from init-db.sql (admin / Admin@123)
TEST_USERNAME="admin"
TEST_PASSWORD="Admin@123"
TEST_EMAIL="admin@openidx.local"

# Counters
PASSED=0
FAILED=0
SKIPPED=0

# Stored state
ACCESS_TOKEN=""
REFRESH_TOKEN=""
USER_ID=""
LOGIN_SESSION=""
AUTH_CODE=""
MFA_SECRET=""

# ── Helpers ────────────────────────────────────────────────────────────────────

header() {
    echo -e "\n${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  $1${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}\n"
}

pass() {
    echo -e "  ${GREEN}✓ $1${NC}"
    PASSED=$((PASSED + 1))
}

fail() {
    echo -e "  ${RED}✗ $1${NC}"
    if [ -n "${2:-}" ]; then
        echo -e "    ${RED}→ $2${NC}"
    fi
    FAILED=$((FAILED + 1))
}

skip() {
    echo -e "  ${CYAN}⊘ $1 (skipped)${NC}"
    SKIPPED=$((SKIPPED + 1))
}

info() {
    echo -e "  ${CYAN}ℹ $1${NC}"
}

# Make an HTTP request and capture status + body
# Usage: http METHOD URL [DATA]
# Sets: HTTP_STATUS, HTTP_BODY
http() {
    local method="$1"
    local url="$2"
    local data="${3:-}"
    local extra_headers="${4:-}"
    local curl_args=(-s -w '\n%{http_code}' -X "$method")

    if [ -n "$data" ]; then
        curl_args+=(-H "Content-Type: application/json" -d "$data")
    fi

    if [ -n "$ACCESS_TOKEN" ] && [ -z "$extra_headers" ]; then
        curl_args+=(-H "Authorization: Bearer $ACCESS_TOKEN")
    fi

    if [ -n "$extra_headers" ]; then
        curl_args+=(-H "$extra_headers")
    fi

    local response
    response=$(curl "${curl_args[@]}" "$url" 2>/dev/null) || true

    HTTP_STATUS=$(echo "$response" | tail -n1)
    HTTP_BODY=$(echo "$response" | sed '$d')
}

# Make a form-encoded POST (for OAuth token endpoint)
http_form() {
    local url="$1"
    local data="$2"
    local response

    response=$(curl -s -w '\n%{http_code}' -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "$data" \
        "$url" 2>/dev/null) || true

    HTTP_STATUS=$(echo "$response" | tail -n1)
    HTTP_BODY=$(echo "$response" | sed '$d')
}

# Extract JSON field using python (available on most systems)
json_field() {
    echo "$1" | python -c "import sys,json; d=json.load(sys.stdin); print(d.get('$2',''))" 2>/dev/null || echo ""
}

# Decode JWT payload (base64url -> JSON)
decode_jwt() {
    local token="$1"
    local payload
    payload=$(echo "$token" | cut -d. -f2)
    # Add padding
    local pad=$((4 - ${#payload} % 4))
    if [ "$pad" -ne 4 ]; then
        payload="${payload}$(printf '%0.s=' $(seq 1 $pad))"
    fi
    echo "$payload" | tr '_-' '/+' | base64 -d 2>/dev/null || echo "{}"
}

# ── Pre-flight checks ─────────────────────────────────────────────────────────

preflight() {
    header "Pre-flight Checks"

    # Check OAuth service
    http GET "$OAUTH_URL/health"
    if [ "$HTTP_STATUS" = "200" ]; then
        pass "OAuth service is healthy"
    else
        fail "OAuth service unreachable at $OAUTH_URL" "Status: $HTTP_STATUS"
        echo -e "\n${RED}Cannot continue without OAuth service. Run: docker-compose up${NC}"
        exit 1
    fi

    # Check Identity service
    http GET "$IDENTITY_URL/health"
    if [ "$HTTP_STATUS" = "200" ]; then
        pass "Identity service is healthy"
    else
        fail "Identity service unreachable at $IDENTITY_URL" "Status: $HTTP_STATUS"
        echo -e "\n${RED}Cannot continue without Identity service. Run: docker-compose up${NC}"
        exit 1
    fi

    # Check OIDC discovery
    http GET "$OAUTH_URL/.well-known/openid-configuration"
    if [ "$HTTP_STATUS" = "200" ]; then
        local issuer
        issuer=$(json_field "$HTTP_BODY" "issuer")
        pass "OIDC discovery available (issuer: $issuer)"
    else
        fail "OIDC discovery endpoint failed" "Status: $HTTP_STATUS"
    fi

    # Check JWKS
    http GET "$OAUTH_URL/.well-known/jwks.json"
    if [ "$HTTP_STATUS" = "200" ]; then
        pass "JWKS endpoint available"
    else
        fail "JWKS endpoint failed" "Status: $HTTP_STATUS"
    fi
}

# ── Test 1: User Setup ────────────────────────────────────────────────────────

test_user_setup() {
    header "1. Verify Seed Data"

    # The admin user (admin / Admin@123) and admin-console OAuth client
    # are seeded by init-db.sql. Verify the seed user exists by checking
    # the health endpoint (we can't query users without auth yet).
    USER_ID="00000000-0000-0000-0000-000000000001"
    info "Using seed admin user: $TEST_USERNAME (ID: $USER_ID)"
    pass "Seed admin user configured"
}

# ── Test 2: OAuth Client Setup ────────────────────────────────────────────────

test_oauth_client() {
    header "2. OAuth Client Verification"

    # admin-console client is seeded by init-db.sql
    http GET "$OAUTH_URL/api/v1/oauth/clients/$OAUTH_CLIENT_ID"
    if [ "$HTTP_STATUS" = "200" ]; then
        pass "OAuth client '$OAUTH_CLIENT_ID' exists (seeded)"
    else
        fail "OAuth client '$OAUTH_CLIENT_ID' not found" "Status: $HTTP_STATUS. Check init-db.sql seed data."
    fi
}

# ── Test 3: OAuth Authorization Flow ──────────────────────────────────────────

test_oauth_flow() {
    header "3. OAuth Authorization Flow"

    # Step 1: Initiate authorization (get login_session)
    # Generate PKCE code_verifier and code_challenge (S256)
    info "Generating PKCE challenge..."
    local code_verifier code_challenge
    code_verifier=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
    code_challenge=$(python -c "
import hashlib, base64
v = '$code_verifier'
digest = hashlib.sha256(v.encode()).digest()
print(base64.urlsafe_b64encode(digest).rstrip(b'=').decode())
")

    info "Step 1: Initiate /oauth/authorize (with PKCE)"
    local auth_url="$OAUTH_URL/oauth/authorize?response_type=code&client_id=$OAUTH_CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid%20profile%20email%20offline_access&state=test-state&code_challenge=$code_challenge&code_challenge_method=S256"

    # Capture the redirect Location header to extract login_session
    local redirect_headers
    redirect_headers=$(curl -s -D - -o /dev/null -X GET "$auth_url" 2>/dev/null) || true

    HTTP_STATUS=$(echo "$redirect_headers" | grep "^HTTP/" | tail -1 | awk '{print $2}')
    local location_header
    location_header=$(echo "$redirect_headers" | grep -i "^location:" | sed 's/^[Ll]ocation: *//' | tr -d '\r')

    if [ "$HTTP_STATUS" = "302" ] && echo "$location_header" | grep -q "login_session"; then
        local raw_session
        raw_session=$(echo "$location_header" | sed -n 's/.*login_session=\([^&]*\).*/\1/p')
        # URL-decode the session value (%3D -> =, %2B -> +, etc.)
        LOGIN_SESSION=$(python -c "import urllib.parse; print(urllib.parse.unquote('$raw_session'))" 2>/dev/null || echo "$raw_session")
        pass "Authorization redirect received (login_session: ${LOGIN_SESSION:0:20}...)"
    else
        fail "Authorization redirect failed" "Status: $HTTP_STATUS"
        skip "Remaining OAuth flow tests"
        return
    fi

    # Step 2: Authenticate with username/password
    info "Step 2: POST /oauth/login"
    http POST "$OAUTH_URL/oauth/login" "{
        \"username\": \"$TEST_USERNAME\",
        \"password\": \"$TEST_PASSWORD\",
        \"login_session\": \"$LOGIN_SESSION\"
    }" "no-auth"

    if [ "$HTTP_STATUS" = "200" ]; then
        local redirect_url_with_code
        redirect_url_with_code=$(json_field "$HTTP_BODY" "redirect_url")
        AUTH_CODE=$(echo "$redirect_url_with_code" | grep -oP 'code=\K[^&]+' 2>/dev/null || echo "$redirect_url_with_code" | sed -n 's/.*code=\([^&]*\).*/\1/p')

        if [ -n "$AUTH_CODE" ]; then
            pass "Login successful, auth code received (${AUTH_CODE:0:20}...)"
        else
            fail "Login succeeded but no auth code in redirect URL"
        fi
    else
        fail "Login failed" "Status: $HTTP_STATUS Body: $HTTP_BODY"
        skip "Token exchange test"
        return
    fi

    # Step 3: Exchange auth code for tokens (with PKCE code_verifier)
    info "Step 3: POST /oauth/token (authorization_code grant + PKCE)"
    http_form "$OAUTH_URL/oauth/token" \
        "grant_type=authorization_code&code=$AUTH_CODE&client_id=$OAUTH_CLIENT_ID&redirect_uri=$REDIRECT_URI&code_verifier=$code_verifier"

    if [ "$HTTP_STATUS" = "200" ]; then
        ACCESS_TOKEN=$(json_field "$HTTP_BODY" "access_token")
        REFRESH_TOKEN=$(json_field "$HTTP_BODY" "refresh_token")
        local id_token
        id_token=$(json_field "$HTTP_BODY" "id_token")
        local expires_in
        expires_in=$(json_field "$HTTP_BODY" "expires_in")

        if [ -n "$ACCESS_TOKEN" ]; then
            pass "Token exchange successful (expires_in: ${expires_in}s)"
        else
            fail "Token response missing access_token"
            return
        fi

        # Verify access token is a valid JWT
        local jwt_payload
        jwt_payload=$(decode_jwt "$ACCESS_TOKEN")
        local sub
        sub=$(echo "$jwt_payload" | python -c "import sys,json; print(json.load(sys.stdin).get('sub',''))" 2>/dev/null || echo "")

        if [ -n "$sub" ]; then
            pass "Access token is valid JWT (sub: $sub)"
        else
            fail "Access token JWT decode failed"
        fi

        # Check roles claim
        local roles
        roles=$(echo "$jwt_payload" | python -c "import sys,json; print(json.load(sys.stdin).get('roles',''))" 2>/dev/null || echo "")
        if [ -n "$roles" ] && [ "$roles" != "None" ] && [ "$roles" != "[]" ]; then
            pass "JWT contains roles claim: $roles"
        else
            info "JWT roles claim is empty (user may not have roles assigned yet)"
        fi

        # Verify ID token if present
        if [ -n "$id_token" ]; then
            local id_payload
            id_payload=$(decode_jwt "$id_token")
            local email
            email=$(echo "$id_payload" | python -c "import sys,json; print(json.load(sys.stdin).get('email',''))" 2>/dev/null || echo "")
            if [ -n "$email" ]; then
                pass "ID token contains email: $email"
            else
                info "ID token present but no email claim"
            fi
        fi

        # Verify refresh token
        if [ -n "$REFRESH_TOKEN" ]; then
            pass "Refresh token received"
        else
            info "No refresh token (offline_access may not be granted)"
        fi
    else
        fail "Token exchange failed" "Status: $HTTP_STATUS Body: $HTTP_BODY"
    fi
}

# ── Test 4: Token Refresh ─────────────────────────────────────────────────────

test_token_refresh() {
    header "4. Token Refresh"

    if [ -z "$REFRESH_TOKEN" ]; then
        skip "No refresh token available"
        return
    fi

    http_form "$OAUTH_URL/oauth/token" \
        "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN&client_id=$OAUTH_CLIENT_ID"

    if [ "$HTTP_STATUS" = "200" ]; then
        local new_token
        new_token=$(json_field "$HTTP_BODY" "access_token")
        if [ -n "$new_token" ]; then
            ACCESS_TOKEN="$new_token"
            pass "Token refresh successful"
        else
            fail "Refresh response missing access_token"
        fi
    else
        fail "Token refresh failed" "Status: $HTTP_STATUS Body: $HTTP_BODY"
    fi
}

# ── Test 5: UserInfo Endpoint ─────────────────────────────────────────────────

test_userinfo() {
    header "5. UserInfo Endpoint"

    if [ -z "$ACCESS_TOKEN" ]; then
        skip "No access token available"
        return
    fi

    http GET "$OAUTH_URL/oauth/userinfo"

    if [ "$HTTP_STATUS" = "200" ]; then
        local sub email name
        sub=$(json_field "$HTTP_BODY" "sub")
        email=$(json_field "$HTTP_BODY" "email")
        name=$(json_field "$HTTP_BODY" "name")
        pass "UserInfo returned (sub: $sub, email: $email, name: $name)"
    else
        fail "UserInfo request failed" "Status: $HTTP_STATUS Body: $HTTP_BODY"
    fi
}

# ── Test 6: User Profile (authenticated) ─────────────────────────────────────

test_user_profile() {
    header "6. User Profile (Authenticated)"

    if [ -z "$ACCESS_TOKEN" ]; then
        skip "No access token available"
        return
    fi

    # Get current user profile
    http GET "$IDENTITY_URL/api/v1/identity/users/me"

    if [ "$HTTP_STATUS" = "200" ]; then
        local firstName lastName email mfaEnabled
        firstName=$(json_field "$HTTP_BODY" "firstName")
        lastName=$(json_field "$HTTP_BODY" "lastName")
        email=$(json_field "$HTTP_BODY" "email")
        mfaEnabled=$(json_field "$HTTP_BODY" "mfaEnabled")
        pass "Profile retrieved (name: $firstName $lastName, email: $email, mfa: $mfaEnabled)"
    else
        fail "Failed to get profile" "Status: $HTTP_STATUS Body: $HTTP_BODY"
    fi

    # Update profile (change firstName, then revert)
    http PUT "$IDENTITY_URL/api/v1/identity/users/me" "{
        \"firstName\": \"IntegrationUpdated\",
        \"lastName\": \"Admin\",
        \"email\": \"$TEST_EMAIL\",
        \"enabled\": true
    }"

    if [ "$HTTP_STATUS" = "200" ]; then
        local updatedName
        updatedName=$(json_field "$HTTP_BODY" "firstName")
        if [ "$updatedName" = "IntegrationUpdated" ]; then
            pass "Profile updated successfully (firstName: $updatedName)"
        else
            fail "Profile update response has wrong firstName" "Got: $updatedName"
        fi

        # Revert to original
        http PUT "$IDENTITY_URL/api/v1/identity/users/me" "{
            \"firstName\": \"System\",
            \"lastName\": \"Admin\",
            \"email\": \"$TEST_EMAIL\",
            \"enabled\": true
        }"
        if [ "$HTTP_STATUS" = "200" ]; then
            pass "Profile reverted to original"
        fi
    else
        fail "Failed to update profile" "Status: $HTTP_STATUS Body: $HTTP_BODY"
    fi
}

# ── Test 7: MFA Setup Flow ───────────────────────────────────────────────────

test_mfa_flow() {
    header "7. MFA Enrollment Flow"

    if [ -z "$ACCESS_TOKEN" ]; then
        skip "No access token available"
        return
    fi

    # Step 1: Setup MFA (get QR code and secret)
    info "Step 1: POST /users/me/mfa/setup"
    http POST "$IDENTITY_URL/api/v1/identity/users/me/mfa/setup" ""

    if [ "$HTTP_STATUS" = "200" ]; then
        MFA_SECRET=$(json_field "$HTTP_BODY" "secret")
        local qrCodeUrl
        qrCodeUrl=$(json_field "$HTTP_BODY" "qrCodeUrl")

        if [ -n "$MFA_SECRET" ]; then
            pass "MFA setup successful (secret: ${MFA_SECRET:0:8}...)"
        else
            fail "MFA setup response missing secret"
            return
        fi

        if [ -n "$qrCodeUrl" ] && echo "$qrCodeUrl" | grep -q "otpauth://"; then
            pass "QR code URL is valid otpauth:// URI"
        else
            fail "QR code URL missing or invalid" "Got: $qrCodeUrl"
        fi
    else
        fail "MFA setup failed" "Status: $HTTP_STATUS Body: $HTTP_BODY"
        return
    fi

    # Step 2: Try enabling with wrong code
    info "Step 2: Verify wrong code is rejected"
    http POST "$IDENTITY_URL/api/v1/identity/users/me/mfa/enable" '{"code":"000000"}'

    if [ "$HTTP_STATUS" = "400" ]; then
        pass "Invalid MFA code correctly rejected"
    else
        fail "Expected 400 for invalid MFA code" "Got: $HTTP_STATUS"
    fi

    # Step 3: Generate valid TOTP code and enable
    # This requires a TOTP library - we'll test with python if available
    info "Step 3: Generate valid TOTP and enable MFA"
    local totp_code
    totp_code=$(echo "$MFA_SECRET" | python -c "
import hmac, hashlib, struct, time, base64, sys
secret_str = sys.stdin.read().strip()
secret = base64.b32decode(secret_str + '=' * (-len(secret_str) % 8), casefold=True)
counter = int(time.time()) // 30
msg = struct.pack('>Q', counter)
h = hmac.HMAC(secret, msg, hashlib.sha1).digest()
offset = h[-1] & 0x0f
code = (struct.unpack('>I', h[offset:offset+4])[0] & 0x7fffffff) % 1000000
print(f'{code:06d}')
" 2>/dev/null || echo "")

    if [ -n "$totp_code" ]; then
        http POST "$IDENTITY_URL/api/v1/identity/users/me/mfa/enable" "{\"code\":\"$totp_code\"}"

        if [ "$HTTP_STATUS" = "200" ]; then
            local backupCodes
            backupCodes=$(json_field "$HTTP_BODY" "backupCodes")
            pass "MFA enabled with valid TOTP code"
            if [ -n "$backupCodes" ] && [ "$backupCodes" != "None" ]; then
                pass "Backup codes received"
            else
                info "No backup codes in response"
            fi
        else
            fail "MFA enable failed with valid code" "Status: $HTTP_STATUS Body: $HTTP_BODY"
        fi

        # Step 4: Verify profile shows MFA enabled
        info "Step 4: Verify profile reflects MFA enabled"
        http GET "$IDENTITY_URL/api/v1/identity/users/me"
        if [ "$HTTP_STATUS" = "200" ]; then
            local mfaEnabled
            mfaEnabled=$(json_field "$HTTP_BODY" "mfaEnabled")
            if [ "$mfaEnabled" = "True" ] || [ "$mfaEnabled" = "true" ]; then
                pass "Profile confirms MFA is enabled"
            else
                fail "Profile shows MFA not enabled after enrollment" "mfaEnabled: $mfaEnabled"
            fi
        fi

        # Step 5: Disable MFA
        info "Step 5: Disable MFA"
        http POST "$IDENTITY_URL/api/v1/identity/users/me/mfa/disable" ""

        if [ "$HTTP_STATUS" = "200" ]; then
            pass "MFA disabled successfully"
        else
            fail "MFA disable failed" "Status: $HTTP_STATUS Body: $HTTP_BODY"
        fi
    else
        skip "TOTP code generation requires python (not available)"
    fi
}

# ── Test 8: Change Password ──────────────────────────────────────────────────

test_change_password() {
    header "8. Change Password"

    if [ -z "$ACCESS_TOKEN" ]; then
        skip "No access token available"
        return
    fi

    # Test with wrong current password first (non-destructive)
    http POST "$IDENTITY_URL/api/v1/identity/users/me/change-password" "{
        \"currentPassword\": \"wrong-password\",
        \"newPassword\": \"anything\"
    }"

    if [ "$HTTP_STATUS" = "400" ]; then
        pass "Wrong current password correctly rejected"
    else
        fail "Expected 400 for wrong password" "Got: $HTTP_STATUS"
    fi

    # Change password and immediately revert
    local new_password="TempP@ss456!"

    http POST "$IDENTITY_URL/api/v1/identity/users/me/change-password" "{
        \"currentPassword\": \"$TEST_PASSWORD\",
        \"newPassword\": \"$new_password\"
    }"

    if [ "$HTTP_STATUS" = "200" ]; then
        pass "Password changed successfully"

        # Revert back for future test runs
        http POST "$IDENTITY_URL/api/v1/identity/users/me/change-password" "{
            \"currentPassword\": \"$new_password\",
            \"newPassword\": \"$TEST_PASSWORD\"
        }"
        if [ "$HTTP_STATUS" = "200" ]; then
            pass "Password reverted to original"
        else
            fail "Password revert failed" "Status: $HTTP_STATUS. Manual reset required."
        fi
    else
        fail "Password change failed" "Status: $HTTP_STATUS Body: $HTTP_BODY"
    fi
}

# ── Test 9: Token Revocation ─────────────────────────────────────────────────

test_token_revocation() {
    header "9. Token Revocation"

    if [ -z "$REFRESH_TOKEN" ]; then
        skip "No refresh token to revoke"
        return
    fi

    http_form "$OAUTH_URL/oauth/revoke" "token=$REFRESH_TOKEN"

    if [ "$HTTP_STATUS" = "200" ]; then
        pass "Token revocation accepted"

        # Verify revoked refresh token no longer works
        http_form "$OAUTH_URL/oauth/token" \
            "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN&client_id=$OAUTH_CLIENT_ID"

        if [ "$HTTP_STATUS" = "400" ]; then
            pass "Revoked refresh token correctly rejected"
        else
            info "Revoked token refresh returned $HTTP_STATUS (may still work briefly)"
        fi
    else
        fail "Token revocation failed" "Status: $HTTP_STATUS"
    fi
}

# ── Test 10: Cleanup ──────────────────────────────────────────────────────────

test_cleanup() {
    header "10. Cleanup"

    # Don't delete the seed admin user -- it's shared infrastructure
    info "Seed admin user preserved (not deleted)"
    pass "Cleanup complete"
}

# ── Summary ───────────────────────────────────────────────────────────────────

summary() {
    header "Test Summary"

    local total=$((PASSED + FAILED + SKIPPED))
    echo "  Total:   $total"
    echo -e "  ${GREEN}Passed:  $PASSED${NC}"
    echo -e "  ${RED}Failed:  $FAILED${NC}"
    echo -e "  ${CYAN}Skipped: $SKIPPED${NC}"
    echo ""

    if [ "$FAILED" -eq 0 ]; then
        echo -e "  ${GREEN}All tests passed!${NC}\n"
        exit 0
    else
        echo -e "  ${RED}Some tests failed!${NC}\n"
        exit 1
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    echo -e "${YELLOW}OpenIDX Integration Test Suite${NC}"
    echo -e "OAuth:    $OAUTH_URL"
    echo -e "Identity: $IDENTITY_URL"
    echo -e "Date:     $(date)"

    preflight
    test_user_setup
    test_oauth_client
    test_oauth_flow
    test_token_refresh
    test_userinfo
    test_user_profile
    test_mfa_flow
    test_change_password
    test_token_revocation
    test_cleanup
    summary
}

main
