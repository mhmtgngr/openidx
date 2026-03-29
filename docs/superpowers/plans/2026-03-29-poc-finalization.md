# PoC Finalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make OpenIDX demo-ready: `docker compose up` then `make smoke-test` proves everything works.

**Architecture:** Three files — a smoke test script that validates the full stack end-to-end via curl, a fixed seed script, and a Makefile target for discoverability.

**Tech Stack:** Bash, curl, jq

---

### Task 1: Create smoke test script

**Files:**
- Create: `scripts/smoke-test.sh`

- [ ] **Step 1: Create the smoke test script**

```bash
cat > scripts/smoke-test.sh << 'SCRIPT_EOF'
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
    # List users via identity service
    USERS_RESPONSE=$(curl -sf "${GATEWAY_URL}/api/v1/identity/users" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" 2>/dev/null || echo "")

    if [ -n "$USERS_RESPONSE" ]; then
        pass "Identity API - list users via gateway"
    else
        fail "Identity API" "empty response from /api/v1/identity/users"
    fi

    # Check audit events
    AUDIT_RESPONSE=$(curl -sf "${GATEWAY_URL}/api/v1/audit/events" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" 2>/dev/null || echo "")

    if [ -n "$AUDIT_RESPONSE" ]; then
        pass "Audit API - list events via gateway"
    else
        fail "Audit API" "empty response from /api/v1/audit/events"
    fi

    # Check governance
    GOV_RESPONSE=$(curl -sf "${GATEWAY_URL}/api/v1/governance/reviews" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" 2>/dev/null || echo "")

    if [ -n "$GOV_RESPONSE" ]; then
        pass "Governance API - list reviews via gateway"
    else
        fail "Governance API" "empty response from /api/v1/governance/reviews"
    fi

    # OIDC discovery
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
SCRIPT_EOF
chmod +x scripts/smoke-test.sh
```

- [ ] **Step 2: Verify the script is syntactically valid**

Run: `bash -n scripts/smoke-test.sh`
Expected: No output (no syntax errors)

- [ ] **Step 3: Commit**

```bash
git add scripts/smoke-test.sh
git commit -m "feat: add smoke test script for end-to-end PoC validation

Tests service health, OAuth token flow, API calls via gateway,
OIDC discovery, and admin console availability."
```

---

### Task 2: Fix seed.sh

**Files:**
- Modify: `scripts/seed.sh`

- [ ] **Step 1: Replace seed.sh with fixed version**

```bash
cat > scripts/seed.sh << 'SEED_EOF'
#!/bin/bash
# Database seeding script for OpenIDX
#
# Seed data is automatically loaded on first `docker compose up` via
# deployments/docker/init-db.sql. This script re-applies seed data
# to a running database for reset scenarios.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Default to docker-compose postgres
DATABASE_URL="${DATABASE_URL:-postgres://openidx:$(grep POSTGRES_PASSWORD "$PROJECT_ROOT/.env" 2>/dev/null | cut -d= -f2)@localhost:5432/openidx?sslmode=disable}"

echo -e "${BLUE}OpenIDX Database Seeder${NC}"
echo

# Check psql
if ! command -v psql &> /dev/null; then
    echo -e "${YELLOW}psql not found. Trying via docker...${NC}"
    PSQL_CMD="docker exec openidx-postgres psql -U openidx -d openidx"
else
    PSQL_CMD="psql $DATABASE_URL"
fi

# Check connectivity
if ! $PSQL_CMD -c '\q' 2>/dev/null; then
    echo -e "${RED}Error: Cannot connect to database${NC}"
    echo -e "  Make sure PostgreSQL is running (docker compose up -d postgres)"
    echo -e "  Or set DATABASE_URL environment variable"
    exit 1
fi

echo -e "${GREEN}Connected to database${NC}"

# Check if seed data already exists
ADMIN_EXISTS=$($PSQL_CMD -tAc "SELECT count(*) FROM users WHERE email='admin@openidx.local'" 2>/dev/null || echo "0")

if [ "$ADMIN_EXISTS" -gt 0 ] && [ "${1:-}" != "--force" ]; then
    echo -e "${YELLOW}Seed data already present (admin user exists)${NC}"
    echo -e "  Use ${BLUE}--force${NC} to re-apply"
    echo
    echo -e "${BLUE}Existing seed credentials:${NC}"
else
    echo -e "${GREEN}Applying seed data from init-db.sql...${NC}"
    $PSQL_CMD -f "$PROJECT_ROOT/deployments/docker/init-db.sql" 2>/dev/null || true
    echo -e "${GREEN}Done${NC}"
    echo
    echo -e "${BLUE}Seed credentials:${NC}"
fi

echo -e "  Admin:         ${GREEN}admin@openidx.local${NC}"
echo -e "  Test users:    jsmith, jdoe, bwilson, amartin"
echo -e "  OAuth clients: admin-console (public), api-service (confidential), test-client"
echo -e "  API client:    ${GREEN}api-service${NC} / ${GREEN}api-service-secret${NC}"
echo -e "  Roles:         admin, user, manager, auditor, developer"
echo -e "  Groups:        Administrators, Developers, DevOps, QA, Finance, HR"
SEED_EOF
chmod +x scripts/seed.sh
```

- [ ] **Step 2: Verify syntax**

Run: `bash -n scripts/seed.sh`
Expected: No output (no syntax errors)

- [ ] **Step 3: Commit**

```bash
git add scripts/seed.sh
git commit -m "fix: update seed.sh to work with init-db.sql

Removes dependency on missing migration file. Adds --force flag,
docker fallback for psql, and documents all seed credentials."
```

---

### Task 3: Add Makefile target

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Add smoke-test target after test-e2e**

Add after line 115 (`cd web/admin-console && npx playwright test`):

```makefile
smoke-test:
	@echo "🔥 Running smoke tests..."
	@./scripts/smoke-test.sh
```

- [ ] **Step 2: Verify Makefile parses**

Run: `make -n smoke-test`
Expected: Shows `echo` and `./scripts/smoke-test.sh` commands

- [ ] **Step 3: Commit**

```bash
git add Makefile
git commit -m "feat: add make smoke-test target for PoC validation"
```

---

### Task 4: Push and verify

- [ ] **Step 1: Verify Go build still passes**

Run: `go build ./...`
Expected: No output (clean build)

- [ ] **Step 2: Verify Go tests still pass**

Run: `go test ./... 2>&1 | grep -c "^ok"`
Expected: `54`

- [ ] **Step 3: Push to main**

```bash
git push origin main
```
