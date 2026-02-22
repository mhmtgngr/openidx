#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# OpenIDX Autopilot — Pure Claude Code
# No n8n, no Z.ai, no SSH, no containers. Just Claude Code.
#
# Usage:
#   ./autopilot.sh                    # Run all phases (background)
#   ./autopilot.sh --phase 1          # Run phase 1 only
#   ./autopilot.sh --phase 2 --phase 3  # Run phases 2 and 3
#   ./autopilot.sh --resume           # Resume from last completed
#   ./autopilot.sh --list             # Show all phases
#   ./autopilot.sh --status           # Show progress (live tail)
#   ./autopilot.sh --fg               # Run in foreground (don't detach)
#   ./autopilot.sh --stop             # Stop running autopilot
#
# Survives SSH disconnect — runs in background with nohup.
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ── Config ──
REPO_DIR="${OPENIDX_REPO:-$HOME/openidx}"
LOG_DIR="$REPO_DIR/.autopilot"
STATE_FILE="$LOG_DIR/state.json"
LIVE_LOG="$LOG_DIR/live.log"
PID_FILE="$LOG_DIR/autopilot.pid"
CLAUDE_MODEL="${CLAUDE_MODEL:-opus}"
MAX_RETRIES=2
DOCKER_COMPOSE="${DOCKER_COMPOSE_FILE:-$REPO_DIR/deployments/docker/docker-compose.yml}"
PLAYWRIGHT_DIR="$REPO_DIR/frontend"

# ── Colors ──
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; B='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${G}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LIVE_LOG"; }
warn() { echo -e "${Y}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LIVE_LOG"; }
err()  { echo -e "${R}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LIVE_LOG"; }
info() { echo -e "${B}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LIVE_LOG"; }

# ── State Management ──
mkdir -p "$LOG_DIR"
touch "$LIVE_LOG"

save_state() {
  local phase="$1" step="$2" status="$3"
  python3 -c "
import json, os
f='$STATE_FILE'
d = json.load(open(f)) if os.path.exists(f) else {'phases':{}}
d['phases']['$phase'] = d['phases'].get('$phase', {})
d['phases']['$phase']['$step'] = '$status'
d['phases']['$phase']['updated'] = '$(date -Iseconds)'
d['last_phase'] = '$phase'
d['last_step'] = '$step'
json.dump(d, open(f,'w'), indent=2)
"
}

get_state() {
  local phase="$1" step="$2"
  python3 -c "
import json, os
f='$STATE_FILE'
if not os.path.exists(f): print('pending'); exit()
d = json.load(open(f))
print(d.get('phases',{}).get('$phase',{}).get('$step','pending'))
" 2>/dev/null || echo "pending"
}

# ── Core: Run Claude Code ──
run_claude() {
  local phase="$1"
  local step="$2"
  local branch="$3"
  local prompt="$4"
  local log_file="$LOG_DIR/${phase}_${step}.log"

  # Check if already done
  local state=$(get_state "$phase" "$step")
  if [ "$state" = "done" ]; then
    info "  ⏭  Already done: $phase/$step (skip)"
    return 0
  fi

  log "  🤖 Running: $step"
  save_state "$phase" "$step" "running"

  # Create/checkout branch
  cd "$REPO_DIR"
  git checkout main 2>/dev/null || true
  git pull origin main 2>/dev/null || true

  if git rev-parse --verify "$branch" >/dev/null 2>&1; then
    git checkout "$branch"
  else
    git checkout -b "$branch"
  fi

  # Run Claude Code
  local attempt=0
  local success=false

  while [ $attempt -le $MAX_RETRIES ]; do
    attempt=$((attempt + 1))

    if [ $attempt -gt 1 ]; then
      warn "  ↻ Retry $attempt/$MAX_RETRIES"
    fi

    if claude -p \
      --model "$CLAUDE_MODEL" \
      --dangerously-skip-permissions \
      "$prompt" \
      2>&1 | tee "$log_file"; then

      # Check if Claude actually made changes
      if git diff --quiet && git diff --cached --quiet; then
        warn "  ⚠ No changes made"
        # Not necessarily a failure — Claude might have determined no changes needed
      fi

      success=true
      break
    else
      err "  ✗ Claude Code failed (attempt $attempt)"
      sleep 5
    fi
  done

  if [ "$success" = true ]; then
    # Commit and push
    cd "$REPO_DIR"
    git add -A
    if ! git diff --cached --quiet; then
      git commit -m "autopilot: $phase/$step — $step" 2>/dev/null || true
      git push origin "$branch" 2>/dev/null || true
      log "  ✓ Committed and pushed: $branch"
    fi
    save_state "$phase" "$step" "done"
    return 0
  else
    save_state "$phase" "$step" "failed"
    return 1
  fi
}

# ── Core: Run Tests ──
run_tests() {
  local service="$1"
  local log_file="$LOG_DIR/test_${service}.log"

  log "  🧪 Testing: $service"

  cd "$REPO_DIR"

  if [ "$service" = "all" ]; then
    go test ./... -count=1 -timeout 120s 2>&1 | tee "$log_file"
  else
    go test ./internal/${service}/... -count=1 -timeout 120s 2>&1 | tee "$log_file"
  fi

  local exit_code=${PIPESTATUS[0]}

  if [ $exit_code -eq 0 ]; then
    log "  ✓ Tests passed: $service"
  else
    warn "  ⚠ Tests failed: $service (exit $exit_code)"
  fi

  return $exit_code
}

# ── Core: Fix Tests ──
fix_tests() {
  local branch="$1"
  local service="$2"
  local test_output="$3"

  log "  🔧 Fixing tests: $service"

  cd "$REPO_DIR"
  git checkout "$branch" 2>/dev/null

  local last_50=$(tail -50 "$test_output")

  claude -p \
    --model "$CLAUDE_MODEL" \
    --dangerously-skip-permissions \
    "Read CLAUDE.md first. The tests for $service are failing. Fix ONLY the test failures, do not change application logic. Here are the test errors:

$last_50

Fix the failing tests and ensure they pass." \
    2>&1 | tee "$LOG_DIR/fix_${service}.log"

  git add -A
  if ! git diff --cached --quiet; then
    git commit -m "autopilot: fix tests for $service" 2>/dev/null || true
    git push origin "$branch" 2>/dev/null || true
  fi
}

# ── Core: Docker Build + Run ──
build_docker() {
  local services=("$@")
  local all_ok=true

  for svc in "${services[@]}"; do
    local dockerfile="deployments/docker/Dockerfile.${svc}"
    if [ ! -f "$REPO_DIR/$dockerfile" ]; then
      warn "  ⚠ No Dockerfile for $svc, skipping"
      continue
    fi

    log "  🐳 Building: $svc"
    cd "$REPO_DIR"

    if podman build -f "$dockerfile" -t "openidx/${svc}:dev" . 2>&1 | tee -a "$LOG_DIR/docker_build.log" | tail -10; then
      log "  ✓ Built: openidx/${svc}:dev"
    else
      err "  ✗ Build failed: $svc"
      all_ok=false

      # Let Claude fix the Dockerfile
      warn "  🤖 Claude fixing Docker build..."
      local build_err=$(tail -30 "$LOG_DIR/docker_build.log")
      claude -p \
        --model "$CLAUDE_MODEL" \
        --dangerously-skip-permissions \
        "Read CLAUDE.md. Docker build failed for $svc. Fix the build error. Only fix Dockerfile or Go compilation issues, not application logic. Error:
$build_err" \
        2>&1 | tee -a "$LOG_DIR/docker_fix_${svc}.log"

      git add -A && git commit -m "autopilot: fix docker build for $svc" 2>/dev/null || true

      # Retry
      if podman build -f "$dockerfile" -t "openidx/${svc}:dev" . 2>&1 | tail -5; then
        log "  ✓ Built on retry: openidx/${svc}:dev"
      else
        err "  ✗ Build still failing: $svc"
        all_ok=false
      fi
    fi
  done

  $all_ok
}

# ── Core: Docker Run (start services) ──
docker_run() {
  log "  🚀 Starting services..."
  cd "$REPO_DIR"

  # Use docker-compose if available
  if [ -f "$DOCKER_COMPOSE" ]; then
    podman-compose -f "$DOCKER_COMPOSE" up -d 2>&1 | tee -a "$LOG_DIR/docker_run.log" | tail -10
    log "  ✓ Services started via docker-compose"
    sleep 10  # Wait for services to be ready

    # Health check
    local healthy=0
    local total=0
    for port in 8081 8082 8083 8084 8085 8086; do
      total=$((total + 1))
      if curl -sf "http://localhost:${port}/health" >/dev/null 2>&1; then
        healthy=$((healthy + 1))
      fi
    done
    log "  Health: $healthy/$total services healthy"
    return 0
  fi

  # Fallback: run individual containers
  local services=("identity-service" "oauth-service" "governance-service" "audit-service" "admin-service")

  for svc in "${services[@]}"; do
    local image="openidx/${svc}:dev"
    local name="openidx-${svc}"

    # Stop existing
    podman rm -f "$name" 2>/dev/null || true

    if podman image exists "$image" 2>/dev/null; then
      podman run -d \
        --name "$name" \
        --network openidx-net \
        -e DATABASE_URL="${DATABASE_URL:-postgres://openidx:openidx@localhost:5432/openidx?sslmode=disable}" \
        -e REDIS_URL="${REDIS_URL:-redis://localhost:6379}" \
        "$image" 2>&1 | tee -a "$LOG_DIR/docker_run.log"
      log "  ✓ Started: $name"
    else
      warn "  ⚠ Image not found: $image (skipping)"
    fi
  done

  # Create network if needed
  podman network exists openidx-net 2>/dev/null || podman network create openidx-net 2>/dev/null || true

  sleep 10
  log "  ✓ Services started"
}

# ── Core: Docker Stop ──
docker_stop() {
  log "  🛑 Stopping services..."

  if [ -f "$DOCKER_COMPOSE" ]; then
    cd "$REPO_DIR"
    podman-compose -f "$DOCKER_COMPOSE" down 2>/dev/null || true
  else
    for svc in identity-service oauth-service governance-service audit-service admin-service; do
      podman rm -f "openidx-${svc}" 2>/dev/null || true
    done
  fi

  log "  ✓ Services stopped"
}

# ── Core: Playwright E2E Tests ──
run_playwright() {
  local phase="$1"
  local log_file="$LOG_DIR/playwright_${phase}.log"

  log "  🎭 Running Playwright E2E tests..."

  # Check if frontend/playwright exists
  if [ ! -d "$PLAYWRIGHT_DIR" ]; then
    warn "  ⚠ No frontend directory at $PLAYWRIGHT_DIR, skipping Playwright"
    return 0
  fi

  cd "$PLAYWRIGHT_DIR"

  # Install deps if needed
  if [ ! -d "node_modules" ]; then
    log "  📦 Installing frontend dependencies..."
    npm install 2>&1 | tail -5
    npx playwright install --with-deps 2>&1 | tail -5
  fi

  # Run Playwright
  if npx playwright test --reporter=list 2>&1 | tee "$log_file" | tail -20; then
    log "  ✓ Playwright tests passed"
    save_state "$phase" "playwright" "done"
    return 0
  else
    local exit_code=${PIPESTATUS[0]}
    warn "  ⚠ Playwright tests failed (exit $exit_code)"
    save_state "$phase" "playwright" "failed"

    # Let Claude fix
    local test_errors=$(tail -40 "$log_file")
    cd "$REPO_DIR"

    claude -p \
      --model "$CLAUDE_MODEL" \
      --dangerously-skip-permissions \
      "Read CLAUDE.md. Playwright E2E tests are failing. Fix the test failures or the application code causing them. Only fix what's broken.

Test output:
$test_errors" \
      2>&1 | tee -a "$LOG_DIR/playwright_fix_${phase}.log"

    git add -A && git commit -m "autopilot: fix playwright tests (phase $phase)" 2>/dev/null || true

    # Retry
    cd "$PLAYWRIGHT_DIR"
    if npx playwright test --reporter=list 2>&1 | tee -a "$log_file" | tail -10; then
      log "  ✓ Playwright tests passed on retry"
      save_state "$phase" "playwright" "done"
      return 0
    else
      err "  ✗ Playwright tests still failing"
      save_state "$phase" "playwright" "failed"
      return 1
    fi
  fi
}

# ── Background Execution ──
is_running() {
  if [ -f "$PID_FILE" ]; then
    local pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
    rm -f "$PID_FILE"
  fi
  return 1
}

stop_autopilot() {
  if is_running; then
    local pid=$(cat "$PID_FILE")
    log "Stopping autopilot (PID: $pid)..."
    kill -TERM "$pid" 2>/dev/null || true

    # Also kill child claude processes
    pkill -P "$pid" 2>/dev/null || true
    pkill -f "claude.*dangerously-skip-permissions" 2>/dev/null || true

    rm -f "$PID_FILE"
    log "✓ Stopped"
  else
    log "Autopilot not running"
  fi
}

run_in_background() {
  local args="$*"

  if is_running; then
    local pid=$(cat "$PID_FILE")
    err "Autopilot already running (PID: $pid)"
    echo "  Use: ./autopilot.sh --status   to monitor"
    echo "  Use: ./autopilot.sh --stop     to stop"
    exit 1
  fi

  log "Starting autopilot in background..."
  log "Log: tail -f $LIVE_LOG"
  echo ""

  # Re-exec self with --fg in background
  nohup bash "$0" --fg $args >> "$LIVE_LOG" 2>&1 &
  local bg_pid=$!
  echo "$bg_pid" > "$PID_FILE"

  log "✓ Running in background (PID: $bg_pid)"
  echo ""
  echo "  Monitor:  tail -f $LIVE_LOG"
  echo "  Status:   ./autopilot.sh --status"
  echo "  Stop:     ./autopilot.sh --stop"
  echo ""
  echo "Safe to close SSH — autopilot continues."

  exit 0
}

# ── Core: Merge to Main ──
merge_branch() {
  local branch="$1"

  cd "$REPO_DIR"
  git checkout main 2>/dev/null
  git pull origin main 2>/dev/null || true

  if git merge "$branch" --no-ff -m "Merge $branch into main" 2>/dev/null; then
    git push origin main 2>/dev/null || true
    log "  ✓ Merged: $branch → main"
    return 0
  else
    err "  ✗ Merge conflict on: $branch"
    git merge --abort 2>/dev/null || true

    # Let Claude fix it
    warn "  🤖 Asking Claude to resolve merge conflict..."
    git checkout main
    git merge "$branch" --no-commit 2>/dev/null || true

    claude -p \
      --model "$CLAUDE_MODEL" \
      --dangerously-skip-permissions \
      "There is a git merge conflict merging $branch into main. Resolve all conflicts keeping both sets of changes where possible. Run 'git diff' to see conflicts, fix them, then 'git add' the resolved files." \
      2>&1 | tee "$LOG_DIR/merge_conflict.log"

    git add -A
    git commit -m "Merge $branch into main (conflict resolved by autopilot)" 2>/dev/null || true
    git push origin main 2>/dev/null || true
    log "  ✓ Merged with conflict resolution: $branch → main"
  fi
}

# ── Phase Runner ──
run_phase() {
  local phase_num="$1"
  local phase_name="$2"
  local branch="openidx/phase-${phase_num}"
  shift 2

  echo ""
  log "═══════════════════════════════════════════════════"
  log "PHASE $phase_num — $phase_name"
  log "═══════════════════════════════════════════════════"

  local phase_start=$(date +%s)

  # Run all steps
  while [ $# -gt 0 ]; do
    local step_name="$1"
    local step_prompt="$2"
    local step_service="${3:-all}"
    local step_docker="${4:-}"
    shift 4 2>/dev/null || shift $#

    run_claude "$phase_num" "$step_name" "$branch" "$step_prompt"

    # Run tests if service specified
    if [ "$step_service" != "none" ]; then
      local test_log="$LOG_DIR/test_${step_name}.log"
      if ! run_tests "$step_service" 2>"$test_log"; then
        fix_tests "$branch" "$step_service" "$test_log"
        run_tests "$step_service" || warn "  ⚠ Tests still failing after fix"
      fi
    fi

    # Docker build if requested
    if [ -n "$step_docker" ]; then
      IFS=',' read -ra DOCKER_SVCS <<< "$step_docker"
      build_docker "${DOCKER_SVCS[@]}" || warn "  ⚠ Some Docker builds failed"

      # Start services and run E2E tests
      docker_run
      run_playwright "$phase_num" || warn "  ⚠ Playwright tests had failures"
      docker_stop
    fi
  done

  # Merge to main
  merge_branch "$branch"

  local elapsed=$(( $(date +%s) - phase_start ))
  log "✅ Phase $phase_num complete in $((elapsed/60))m $((elapsed%60))s"
  save_state "$phase_num" "_phase" "done"
}


# ═══════════════════════════════════════════════
# PHASE DEFINITIONS
# ═══════════════════════════════════════════════

phase_1() {
  run_phase 1 "Foundation — Auth + Security" \
    "auth-core" \
    "Read CLAUDE.md first. Implement authentication foundation for OpenIDX (Go/Gin Zero Trust IAM platform).

Create these files:
1. internal/auth/token.go — JWT access+refresh token generation using RS256, token validation, claims extraction (sub, roles, tenant_id, exp, iat), token revocation via Redis blacklist
2. internal/auth/password.go — bcrypt and argon2id password hashing, password strength validation (min 12 chars, upper+lower+digit+special), migration function from bcrypt to argon2id
3. internal/auth/session.go — Redis-backed session store: Create, Get, Delete, ListByUser, enforce max concurrent sessions (configurable, default 5), session timeout (configurable, default 24h)

Write table-driven unit tests for each file in corresponding _test.go files. Cover: valid tokens, expired tokens, revoked tokens, weak passwords, strong passwords, session limits, concurrent access." \
    "auth" \
    "" \
    \
    "rbac-middleware" \
    "Read CLAUDE.md first. Implement RBAC middleware for OpenIDX.

Create these files:
1. internal/auth/roles.go — Define roles: super_admin, admin, operator, auditor, user. Hierarchical: super_admin inherits all permissions below. Define permissions: users:read, users:write, users:delete, groups:manage, config:manage, audit:read, audit:export, policies:manage, tenants:manage
2. internal/auth/middleware.go — Gin middleware: extract JWT from Authorization Bearer header, validate token using token.go, load user roles from claims, RequireRole(roles ...string) middleware, RequirePermission(perms ...string) middleware, RequireAny(roles ...string) for OR logic
3. internal/auth/context.go — Helper functions: GetUserFromContext(c *gin.Context), GetRolesFromContext, GetTenantFromContext

Write unit tests covering: admin access allowed, user access denied to admin route, expired token rejected, missing auth header, role hierarchy inheritance, multiple permission requirements." \
    "auth" \
    "" \
    \
    "security-middleware" \
    "Read CLAUDE.md first. Implement security middleware stack for OpenIDX.

Create these files:
1. internal/middleware/ratelimit.go — Redis-backed sliding window rate limiter. Per-IP (100 req/min default) and per-user (200 req/min default) with configurable limits. Return 429 with Retry-After header.
2. internal/middleware/cors.go — Configurable CORS: allowed origins from env ALLOWED_ORIGINS, support credentials, preflight caching 24h
3. internal/middleware/requestid.go — Generate UUID X-Request-ID, propagate through context, add to response headers
4. internal/middleware/logging.go — Structured JSON logging with zerolog: method, path, status, duration_ms, request_id, user_id, ip, user_agent
5. internal/middleware/recovery.go — Panic recovery returning JSON error response with correlation ID, log stack trace

Write unit tests for rate limit enforcement, CORS headers, request ID propagation." \
    "all" \
    ""
}

phase_2() {
  run_phase 2 "Identity & Directory" \
    "identity-crud" \
    "Read CLAUDE.md first. Implement Identity service CRUD for OpenIDX.

Create/update these files:
1. internal/identity/model.go — User struct: ID(uuid), Email, FirstName, LastName, DisplayName, Status(active/suspended/deprovisioned), PasswordHash, MFAEnabled, TenantID, Metadata(jsonb), CreatedAt, UpdatedAt, LastLoginAt. Group struct: ID, Name, Description, TenantID, Members[]
2. internal/identity/repository.go — PostgreSQL with sqlx: InsertUser, GetUserByID, GetUserByEmail, UpdateUser, DeleteUser (soft delete), ListUsers(limit, offset, filters), SearchUsers(query string). Same for groups. Handle not-found vs internal errors distinctly.
3. internal/identity/service.go — Business logic layer: validate inputs, check duplicates, enforce tenant isolation, emit lifecycle events
4. internal/identity/handler.go — Gin handlers: POST /api/v1/users, GET /api/v1/users/:id, PUT /api/v1/users/:id, DELETE /api/v1/users/:id, GET /api/v1/users?page=&limit=&q=, same pattern for /groups and /groups/:id/members

Write unit tests for service layer with mocked repository. Cover: create success, duplicate email, not found, input validation, pagination, tenant isolation." \
    "identity" \
    "" \
    \
    "scim-provisioning" \
    "Read CLAUDE.md first. Implement SCIM 2.0 provisioning for OpenIDX per RFC 7644.

Create these files:
1. internal/identity/scim.go — SCIM endpoints: GET /scim/v2/Users (list+filter), POST /scim/v2/Users (create), GET /scim/v2/Users/:id, PUT /scim/v2/Users/:id (replace), PATCH /scim/v2/Users/:id (modify with add/replace/remove ops), DELETE /scim/v2/Users/:id. Same for /scim/v2/Groups. Bearer token auth.
2. internal/identity/scim_schema.go — SCIM JSON schema: userName, name{givenName,familyName}, emails[], active, groups[]. Marshal/unmarshal between SCIM and internal User model.
3. internal/identity/scim_filter.go — Parse SCIM filter expressions: eq, ne, co, sw, ew operators for userName, email, displayName. Convert to SQL WHERE clauses.
4. Support pagination with startIndex, count, totalResults in ListResponse.

Write unit tests for: filter parsing, SCIM JSON serialization, PATCH operations (add email, replace name, remove group), pagination." \
    "identity" \
    "" \
    \
    "directory-sync" \
    "Read CLAUDE.md first. Implement directory sync and identity lifecycle for OpenIDX.

Create these files:
1. internal/identity/directory.go — Directory sync interface and LDAP implementation: connect with bind credentials, search users/groups with configurable base DN and filters, attribute mapping (cn->FirstName, sn->LastName, mail->Email), incremental sync tracking last sync timestamp
2. internal/identity/lifecycle.go — Identity state machine: Created->Active->Suspended->Deprovisioned. Actions per transition: activate(set status, send welcome), suspend(revoke sessions, disable login), deprovision(remove access, anonymize PII after retention period). Webhook notifications on each transition.

Write unit tests for state transitions (valid and invalid), attribute mapping, webhook notification." \
    "identity" \
    "identity-service"
}

phase_3() {
  run_phase 3 "OAuth / OIDC / SSO" \
    "oauth-core" \
    "Read CLAUDE.md first. Implement OAuth 2.0 core flows for OpenIDX.

Create these files:
1. internal/oauth/client.go — OAuth client model and CRUD: ClientID, ClientSecret(hashed), RedirectURIs[], GrantTypes[], Scopes[], ClientName, TenantID. Registration endpoint POST /api/v1/oauth/clients. Client authentication: client_secret_basic, client_secret_post.
2. internal/oauth/authorize.go — Authorization endpoint GET/POST /oauth/authorize: validate client_id, redirect_uri, response_type=code, generate auth code with PKCE S256 support, state parameter validation, scope consent check.
3. internal/oauth/token.go — Token endpoint POST /oauth/token: authorization_code grant (with PKCE verify), refresh_token grant (with rotation — old refresh token invalidated), client_credentials grant. Return access_token, refresh_token, token_type, expires_in, scope.
4. internal/oauth/store.go — Redis-backed: auth code store (10min TTL, single-use), refresh token store with family tracking for rotation.

Write unit tests: auth code flow end-to-end, PKCE S256 validation, token refresh with rotation, client_credentials, expired code rejection, replay attack detection." \
    "oauth" \
    "" \
    \
    "oidc-discovery" \
    "Read CLAUDE.md first. Implement OpenID Connect for OpenIDX.

Create these files:
1. internal/oauth/oidc.go — OIDC layer: when scope includes 'openid', generate ID token (JWT) with claims: iss, sub, aud, exp, iat, auth_time, nonce, email, name, roles. UserInfo endpoint GET /oauth/userinfo returning profile claims from access token.
2. internal/oauth/discovery.go — Discovery endpoint GET /.well-known/openid-configuration returning: issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, scopes_supported, response_types_supported, grant_types_supported, subject_types_supported, id_token_signing_alg_values_supported.
3. internal/oauth/keys.go — RSA 2048 key pair management: generate, store in DB, expose GET /.well-known/jwks.json in JWK format, key rotation with overlap period (old key valid for 24h after rotation).
4. internal/oauth/consent.go — Consent management: store user consent per client+scopes, check existing consent, revoke consent, consent UI data endpoint.

Write unit tests: ID token claims validation, discovery doc contains all required fields, JWKS format correct, key rotation overlap, consent persistence." \
    "oauth" \
    "" \
    \
    "saml-sso" \
    "Read CLAUDE.md first. Implement SAML 2.0 Identity Provider for OpenIDX.

Create these files:
1. internal/oauth/saml.go — SAML IdP: SP-initiated SSO handling AuthnRequest, generate SAML Response with signed Assertion (XML-DSig RSA-SHA256), attribute statement mapping user fields to SAML attributes (email, firstName, lastName, groups, roles), support NameID formats: emailAddress, persistent, transient.
2. internal/oauth/saml_metadata.go — IdP metadata endpoint GET /saml/metadata returning EntityDescriptor XML with IDPSSODescriptor, signing certificate, SingleSignOnService bindings (POST, Redirect).
3. internal/oauth/saml_sp.go — SP registration and management: store SP entity ID, ACS URL, metadata URL, x509 cert. CRUD API for SP configuration.
4. internal/oauth/saml_slo.go — Single Logout: handle LogoutRequest, send LogoutResponse, notify other SPs in session.

Write unit tests: SAML response generation, XML signature, attribute mapping, metadata format." \
    "oauth" \
    "oauth-service"
}

phase_4() {
  run_phase 4 "MFA & Passwordless" \
    "totp-recovery" \
    "Read CLAUDE.md first. Implement TOTP MFA and recovery codes for OpenIDX.

Create these files:
1. internal/mfa/totp.go — RFC 6238 TOTP: generate random 20-byte secret, base32 encode, generate otpauth:// URI for QR codes (issuer=OpenIDX), verify TOTP with 30s time step and +/-1 window drift tolerance, rate limit verification attempts (5 per minute).
2. internal/mfa/recovery.go — Generate 10 recovery codes (8 alphanumeric chars each), bcrypt hash for storage, verify and consume (single-use), regenerate endpoint that invalidates old codes.
3. internal/mfa/enrollment.go — MFA enrollment flow: POST /mfa/enroll/totp returns secret+QR URI, POST /mfa/enroll/totp/verify confirms setup with initial code, POST /mfa/verify for login-time verification, POST /mfa/recovery/verify for recovery code use.

Write unit tests: TOTP generation matches reference vectors, drift tolerance, recovery code single-use, enrollment flow, rate limiting." \
    "mfa" \
    "" \
    \
    "webauthn-passkeys" \
    "Read CLAUDE.md first. Implement WebAuthn/FIDO2 passwordless auth for OpenIDX.

Create these files:
1. internal/mfa/webauthn.go — Using go-webauthn/webauthn library: BeginRegistration (generate challenge, credential creation options), FinishRegistration (verify attestation, store credential), BeginLogin (generate challenge, assertion options), FinishLogin (verify assertion, check sign count). Support platform authenticators (passkeys) and roaming authenticators (security keys).
2. internal/mfa/webauthn_store.go — PostgreSQL storage: credential_id, public_key, aaguid, sign_count, transports[], user_id, friendly_name, created_at, last_used_at. Support multiple credentials per user. List/delete credentials.
3. internal/mfa/webauthn_handler.go — Gin handlers: POST /mfa/webauthn/register/begin, POST /mfa/webauthn/register/finish, POST /mfa/webauthn/login/begin, POST /mfa/webauthn/login/finish, GET /mfa/webauthn/credentials, DELETE /mfa/webauthn/credentials/:id.

Write unit tests: registration ceremony, authentication ceremony, sign count validation, multiple credentials per user." \
    "mfa" \
    "" \
    \
    "adaptive-mfa" \
    "Read CLAUDE.md first. Implement adaptive MFA for OpenIDX.

Create these files:
1. internal/mfa/adaptive.go — Risk-based MFA policy engine. Evaluate signals: known_device(bool), known_ip(bool), known_location(bool), risk_score(0-100), login_time_normal(bool). Rules: all trusted signals + score<30 = skip MFA, score 30-70 = require TOTP, score>70 = require WebAuthn/hardware key, score>90 = block + alert admin.
2. internal/mfa/otp.go — Email and SMS OTP: generate 6-digit cryptographic random code, 5-minute TTL in Redis, max 3 verification attempts, rate limit 1 OTP per 60 seconds per user.
3. internal/mfa/provider.go — Provider interface with implementations: SMTPProvider (email OTP via SMTP), TwilioProvider (SMS via Twilio REST API, configurable), LogProvider (for development/testing, logs to stdout).

Write unit tests: adaptive policy evaluation scenarios, OTP generation/expiry, rate limiting, attempt limiting." \
    "mfa" \
    "identity-service"
}

phase_5() {
  run_phase 5 "Access Governance" \
    "policy-engine" \
    "Read CLAUDE.md first. Implement Zero Trust policy engine for OpenIDX.

Create these files:
1. internal/governance/policy.go — Policy model: ID, Name, Description, Effect(allow/deny), Conditions(JSON), Priority, Enabled, TenantID. Policy evaluator: evaluate(user, resource, context) → allow/deny. Support conditions with and/or/not operators matching user attributes, resource types, environment (time, IP, device).
2. internal/governance/policy_store.go — PostgreSQL storage with versioning: create, update(creates new version), get(latest or specific version), list, delete(soft), get_history. Audit trail of all policy changes.
3. internal/governance/policy_handler.go — Gin handlers: CRUD at /api/v1/policies, POST /api/v1/policies/evaluate for real-time decisions accepting {subject, resource, context}.

Write unit tests: policy evaluation with nested conditions, version history, evaluate endpoint with various scenarios." \
    "governance" \
    "" \
    \
    "jit-access" \
    "Read CLAUDE.md first. Implement JIT access and approval workflows for OpenIDX.

Create these files:
1. internal/governance/jit.go — Just-In-Time access: RequestElevation(user, role, duration, justification), GrantElevation (stores with TTL), background goroutine checking expired grants every 30s and revoking, ExtendGrant, RevokeGrant. Duration range: 15min to 8hrs.
2. internal/governance/request.go — Access request workflow: Submit(requester, requested_role, justification) → pending, approval chain (manager → security_team configurable), Approve/Deny with comments, auto-escalate after 24h, notification hooks on state changes (pending, approved, denied, expired).
3. internal/governance/certification.go — Access certification campaigns: CreateCampaign(scope, reviewers, deadline), generate review items from current role assignments, ReviewItem(confirm/revoke), track completion %, auto-revoke unreviewed items after deadline.

Write unit tests: JIT grant timing and auto-revoke, approval chain logic, certification workflow states." \
    "governance" \
    "governance-service"
}

phase_6() {
  run_phase 6 "Risk Engine" \
    "risk-scoring" \
    "Read CLAUDE.md first. Implement risk scoring engine for OpenIDX.

Create these files:
1. internal/risk/scorer.go — Calculate 0-100 risk score from weighted signals: ip_reputation(20%, check blocklist), device_trust(20%, known vs unknown), geo_distance(15%, km from usual location), login_velocity(15%, logins per hour), time_pattern(10%, deviation from usual hours), failed_attempts(10%, recent failures), vpn_tor(10%, detected proxy/tor). Return RiskAssessment{Score, Signals[], Recommendation}.
2. internal/risk/device.go — Device fingerprinting: hash of UserAgent+ScreenRes+Timezone+Language+Platform. Trust levels: trusted(seen 5+ times), known(seen before), unknown(first time), suspicious(fingerprint changed for known device). Store in Redis with user association.
3. internal/risk/ip.go — IP intelligence: GeoIP lookup (MaxMind GeoLite2 interface), VPN/Tor detection via configurable IP range lists, blocklist/allowlist CRUD, impossible travel detection (two logins from locations requiring faster-than-possible travel based on distance/time).

Write unit tests: score calculation with various signal combinations, impossible travel detection, device fingerprint matching, IP blocklist." \
    "risk" \
    "" \
    \
    "behavioral-analytics" \
    "Read CLAUDE.md first. Implement behavioral analytics for OpenIDX.

Create these files:
1. internal/risk/behavior.go — Track user behavior patterns in Redis: typical login hours (histogram), typical locations (list of lat/lon), typical devices (fingerprint list), typical resources accessed. Detect deviation: login at unusual hour (>2 std dev), new location (>500km from any known), new device + new location = high risk.
2. internal/risk/policy.go — Risk-based auth policies: configurable thresholds per tenant. Default: score<30 allow+no MFA, 30-50 require MFA, 50-70 require strong MFA, 70-90 require approval, >90 block+alert. POST /api/v1/risk/evaluate endpoint.
3. internal/risk/alert.go — Security alert system: generate alerts for high-risk events, deliver via: webhook(configurable URL), email(to security team), store in DB for dashboard. Alert model: ID, Severity, Type, UserId, Details, CreatedAt, AcknowledgedAt.

Write unit tests: behavior pattern tracking, deviation detection, policy threshold evaluation, alert generation." \
    "risk" \
    "identity-service"
}

phase_7() {
  run_phase 7 "Audit & Compliance" \
    "audit-logging" \
    "Read CLAUDE.md first. Implement audit logging for OpenIDX.

Create these files:
1. internal/audit/logger.go — Structured audit events: AuditEvent{ID, Timestamp, TenantID, ActorID, ActorType(user/system/api), Action(auth.login/user.create/role.assign/policy.change/etc), ResourceType, ResourceID, Outcome(success/failure/denied), IP, UserAgent, CorrelationID, Metadata(jsonb), PreviousHash, Hash}. HMAC-SHA256 chain linking each event to previous for tamper detection.
2. internal/audit/store.go — PostgreSQL with monthly partitions: batch insert (buffer 100 events or 5s flush), indexed on: timestamp, actor_id, action, resource_type. Verify chain integrity on read.
3. internal/audit/search.go — Search API: GET /api/v1/audit/events?actor=&action=&resource_type=&from=&to=&outcome= with cursor-based pagination (after_id parameter), max 100 per page.
4. internal/audit/handler.go — Gin handlers with RequirePermission(audit:read) middleware.

Write unit tests: HMAC chain integrity verification, tamper detection, search filtering, batch insert, pagination." \
    "audit" \
    "" \
    \
    "compliance-streaming" \
    "Read CLAUDE.md first. Implement compliance reporting and event streaming for OpenIDX.

Create these files:
1. internal/audit/compliance.go — Report generators returning structured JSON: SOC2Report (access reviews, password policy compliance, MFA adoption rate, session management), ISO27001Report (access control metrics, cryptography usage, operational security events), GDPRReport (data access logs, consent records, data subject requests, data deletion records). Each report covers a date range.
2. internal/audit/stream.go — Real-time event streaming: WebSocket endpoint GET /api/v1/audit/stream (auth required) with filter subscription (subscribe to specific event types), webhook delivery POST to configured URLs with exponential backoff retry (1s, 2s, 4s, max 5 retries).
3. internal/audit/anomaly.go — Anomaly detection rules: brute_force (>5 failed logins in 5min from same actor), privilege_escalation (role change + immediate sensitive action), bulk_access (>100 resource reads in 1min), off_hours_admin (admin action outside business hours). Emit alert events.

Write unit tests: report generation accuracy, WebSocket streaming, webhook retry logic, anomaly detection rules." \
    "audit" \
    "audit-service"
}

phase_8() {
  run_phase 8 "Admin Console Backend" \
    "admin-dashboard" \
    "Read CLAUDE.md first. Implement Admin service backend for OpenIDX.

Create these files:
1. internal/admin/dashboard.go — GET /api/v1/admin/dashboard returning: total_users, active_users_24h, mfa_adoption_pct, active_sessions, failed_logins_24h, avg_risk_score, top_risk_events(last 10), login_success_rate. Aggregate from other services via internal API calls.
2. internal/admin/tenant.go — Multi-tenancy: Tenant model (ID, Name, Domain, Plan, Config, CreatedAt), CRUD at /api/v1/admin/tenants, tenant isolation enforced via middleware injecting tenant_id into all queries, tenant-scoped configuration.
3. internal/admin/config.go — System configuration API at /api/v1/admin/config: password_policy(min_length, require_upper, require_digit, require_special, history_count), session_policy(timeout_minutes, max_concurrent), mfa_policy(required_for_roles[], allowed_methods[]), rate_limit(per_ip, per_user). Validate and persist to DB.
4. internal/admin/bulk.go — Bulk operations: POST /api/v1/admin/users/import (CSV upload, validate rows, create users, return success/error per row), GET /api/v1/admin/users/export (CSV download of all users, streaming response).
5. internal/admin/handler.go — Wire all handlers with RequireRole(super_admin, admin) middleware.

Write unit tests: dashboard aggregation, tenant isolation, config validation, CSV parsing with error rows." \
    "admin" \
    "admin-service"
}

phase_9() {
  run_phase 9 "Production Readiness" \
    "production-ready" \
    "Read CLAUDE.md first. Implement production readiness features across all OpenIDX services.

Create these files:
1. internal/health/health.go — Health check: GET /health returning {status: up/degraded/down, components: {database: {status, latency_ms}, redis: {status, latency_ms}, dependencies: [{name, status}]}}. GET /ready for k8s readiness (returns 503 if any critical component down).
2. internal/metrics/prometheus.go — Prometheus metrics using prometheus/client_golang: http_requests_total{method,path,status}, http_request_duration_seconds{method,path}, active_sessions_gauge, auth_attempts_total{outcome}, risk_score_histogram, mfa_verifications_total{method,outcome}. Expose GET /metrics.
3. internal/server/graceful.go — Graceful shutdown: listen for SIGTERM/SIGINT, stop accepting new requests, drain existing with 30s timeout, close DB and Redis connections, exit cleanly.
4. internal/api/version.go — API versioning: /v1/ URL prefix, X-API-Version response header, version negotiation middleware.

Add /health and /metrics endpoints to every service's router. Write unit tests for health check logic, metrics registration, graceful shutdown signal handling.

Also add to each service's main.go: the health, metrics, graceful shutdown, and versioning wiring." \
    "all" \
    "identity-service,oauth-service,governance-service,audit-service,admin-service"
}


# ═══════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════

show_list() {
  echo "OpenIDX Autopilot Phases:"
  echo ""
  echo "  Phase 1 — Foundation (Auth + RBAC + Middleware)     ~90 min"
  echo "  Phase 2 — Identity (CRUD + SCIM + Directory)       ~2 hrs"
  echo "  Phase 3 — OAuth (OAuth2 + OIDC + SAML)             ~2 hrs"
  echo "  Phase 4 — MFA (TOTP + WebAuthn + Adaptive)         ~90 min"
  echo "  Phase 5 — Governance (Policy + JIT Access)          ~70 min"
  echo "  Phase 6 — Risk (Scoring + Behavior)                 ~60 min"
  echo "  Phase 7 — Audit (Logging + Compliance)              ~60 min"
  echo "  Phase 8 — Admin (Dashboard + Tenants + Config)      ~45 min"
  echo "  Phase 9 — Production (Health + Metrics + Graceful)  ~35 min"
  echo ""
  echo "  Total: ~12 hours"
}

show_status() {
  echo "OpenIDX Autopilot Status:"
  echo ""

  if is_running; then
    local pid=$(cat "$PID_FILE")
    echo "  🔄 RUNNING (PID: $pid)"
    echo "  Live log: tail -f $LIVE_LOG"
    echo ""
    # Show last 5 lines
    if [ -f "$LIVE_LOG" ]; then
      echo "  Last activity:"
      tail -5 "$LIVE_LOG" | sed 's/^/    /'
      echo ""
    fi
  else
    echo "  ⏹  Not running"
    echo ""
  fi

  if [ -f "$STATE_FILE" ]; then
    python3 -c "
import json
d = json.load(open('$STATE_FILE'))
for phase, steps in sorted(d.get('phases',{}).items()):
    updated = steps.pop('updated','')
    done = sum(1 for s in steps.values() if s == 'done')
    total = len(steps)
    status = '✅' if steps.get('_phase') == 'done' else '🔄'
    print(f'  Phase {phase}: {status} {done}/{total} steps  (last: {updated})')
    for step, state in sorted(steps.items()):
        if step.startswith('_'): continue
        icon = '✓' if state == 'done' else '✗' if state == 'failed' else '⏳'
        print(f'    {icon} {step}: {state}')
"
  else
    echo "  No runs yet. Start with: ./autopilot.sh --phase 1"
  fi
}

show_help() {
  echo "Usage: ./autopilot.sh [options]"
  echo ""
  echo "Options:"
  echo "  (no args)          Run all phases 1-9 in background"
  echo "  --phase N          Run specific phase(s). Repeat for multiple."
  echo "  --resume           Resume from last completed phase"
  echo "  --fg               Run in foreground (don't detach)"
  echo "  --list             Show all phases"
  echo "  --status           Show current progress"
  echo "  --stop             Stop running autopilot"
  echo "  --reset            Clear all state and start fresh"
  echo "  -h, --help         Show this help"
  echo ""
  echo "Examples:"
  echo "  ./autopilot.sh                  # All phases, background, SSH-safe"
  echo "  ./autopilot.sh --phase 1        # Phase 1 only, background"
  echo "  ./autopilot.sh --phase 1 --fg   # Phase 1 in foreground"
  echo "  ./autopilot.sh --status         # Check progress anytime"
  echo "  tail -f ~/openidx/.autopilot/live.log  # Watch live"
}

# ── Parse Args ──
PHASES=()
RESUME=false
RESET=false
FOREGROUND=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --phase) PHASES+=("$2"); shift 2 ;;
    --resume) RESUME=true; shift ;;
    --fg) FOREGROUND=true; shift ;;
    --stop) mkdir -p "$LOG_DIR"; stop_autopilot; exit 0 ;;
    --list) show_list; exit 0 ;;
    --status) mkdir -p "$LOG_DIR"; show_status; exit 0 ;;
    --reset) RESET=true; shift ;;
    -h|--help) show_help; exit 0 ;;
    *) echo "Unknown option: $1"; show_help; exit 1 ;;
  esac
done

# Reset
if [ "$RESET" = true ]; then
  stop_autopilot 2>/dev/null || true
  rm -rf "$LOG_DIR"
  mkdir -p "$LOG_DIR"
  log "State cleared. Ready for fresh run."
  exit 0
fi

# Resume from last
if [ "$RESUME" = true ] && [ -f "$STATE_FILE" ]; then
  LAST=$(python3 -c "import json; d=json.load(open('$STATE_FILE')); print(d.get('last_phase','1'))")
  log "Resuming from phase $LAST"
  PHASES=()
  for i in $(seq "$LAST" 9); do
    PHASES+=("$i")
  done
fi

# Default: all phases
if [ ${#PHASES[@]} -eq 0 ]; then
  PHASES=(1 2 3 4 5 6 7 8 9)
fi

# ── Background execution (default) ──
# Unless --fg is passed, re-exec in background with nohup
if [ "$FOREGROUND" = false ]; then
  # Build args to pass through
  BG_ARGS=""
  for p in "${PHASES[@]}"; do
    BG_ARGS="$BG_ARGS --phase $p"
  done
  run_in_background $BG_ARGS
  # run_in_background exits, so we never reach here
fi

# ── Running in foreground (--fg or re-exec from background) ──
echo $$ > "$PID_FILE"
trap 'rm -f "$PID_FILE"; docker_stop 2>/dev/null; exit' EXIT INT TERM

# ── Preflight ──
log "═══════════════════════════════════════════════"
log "  OpenIDX Autopilot — Pure Claude Code"
log "═══════════════════════════════════════════════"
log "Repo:    $REPO_DIR"
log "Model:   $CLAUDE_MODEL"
log "Phases:  ${PHASES[*]}"
log "Logs:    $LOG_DIR/"
echo ""

# Verify Claude Code
if ! command -v claude &> /dev/null; then
  err "Claude Code not found. Install: npm install -g @anthropic-ai/claude-code"
  exit 1
fi

# Verify repo
if [ ! -d "$REPO_DIR/.git" ]; then
  err "Not a git repo: $REPO_DIR"
  exit 1
fi

cd "$REPO_DIR"

TOTAL_START=$(date +%s)

# ── Execute ──
for phase in "${PHASES[@]}"; do
  case $phase in
    1) phase_1 ;;
    2) phase_2 ;;
    3) phase_3 ;;
    4) phase_4 ;;
    5) phase_5 ;;
    6) phase_6 ;;
    7) phase_7 ;;
    8) phase_8 ;;
    9) phase_9 ;;
    *) err "Unknown phase: $phase" ;;
  esac
done

TOTAL_ELAPSED=$(( $(date +%s) - TOTAL_START ))
echo ""
log "═══════════════════════════════════════════════"
log "🎉 ALL DONE in $((TOTAL_ELAPSED/3600))h $((TOTAL_ELAPSED%3600/60))m"
log "═══════════════════════════════════════════════"
log "Logs:     $LOG_DIR/"
log "Status:   ./autopilot.sh --status"
log "Branches: git branch | grep openidx/"

# Cleanup
docker_stop 2>/dev/null || true
rm -f "$PID_FILE"
