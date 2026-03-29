# Sub-project 1: Code Completion & Cleanup

**Date:** 2026-03-29
**Status:** Approved
**Goal:** Eliminate all TODOs, stubs, placeholders, and build errors so OpenIDX is code-complete with clean, reviewable git history.
**Audience:** Team handoff — all changes must be self-explanatory in commit messages and code.

---

## Context

OpenIDX is ~85-90% complete. The codebase compiles and most services are fully implemented. However, 258 files of uncommitted changes sit on branch `team/fix-the-security-todo-at-internalauditst-1772300604`, several backend functions are stubbed, the frontend has 18 TypeScript errors and a placeholder route, and the security artifact has stale metadata.

This sub-project is the first of six phases toward production launch readiness:

1. **Code Completion & Cleanup** (this spec)
2. Test Suite Completion
3. CI/CD Pipeline
4. Production Hardening
5. Monitoring & Observability
6. Documentation & Runbooks

## Definition of Done

- `go build ./...` succeeds with zero warnings
- `npm run build` in `web/admin-console/` succeeds with zero TypeScript errors
- Zero TODO/FIXME comments remain in production code paths
- All 8 security vulnerabilities in `.team/artifacts/07_security.json` are marked "fixed"
- All changes committed in logical, reviewable commits (not one giant commit)
- No placeholder or stub functions remain in production code paths
- `.bak` files and dead code removed

---

## Section 1: Backend Code Gaps

### 1.1 V-007 AutoApproveConditions Validation

**File:** `internal/governance/workflows.go`
**Problem:** `AutoApproveConditions` struct exists but has no validation. Arbitrary values can be submitted.
**Fix:**
- Add `Validate() error` method on `AutoApproveConditions`:
  - `MaxRiskScore`: must be 0-100 if set
  - `AllowedRoles` / `AllowedGroups`: non-empty strings, max 64 chars each, max 50 entries
  - `MaxRequestCount`: must be positive if set
- Call `Validate()` in both `createApprovalPolicy` and `updateApprovalPolicy` handlers before marshaling
- Update `.team/artifacts/07_security.json`: V-007 status to "fixed", verdict to "ALL_FIXED"

### 1.2 Feature Flag Database Store

**File:** `internal/feature/flag.go:295`
**Problem:** `StorageDatabase` option falls back to `MemoryStore` instead of persisting to PostgreSQL.
**Fix:**
- Implement `DatabaseStore` struct satisfying the existing `Store` interface
- Methods: `Get`, `Set`, `Delete`, `List` — using pgx pool
- Add migration `030_feature_flags.up.sql` with table: `feature_flags(key TEXT PRIMARY KEY, value JSONB NOT NULL, updated_at TIMESTAMPTZ DEFAULT NOW())`
- Add corresponding `.down.sql`
- Wire `DatabaseStore` into the `NewFlagService` constructor when `StorageDatabase` is selected

### 1.3 Ed25519 Key Support

**File:** `internal/oauth/keys.go:209`
**Problem:** Only RSA-3072 is supported. Ed25519 is documented as a TODO.
**Fix:**
- Add `generateEd25519Key()` function using `crypto/ed25519`
- Add `ed25519Signer` implementing the existing key interface
- Support `EdDSA` algorithm in JWKS endpoint alongside `RS256`
- Make Ed25519 the default for newly generated keys; RSA remains supported for existing keys
- Add config option `OAUTH_KEY_ALGORITHM` (default: `EdDSA`, allowed: `EdDSA`, `RS256`)
- Update `internal/oauth/keys_test.go` with Ed25519 test cases

### 1.4 MaxMind GeoIP Provider

**File:** `internal/risk/ip.go:281-288`
**Problem:** `lookupMaxMind()` returns hardcoded "Unknown" data.
**Fix:**
- Implement using `github.com/oschwald/geoip2-golang`
- Config: `GEOIP_DB_PATH` for GeoLite2-City.mmdb location
- Graceful degradation: if DB file missing, log warning and return unknown (current behavior) rather than failing
- Return country code, country name, city, latitude/longitude from the DB

### 1.5 Gateway Middleware Placeholders

**Files:** `internal/gateway/service.go:323-335`
**Problem:** `rateLimitMiddleware()` and `authMiddleware()` are placeholder functions.
**Fix:**
- Verify `ratelimit.go` and `auth.go` exist with real implementations
- Wire the placeholder functions to delegate to the real implementations
- If the real implementations don't exist, implement them:
  - Rate limiting: Redis-backed sliding window, configurable per-route limits
  - Auth: JWT validation using JWKS endpoint, token extraction from Authorization header

### 1.6 WebAuthn Endpoint Gaps

**Files:** Integration test skips at `test/integration/auth_flows_test.go:789,802`
**Problem:** Tests skip because WebAuthn registration and credential endpoints are not accessible.
**Fix:**
- Verify endpoints exist in identity service router
- If missing, add `POST /api/v1/identity/users/:id/webauthn/register` and `GET /api/v1/identity/users/:id/webauthn/credentials`
- These should delegate to existing `internal/mfa/webauthn_auth.go` logic
- Un-skip the integration tests

### 1.7 Security Artifact Update

**File:** `.team/artifacts/07_security.json`
**Fix:** After all code fixes are applied:
- V-007 status: "fixed"
- verdict: "ALL_FIXED"
- security_score: update to reflect all fixes

### 1.8 Team State Update

**File:** `.team/state.json`
**Fix:** Update phases to reflect completion of security phase and progress of deploy phase.

---

## Section 2: Frontend Fixes

### 2.1 TypeScript Build Errors (18 errors)

**Fix each category:**

1. **Unused imports** (5 errors in test files):
   - `mfa-setup-wizard.test.tsx`: remove unused `waitFor`, `userEvent`
   - `WebAuthnCredentials.test.tsx`: remove unused `waitFor`, `userEvent`
   - `user-profile.test.tsx`: remove unused `screen`
   - `audit-stream.test.ts`: remove unused `data` variable

2. **Wrong component name** (6 errors):
   - `WebAuthnCredentials.test.tsx`: `WebAuthnCredentialsPage` not found — fix to match the actual exported component name

3. **Variable declaration order** (2 errors):
   - `WebAuthnCredentials.test.tsx`: `mockCredentials` used before declaration — move declaration above usage

4. **Type mismatches** (5 errors):
   - `audit.test.ts`: `ApiError` mock objects include `status` property not in type — fix mock construction to match `ApiError` interface
   - `audit.test.ts`: `outcome` field string type — use literal type assertion

### 2.2 Profile Page Implementation

**File:** `web/admin-console/src/App.tsx:169`
**Problem:** `/profile` route renders inline "coming soon" div.
**Fix:**
- Create `web/admin-console/src/pages/profile.tsx`
- Sections: user info display, password change form, MFA device management, active sessions list
- Follow existing page patterns (React Query for data fetching, Radix UI components, Tailwind styling)
- Wire into the route in `App.tsx`

### 2.3 E2E Test Failures

**Deferred to Sub-project 2 (Test Suite Completion).** Root cause analysis needed; likely auth/environment setup issues rather than component bugs.

---

## Section 3: Infrastructure & Cleanup

### 3.1 New Migration

- `migrations/030_feature_flags.up.sql` — create `feature_flags` table
- `migrations/030_feature_flags.down.sql` — drop table

### 3.2 Logical Commits

Stage and commit in this order (each a separate commit):
1. Security fixes (V-007 validation, artifact update)
2. Backend feature completions (feature flags DB store, Ed25519, GeoIP, gateway middleware)
3. WebAuthn endpoint wiring
4. Frontend TypeScript fixes
5. Profile page implementation
6. Migration files
7. Infrastructure/config changes
8. Dead code and `.bak` file cleanup

### 3.3 Dead Code Removal

- Delete `internal/common/config/config.go.bak`
- Scan for unused exports and unreferenced files
- Remove any orphaned test fixtures

---

## Out of Scope

- E2E test fixes (Sub-project 2)
- CI/CD pipeline (Sub-project 3)
- Security headers, TLS hardening (Sub-project 4)
- Monitoring dashboards (Sub-project 5)
- Documentation and runbooks (Sub-project 6)
- Performance optimization
- New features not described above
