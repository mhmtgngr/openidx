# PoC Finalization Design

## Problem

OpenIDX has all services compiling, tests passing, docker-compose valid, and seed data in init-db.sql. But there's no automated way to verify the stack works end-to-end after `docker compose up`. The seed script references a missing migration file. A first-time user has no quick confirmation that the platform is functional.

## Deliverables

### 1. Smoke Test Script (`scripts/smoke-test.sh`)

A lightweight bash script that proves the PoC works end-to-end without a browser. Runs after `docker compose up`.

**Steps:**
1. Wait for all services to report healthy (poll `/health` on ports 8001-8008)
2. Test OAuth client_credentials flow: POST to `http://localhost:8006/oauth/token` with `api-service` / `api-service-secret` credentials
3. Use the returned access token to call `GET /api/v1/identity/users` via the APISIX gateway (`http://localhost:8088`)
4. Verify the seeded admin user appears in the response
5. Call `GET /api/v1/audit/events` to verify audit service is recording
6. Print pass/fail summary with timing

**Design constraints:**
- Bash only, no external dependencies beyond `curl` and `jq`
- Timeout after 120s if services don't come up
- Exit 0 on success, exit 1 on failure (CI-friendly)
- Colorized output for terminal readability

### 2. Fix `scripts/seed.sh`

Current issue: references `migrations/010_seed_data.up.sql` which may not match what init-db.sql already loads.

Fix: Replace the migration-based approach with a clear message that seed data loads automatically via `deployments/docker/init-db.sql` on first `docker compose up`. Add a manual re-seed option that runs key INSERT statements against the running database for reset scenarios.

**Seed credentials (already in init-db.sql):**
- Admin: `admin@openidx.local` (id: 00000000-0000-0000-0000-000000000001)
- OAuth client: `admin-console` (public, PKCE)
- OAuth client: `api-service` / `api-service-secret` (confidential, client_credentials)
- OAuth client: `test-client` / `test-secret` (confidential, all flows)
- Test users: jsmith, jdoe, bwilson, amartin

### 3. Makefile target

Add `make smoke-test` target that runs `scripts/smoke-test.sh` for discoverability.

## Files to Create/Modify

| File | Action |
|------|--------|
| `scripts/smoke-test.sh` | Create - end-to-end verification script |
| `scripts/seed.sh` | Modify - fix migration reference, add manual re-seed |
| `Makefile` | Modify - add `smoke-test` target |

## Verification

After implementation:
1. `docker compose up -d` (services must be running)
2. `make smoke-test` passes with all checks green
3. `scripts/seed.sh` runs without errors
4. `go build ./...` still compiles
5. `go test ./...` still passes 54/54

## Out of Scope

- Playwright/browser-based E2E tests (separate effort)
- New seed data beyond what init-db.sql already provides
- Changes to service code
