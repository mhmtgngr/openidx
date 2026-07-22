# Dark Platform (Ziti-first) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make OpenIDX's own management/data surfaces "dark" (overlay-only, invisible to public scanners) behind a single hardened public bootstrap tier, reversibly and safely.

**Architecture:** Reuse the existing dark-app machinery. Add (1) a per-service loopback-bind flag, (2) a dark-mode route set for the APISIX edge, (3) two Ziti dial-policy attribute groups (`#enrolled-users`, `#device-trusted`) via the existing reconciler + user-sync, (4) a single hardened public `enroll` route (token/session/passkey → Ziti JWT), (5) cutover tooling (`scripts/dark-mode.sh`, `make dark-drill`) that verifies "public refused / overlay reachable / tier gate holds" before any public route is dropped. No new enforcement engine.

**Tech Stack:** Go (services + access-service), viper config, APISIX Admin API, OpenZiti (edge controller + reconciler), bash tooling, React admin console (BrowZer-served).

## Global Constraints

- **Tier 0 is always public — never add a flag that darks it.** Darking the login/JWKS/enroll gate bricks bootstrap.
- **Every phase is independently shippable and defaults to today's behavior** (`DARK_MODE_*` default `false`, `SERVICE_BIND_ADDR` default `0.0.0.0`).
- **Verify-before-cutover:** never drop a public route until `dark-mode.sh --verify` proves the overlay path works and the public path is refused.
- **Break-glass always exists:** `scripts/dark-mode.sh --undark` restores public routes from the host shell in one command; a sealed enroll token is kept out-of-band.
- Default org UUID constant: `00000000-0000-0000-0000-000000000010` (unchanged).
- Config env convention: viper `SetDefault("snake_case", …)` + env `OPENIDX_`/bare mapping as in `internal/common/config/config.go`. Follow the exact pattern of `default_org_fallback` → `DEFAULT_ORG_FALLBACK`.
- Reconciler is the **single owner** of Ziti mutations (`internal/access/ziti_reconciler.go`). Attribute/policy changes go through it, never hand-wired.
- Spec: `docs/superpowers/specs/2026-07-17-dark-platform-ziti-first-design.md`.
- Verify each Go change with `go build ./...` and `go vet ./...`; run touched-package tests.

---

## Phase 1 — Config flags + per-service loopback bind (no behavior change by default)

Adds the plumbing that lets a service go dark, defaulting off. Ships alone; changes nothing until flags are set.

### Task 1.1: Add `BindAddr` + `DarkModeTier1/Tier2` config fields

**Files:**
- Modify: `internal/common/config/config.go` (Config struct near line 31 `Port`; defaults near line 471; env map)
- Test: `internal/common/config/config_test.go`

**Interfaces:**
- Produces: `Config.BindAddr string` (mapstructure `bind_addr`), `Config.DarkModeTier1 bool` (`dark_mode_tier1`), `Config.DarkModeTier2 bool` (`dark_mode_tier2`), and a helper `Config.ListenAddr() string` returning `fmt.Sprintf("%s:%d", bindAddr, Port)` with `bindAddr` defaulting to empty (all interfaces) when unset.

- [ ] **Step 1: Write the failing test**

```go
// internal/common/config/config_test.go
func TestListenAddrDefaultsToAllInterfaces(t *testing.T) {
	c := &Config{Port: 8001}
	if got := c.ListenAddr(); got != ":8001" {
		t.Errorf("ListenAddr() = %q, want \":8001\"", got)
	}
}

func TestListenAddrHonorsBindAddr(t *testing.T) {
	c := &Config{Port: 8001, BindAddr: "127.0.0.1"}
	if got := c.ListenAddr(); got != "127.0.0.1:8001" {
		t.Errorf("ListenAddr() = %q, want \"127.0.0.1:8001\"", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/common/config/ -run TestListenAddr -v`
Expected: FAIL — `c.ListenAddr undefined`.

- [ ] **Step 3: Add the fields + helper**

In the `Config` struct (near `Port int` at line 31):
```go
	Port     int    `mapstructure:"port"`
	BindAddr string `mapstructure:"bind_addr"`
```
Add dark-mode flags near `DefaultOrgFallback` (line 104):
```go
	// DarkModeTier1/Tier2 gate the "dark platform" posture (see
	// docs/superpowers/specs/2026-07-17-dark-platform-ziti-first-design.md).
	// Default false → today's public behavior. Tier 0 is always public.
	DarkModeTier1 bool `mapstructure:"dark_mode_tier1"`
	DarkModeTier2 bool `mapstructure:"dark_mode_tier2"`
```
Add the helper (near the `Validate`/`GetRedisSentinelAddresses` helpers, ~line 826):
```go
// ListenAddr is the address the HTTP server binds. Empty BindAddr → ":<port>"
// (all interfaces, today's behavior); "127.0.0.1" → loopback-only ("dark").
func (c *Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.BindAddr, c.Port)
}
```
Add defaults + env mapping alongside the other `SetDefault` calls (~line 471) and the env key map used for `default_org_fallback`:
```go
	v.SetDefault("bind_addr", "")
	v.SetDefault("dark_mode_tier1", false)
	v.SetDefault("dark_mode_tier2", false)
```
In the env key map (where `"default_org_fallback": "DEFAULT_ORG_FALLBACK"` lives, ~line 683):
```go
		"bind_addr":       "SERVICE_BIND_ADDR",
		"dark_mode_tier1": "DARK_MODE_TIER1",
		"dark_mode_tier2": "DARK_MODE_TIER2",
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/common/config/ -run TestListenAddr -v`
Expected: PASS (both).

- [ ] **Step 5: Build + commit**

```bash
go build ./... && go vet ./internal/common/config/
git add internal/common/config/config.go internal/common/config/config_test.go
git commit -m "config: add BindAddr + DarkModeTier1/Tier2 flags (ListenAddr helper)"
```

### Task 1.2: Bind every service on `cfg.ListenAddr()`

**Files:**
- Modify: `cmd/identity-service/main.go:283`, `cmd/oauth-service/main.go`, `cmd/governance-service/main.go`, `cmd/provisioning-service/main.go`, `cmd/audit-service/main.go`, `cmd/admin-api/main.go`, `cmd/access-service/main.go`, `cmd/gateway-service/main.go` (each `http.Server{ Addr: fmt.Sprintf(":%d", cfg.Port) }`)

**Interfaces:**
- Consumes: `Config.ListenAddr()` from Task 1.1.

- [ ] **Step 1: Find every listen site**

Run: `grep -rn 'Addr: *fmt.Sprintf(":%d", cfg.Port)' cmd/`
Expected: one line per service main.

- [ ] **Step 2: Replace each with the helper**

For each match, change:
```go
Addr:         fmt.Sprintf(":%d", cfg.Port),
```
to:
```go
Addr:         cfg.ListenAddr(),
```
(If a service reads the port differently, keep its port source; only swap the address expression to `cfg.ListenAddr()`.)

- [ ] **Step 3: Build**

Run: `go build ./...`
Expected: success.

- [ ] **Step 4: Manual smoke — loopback bind works**

Run: `SERVICE_BIND_ADDR=127.0.0.1 go run ./cmd/identity-service &` then
`curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8001/health/live` → `200`,
and from another interface IP → connection refused. Kill the process.

- [ ] **Step 5: Commit**

```bash
go vet ./cmd/...
git add cmd/*/main.go
git commit -m "services: bind on cfg.ListenAddr() so SERVICE_BIND_ADDR can dark them"
```

---

## Phase 2 — Ziti dial-policy attribute groups (`#enrolled-users`, `#device-trusted`)

Extends the user-sync so every identity carries `#enrolled-users`, and `#device-trusted` reflects real device trust. Ships alone; adds attributes with no gating effect until services are modeled (Phase 4).

### Task 2.1: Add `#enrolled-users` to every synced identity

**Files:**
- Modify: `internal/access/ziti_user_sync.go` (`buildUserAttributes`, ~line 230-257)
- Test: `internal/access/ziti_user_sync_test.go` (or a new `_test.go` if none)

**Interfaces:**
- Produces: `buildUserAttributes` output always includes `"enrolled-users"`; still includes group names, and `device-trusted` when the user has a trusted device, `browzer-users` when BrowZer is on.

- [ ] **Step 1: Write the failing test**

```go
func TestBuildUserAttributesAlwaysIncludesEnrolledUsers(t *testing.T) {
	attrs := attributesForTest([]string{"engineering"}, /*deviceTrusted=*/false, /*browzer=*/false)
	if !contains(attrs, "enrolled-users") {
		t.Errorf("attrs %v missing enrolled-users", attrs)
	}
}
func TestBuildUserAttributesDeviceTrustedGated(t *testing.T) {
	trusted := attributesForTest(nil, true, false)
	untrusted := attributesForTest(nil, false, false)
	if !contains(trusted, "device-trusted") { t.Error("trusted device should carry device-trusted") }
	if contains(untrusted, "device-trusted") { t.Error("untrusted device must NOT carry device-trusted") }
}
```
(If `buildUserAttributes` needs a DB, extract the pure attribute-assembly into a helper `assembleAttributes(groups []string, deviceTrusted, browzer bool) []string` and test that; `attributesForTest` calls it.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/access/ -run TestBuildUserAttributes -v`
Expected: FAIL — `enrolled-users` absent.

- [ ] **Step 3: Implement**

In `buildUserAttributes` (or the extracted `assembleAttributes`), append `"enrolled-users"` to every result:
```go
	attrs = append(attrs, "enrolled-users")
	if deviceTrusted {
		attrs = append(attrs, "device-trusted")
	}
	// (existing group-name + browzer-users logic unchanged)
```
Confirm `device-trusted` is only appended when the user has a trusted device (existing `hasTrustedDevice`/`known_devices.trusted` check).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/access/ -run TestBuildUserAttributes -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
go build ./... && go vet ./internal/access/
git add internal/access/ziti_user_sync.go internal/access/ziti_user_sync_test.go
git commit -m "ziti-sync: tag every identity #enrolled-users; keep #device-trusted gated on trust"
```

### Task 2.2: Reconciler helper to create a tier dial policy

**Files:**
- Modify: `internal/access/ziti_reconciler.go` (near `CreateServicePolicy`/`EnsureServicePolicy`, ~line 334-371)
- Test: `internal/access/ziti_reconciler_test.go`

**Interfaces:**
- Produces: `func (rec *Reconciler) ensureTierDialPolicy(serviceName, tierAttr string) error` — upserts a dial policy `Dial: #<tierAttr> → #<serviceName>` (tierAttr ∈ `enrolled-users`, `device-trusted`), mirroring the existing `#browzer-users` dial upsert. Bind stays `#ziti-routers` (unchanged).

- [ ] **Step 1: Write the failing test (fake ziti client)**

```go
func TestEnsureTierDialPolicyBindsAttribute(t *testing.T) {
	fake := newFakeZiti()
	rec := &Reconciler{ziti: fake, logger: zap.NewNop()}
	if err := rec.ensureTierDialPolicy("openidx-admin-api", "device-trusted"); err != nil {
		t.Fatal(err)
	}
	p := fake.dialPolicyFor("openidx-admin-api")
	if p.dial != "#device-trusted" || p.serviceRole != "#openidx-admin-api" {
		t.Errorf("policy = %+v, want dial #device-trusted → #openidx-admin-api", p)
	}
}
```
(Reuse or extend the reconciler's existing fake/mocked ziti client used in its current tests; if none, add a minimal fake capturing `EnsureServicePolicy` calls.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/access/ -run TestEnsureTierDialPolicy -v`
Expected: FAIL — method undefined.

- [ ] **Step 3: Implement**

```go
// ensureTierDialPolicy upserts a dial policy granting #<tierAttr> the right to
// dial #<serviceName>. tierAttr is "enrolled-users" (Tier 1) or "device-trusted"
// (Tier 2). Bind is left to the existing #ziti-routers policy. Mirrors the
// #browzer-users dial upsert so it is idempotent/convergent.
func (rec *Reconciler) ensureTierDialPolicy(serviceName, tierAttr string) error {
	svcRole := "#" + serviceName
	return rec.ziti.EnsureServicePolicy(
		serviceName+"-dial-"+tierAttr, "Dial",
		[]string{svcRole}, []string{"#" + tierAttr})
}
```
(Match the exact `EnsureServicePolicy` signature already used in the file at ~line 356-371.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/access/ -run TestEnsureTierDialPolicy -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
go build ./... && go vet ./internal/access/
git add internal/access/ziti_reconciler.go internal/access/ziti_reconciler_test.go
git commit -m "ziti-reconciler: ensureTierDialPolicy for #enrolled-users / #device-trusted"
```

---

## Phase 3 — The `enroll` front door (Tier 0, the only new public surface)

A single hardened public route that trades an entitlement proof for a one-time Ziti enrollment JWT. Ships alone; adds a public capability with no darkening yet.

### Task 3.1: `POST /api/v1/access/enroll` — session/token/passkey → Ziti JWT

**Files:**
- Create: `internal/access/enroll_handler.go`
- Modify: `internal/access/service.go` (route registration near the agent routes ~line 826)
- Test: `internal/access/enroll_handler_test.go`

**Interfaces:**
- Consumes: existing `issueAgentCredentials`/Ziti identity minting (`agent_api.go:189-198` returns `ZitiJWT`), existing agent-token validation, existing JWT/session validation middleware.
- Produces: `func (s *Service) handleEnroll(c *gin.Context)`; request `{ "enrollment_token"?: string, "passkey"?: <assertion> }` (or a valid `Authorization: Bearer`); response `{ "ziti_enrollment_jwt": string, "identity_name": string, "expires_at": string }`. Rate-limited + audited; no DB browse.

- [ ] **Step 1: Write the failing test**

```go
func TestEnrollRejectsWithoutEntitlement(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/access/enroll", strings.NewReader(`{}`))
	c.Request.Header.Set("Content-Type", "application/json")
	svc := &Service{logger: zap.NewNop()}
	svc.handleEnroll(c)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no entitlement → %d, want 401", w.Code)
	}
}

func TestEnrollWithValidSessionReturnsZitiJWT(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("user_id", "00000000-0000-0000-0000-000000000001") // as auth middleware would
	c.Request = httptest.NewRequest("POST", "/api/v1/access/enroll", strings.NewReader(`{}`))
	c.Request.Header.Set("Content-Type", "application/json")
	svc := newEnrollTestService(t) // fake ziti minting returns "eyJ.jwt"
	svc.handleEnroll(c)
	if w.Code != 200 { t.Fatalf("status %d", w.Code) }
	var body map[string]any
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["ziti_enrollment_jwt"] == "" { t.Error("missing ziti_enrollment_jwt") }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/access/ -run TestEnroll -v`
Expected: FAIL — `handleEnroll` undefined.

- [ ] **Step 3: Implement the handler**

```go
// handleEnroll is the ONLY public access-service route in dark mode. It trades
// an entitlement proof (a live session set by auth middleware, an admin/MDM
// enrollment_token, or a passkey assertion) for a one-time Ziti enrollment JWT.
// No DB browsing; every issuance is audited. See the dark-platform spec §4.
func (s *Service) handleEnroll(c *gin.Context) {
	var req struct {
		EnrollmentToken string          `json:"enrollment_token"`
		Passkey         json.RawMessage `json:"passkey"`
	}
	_ = c.ShouldBindJSON(&req)

	userID, viaSession := c.Get("user_id")
	var subject string
	switch {
	case viaSession:
		subject = userID.(string)
	case req.EnrollmentToken != "":
		uid, err := s.validateEnrollmentToken(c.Request.Context(), req.EnrollmentToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid enrollment token"})
			return
		}
		subject = uid
	case len(req.Passkey) > 0:
		uid, err := s.validateEnrollPasskey(c.Request.Context(), req.Passkey)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "passkey verification failed"})
			return
		}
		subject = uid
	default:
		c.JSON(http.StatusUnauthorized, gin.H{"error": "entitlement required"})
		return
	}

	jwt, name, exp, err := s.mintZitiEnrollmentJWT(c.Request.Context(), subject)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("enroll: mint ziti jwt", err), s.logger)
		return
	}
	s.auditEnroll(c, subject, name) // audit event: who enrolled which identity
	c.JSON(http.StatusOK, gin.H{
		"ziti_enrollment_jwt": jwt, "identity_name": name, "expires_at": exp,
	})
}
```
Implement `validateEnrollmentToken` (reuse `agent_tokens` validation), `validateEnrollPasskey` (reuse identity WebAuthn assertion), `mintZitiEnrollmentJWT` (reuse the identity-minting path that already returns `ZitiJWT`), and `auditEnroll` (emit an audit event). Register the route in `service.go` **outside** any admin guard, next to the public agent routes (`service.go:826`):
```go
	api.POST("/enroll", s.rateLimitEnroll(), s.handleEnroll) // public in dark mode
```
Wrap with an aggressive rate-limit middleware (reuse the existing rate-limiter with a tight per-IP budget).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/access/ -run TestEnroll -v`
Expected: PASS.

- [ ] **Step 5: Build + commit**

```bash
go build ./... && go vet ./internal/access/
git add internal/access/enroll_handler.go internal/access/enroll_handler_test.go internal/access/service.go
git commit -m "access: public POST /api/v1/access/enroll (token/session/passkey -> ziti JWT), rate-limited + audited"
```

---

## Phase 4 — Dark-mode route set + cutover tooling (`dark-mode.sh`, `make dark-drill`)

The edge route set for dark mode, plus the verify/undark/self-test tooling. Ships alone; changes nothing until an operator runs it.

### Task 4.1: Dark-mode variant of the edge route seeder

**Files:**
- Modify: `deployments/apisix-edge/seed-edge-routes.sh` (route block)
- Test: `deployments/apisix-edge/seed-edge-routes.test.sh` (new bash test) or a `--dry-run` assertion

**Interfaces:**
- Produces: `DARK_MODE=tier2|tier1|off` env read by the seeder. `off` (default) = today's full route set. `tier2` = drop the management routes (`/api/v1/{admin catch-all pointing at 8005 management}, governance, audit, provisioning, scim, access` except `/api/v1/access/enroll`). `tier1` = additionally drop self-service/console public routes, leaving only Tier-0 (enroll, BrowZer hosts, `/oauth/*` auth subset, `/.well-known/*`, `/api/v1/identity/branding`).

- [ ] **Step 1: Write the failing test (dry-run route set assertion)**

```bash
# deployments/apisix-edge/seed-edge-routes.test.sh
set -euo pipefail
out=$(DARK_MODE=tier2 DRY_RUN=1 bash seed-edge-routes.sh 2>&1)
echo "$out" | grep -q 'openidx-api-admin' && { echo "FAIL: admin route present in tier2"; exit 1; }
echo "$out" | grep -q 'openidx-api-enroll'  || { echo "FAIL: enroll route missing in tier2"; exit 1; }
echo "$out" | grep -q 'openidx-wellknown'   || { echo "FAIL: well-known missing (Tier 0)"; exit 1; }
echo "OK tier2 route set"
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd deployments/apisix-edge && bash seed-edge-routes.test.sh`
Expected: FAIL (no `DARK_MODE`/`DRY_RUN` handling yet).

- [ ] **Step 3: Implement**

In `seed-edge-routes.sh`, add near the top:
```bash
DARK_MODE="${DARK_MODE:-off}"     # off | tier2 | tier1
DRY_RUN="${DRY_RUN:-0}"
put() { if [ "$DRY_RUN" = "1" ]; then echo "put $1"; else _put_real "$1" "$2"; fi; }
```
Add the enroll route to Tier 0 (always seeded):
```bash
put openidx-api-enroll "{$H,\"uri\":\"/api/v1/access/enroll\",\"priority\":40,\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1:8007\":1}}}"
```
Guard the management routes so they are skipped in tier2/tier1:
```bash
if [ "$DARK_MODE" = "off" ]; then
  put openidx-api-admin        "{...8005...}"
  put openidx-api-governance   "{...8002...}"
  put openidx-api-audit        "{...8004...}"
  put openidx-api-provisioning "{...8003...}"
  put openidx-scim             "{...8003...}"
  put openidx-api-access       "{...8007...}"   # keep enroll separate above
fi
```
Guard the self-service/console SPA + oauth-management routes so they are skipped in tier1 (Tier-0 auth subset — `/oauth/authorize`, `/oauth/token`, `/oauth/login`, `/oauth/native/login-init`, `/oauth/passkey-*`, `/oauth/mfa-*`, `/.well-known/*`, branding, BrowZer hosts — stays in every mode). Split the current single `openidx-oauth /oauth/*` route into the Tier-0 auth subset (always) vs the rest (off/tier1).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd deployments/apisix-edge && bash seed-edge-routes.test.sh`
Expected: `OK tier2 route set`.

- [ ] **Step 5: Commit**

```bash
git add deployments/apisix-edge/seed-edge-routes.sh deployments/apisix-edge/seed-edge-routes.test.sh
git commit -m "edge: DARK_MODE route set (drop mgmt routes in tier2, self-service in tier1; enroll + Tier-0 always)"
```

### Task 4.2: `scripts/dark-mode.sh` — verify / undark / self-test

**Files:**
- Create: `scripts/dark-mode.sh`
- Modify: `Makefile` (add `dark-drill` target + `.PHONY`)

**Interfaces:**
- Produces: `scripts/dark-mode.sh --verify [--self-test]`, `--undark`. `--verify` asserts, for each darked surface: public = refused (route gone / off-box loopback refused), overlay = 200, and a Tier-2 gate check (an `#enrolled-users`-only identity is refused Tier 2). `--self-test` mocks the overlay/loopback (à la `dr-game-day.sh`) so the verdict logic runs with no infra. `--undark` re-seeds `DARK_MODE=off` routes and prints the loopback-bind revert.

- [ ] **Step 1: Write the script skeleton with a self-test**

Model on `scripts/dr-game-day.sh` structure (arg parse, `log`/`fail`, a `--self-test` mock HTTP server, a verdict block). The self-test stands up a mock "public" server (returns 404 for `/api/v1/admin`, 200 for `/api/v1/access/enroll`) and a mock "overlay" server (200 for admin) and asserts the two-sided invariant.

- [ ] **Step 2: Wire the Makefile target**

```make
dark-drill:
	@bash scripts/dark-mode.sh --verify --self-test
```
Add `dark-drill` to the `.PHONY` line.

- [ ] **Step 3: Run the self-test (must pass green)**

Run: `make dark-drill`
Expected: verdict "✅ dark-mode invariant holds (public refused / overlay reachable / tier gate holds)".

- [ ] **Step 4: Negative self-test (must fail red)**

Temporarily make the mock public server return 200 for `/api/v1/admin`; run `--verify --self-test`; expected exit 1 with "public surface still reachable". Restore.

- [ ] **Step 5: Commit**

```bash
chmod +x scripts/dark-mode.sh
git add scripts/dark-mode.sh Makefile
git commit -m "tooling: dark-mode.sh (--verify/--undark/--self-test) + make dark-drill"
```

---

## Phase 5 — Model OpenIDX surfaces as tier'd dark services + console-as-dark-app

Registers each dark OpenIDX surface as a managed Ziti service with its tier dial policy, and the admin console as a BrowZer dark app. Ships alone; the reconciler creates policies but nothing is cut over until Phase 6.

### Task 5.1: Seed the dark-surface service definitions + reconcile tier policies

**Files:**
- Modify: `internal/access/ziti_reconciler.go` (reconcile loop — call `ensureTierDialPolicy` for the platform services)
- Create/seed: a `dark_services` definition (config or a seeded set) mapping `service → {upstream 127.0.0.1:800x, tier}`
- Test: `internal/access/ziti_reconciler_test.go`

**Interfaces:**
- Consumes: `ensureTierDialPolicy` (Task 2.2).
- Produces: for each platform surface (`openidx-admin-api`→8005/tier2, `openidx-governance`→8002/tier2, `openidx-audit`→8004/tier2, `openidx-provisioning`→8003/tier2, `openidx-scim`→8003/tier2, `openidx-access`→8007/tier2, `openidx-identity-selfservice`→8001/tier1, `openidx-console`→SPA/tier1) the reconciler ensures a service + `host.v1` to its loopback upstream + a tier dial policy.

- [x] **Step 1: Write the failing test**

```go
func TestReconcileCreatesTier2PolicyForAdminAPI(t *testing.T) {
	fake := newFakeZiti()
	rec := &Reconciler{ziti: fake, logger: zap.NewNop(), darkServices: defaultDarkServices()}
	rec.reconcileDarkServices()
	p := fake.dialPolicyFor("openidx-admin-api")
	if p.dial != "#device-trusted" { t.Errorf("admin-api dial = %q, want #device-trusted", p.dial) }
	s := fake.serviceFor("openidx-admin-api")
	if s.upstream != "127.0.0.1:8005" { t.Errorf("admin-api upstream = %q", s.upstream) }
}
func TestReconcileTier1PolicyForConsole(t *testing.T) {
	fake := newFakeZiti()
	rec := &Reconciler{ziti: fake, logger: zap.NewNop(), darkServices: defaultDarkServices()}
	rec.reconcileDarkServices()
	if fake.dialPolicyFor("openidx-console").dial != "#enrolled-users" {
		t.Error("console must be Tier 1 (#enrolled-users)")
	}
}
```

- [x] **Step 2: Run to verify it fails**

Run: `go test ./internal/access/ -run 'TestReconcile(CreatesTier2|Tier1)' -v`
Expected: FAIL.

- [x] **Step 3: Implement `defaultDarkServices()` + `reconcileDarkServices()`**

```go
type darkService struct { name, upstream, tierAttr string }

func defaultDarkServices() []darkService {
	return []darkService{
		{"openidx-admin-api", "127.0.0.1:8005", "device-trusted"},
		{"openidx-governance", "127.0.0.1:8002", "device-trusted"},
		{"openidx-audit", "127.0.0.1:8004", "device-trusted"},
		{"openidx-provisioning", "127.0.0.1:8003", "device-trusted"},
		{"openidx-scim", "127.0.0.1:8003", "device-trusted"},
		{"openidx-access", "127.0.0.1:8007", "device-trusted"},
		{"openidx-identity-selfservice", "127.0.0.1:8001", "enrolled-users"},
		{"openidx-console", "127.0.0.1:8090", "enrolled-users"}, // SPA upstream
	}
}

func (rec *Reconciler) reconcileDarkServices() {
	for _, d := range rec.darkServices {
		if err := rec.ziti.EnsureServiceWithHostV1(d.name, d.upstream); err != nil {
			rec.logger.Warn("dark service converge failed", zap.String("svc", d.name), zap.Error(err)); continue
		}
		if err := rec.ensureTierDialPolicy(d.name, d.tierAttr); err != nil {
			rec.logger.Warn("dark dial policy converge failed", zap.String("svc", d.name), zap.Error(err))
		}
	}
}
```
Call `reconcileDarkServices()` from the main reconcile loop, gated so it only runs when `cfg.DarkModeTier1 || cfg.DarkModeTier2` (creating policies early is harmless, but gate to avoid noise). Use the existing service/host.v1 creation helper (match the real method name in the file — likely `EnsureService`/`CreateService` + host.v1 config; adapt `EnsureServiceWithHostV1` to it).

- [x] **Step 4: Run to verify it passes**

Run: `go test ./internal/access/ -run 'TestReconcile' -v`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
go build ./... && go vet ./internal/access/
git add internal/access/ziti_reconciler.go internal/access/ziti_reconciler_test.go
git commit -m "ziti-reconciler: model OpenIDX surfaces as tier'd dark services (admin/gov/audit/scim/access=Tier2, self-service/console=Tier1)"
```

### Task 5.2: Register the admin console as a BrowZer dark app + Tier-2 API dial

**Files:**
- Modify: `proxy_routes` seed / console route registration (follow the `psm`/`netgraph` published-app pattern in `internal/access/apisix_routes.go` + reconciler)
- Modify: `web/admin-console` build config if the API base must be overlay-relative (verify it already uses same-origin `/api` — from earlier work `getAPIBaseURL()` returns `window.location.origin`, which is correct for BrowZer same-origin)

**Interfaces:**
- Consumes: existing BrowZer app registration + APISIX route reconciler.
- Produces: `console.<domain>` served via the BrowZer bootstrapper; its `/api/*` calls tunnel to the Tier-2 dark backends; console SPA itself is Tier 1.

- [x] **Step 1: Confirm the console uses same-origin API calls**

Run: `grep -n "window.location.origin\|VITE_API" web/admin-console/src/lib/api.ts`
Expected: `getAPIBaseURL()` returns `window.location.origin` in prod (already true) — so BrowZer same-origin works with no code change. If not, set the prod API base to same-origin.

- [x] **Step 2: Register the console BrowZer app (DB seed / reconcile)**

Add a `proxy_routes` row (or console-app registration) for `console.<domain>` with `browzer_enabled=true`, `hosting_mode` matching the SPA, `to_url` = the console SPA upstream (`127.0.0.1:8090`). Let the reconciler converge the Ziti service + APISIX BrowZer route (no hand-config, per the reconciler-owns-mutations invariant).

- [x] **Step 3: Verify the reconcilers produce the route**

Run the access-service locally with `APISIX_EDGE_ENABLED=false ZITI_RECONCILER=true` and a fake/mock ziti; assert (unit or log) that `openidx-console` service + BrowZer route are converged. (Full live verification happens in Phase 6 staging.)

- [x] **Step 4: Commit**

```bash
git add internal/access/ (seed/reconcile changes) web/admin-console/ (if any)
git commit -m "access: register admin console as a BrowZer dark app (Tier 1 shell, Tier 2 API dial)"
```

---

## Phase 6 — Staged cutover runbook + break-glass (docs + drill, no always-on behavior change)

The operator procedure to actually go dark, Tier 2 first, each step gated on `dark-drill`. This phase is documentation + the wired drill; flipping the flags in prod is an operator action, not a code default.

### Task 6.1: Write the cutover runbook + break-glass into the spec's operations doc

**Files:**
- Modify: `docs/OPENIDX_ZITI_ARCHITECTURE.md` (add a "Dark platform cutover" section)
- Modify: `docs/DEPLOYMENT.md` (link it)

**Interfaces:** none (docs).

- [x] **Step 1: Write the runbook**

Document, in order:
1. Enroll the admin fleet (native tunnel or BrowZer); confirm `#device-trusted` via `GET /api/v1/access/my-devices`.
2. Deploy Phase 1-5 with flags **off** (no behavior change).
3. `make dark-drill` (self-test green) + a **staging live drill**: set `DARK_MODE_TIER2=true` + `SERVICE_BIND_ADDR=127.0.0.1` on admin/gov/audit/scim/access, `DARK_MODE=tier2 bash seed-edge-routes.sh`, then `scripts/dark-mode.sh --verify` (live) → must prove public-refused + overlay-200 + tier-gate.
4. Only if verify passes: proceed to prod Tier 2, then repeat for Tier 1.
5. **Break-glass:** `scripts/dark-mode.sh --undark` (re-seeds `DARK_MODE=off`, prints the `SERVICE_BIND_ADDR` revert) + the sealed out-of-band enroll token. Test the undark path in staging as part of the drill.

- [x] **Step 2: Cross-check the drill exists and passes**

Run: `make dark-drill`
Expected: green.

- [x] **Step 3: Commit**

```bash
git add docs/OPENIDX_ZITI_ARCHITECTURE.md docs/DEPLOYMENT.md
git commit -m "docs: dark-platform staged cutover runbook + break-glass (Tier 2 -> Tier 1, verify-before-cutover)"
```

### Task 6.2: Wire the invariant guards into `make dark-drill`

**Files:**
- Create: `internal/access/dark_invariants_test.go`
- Modify: `Makefile` (`dark-drill` also runs the guard tests)

**Interfaces:**
- Produces: mutation-tested guards: Tier-2 dark services carry `#device-trusted` (not `#enrolled-users`); `defaultDarkServices()` never lists a Tier-0 surface (no `openidx-oauth`/`enroll`/`wellknown`); the seeder's Tier-0 set always includes enroll + well-known.

- [x] **Step 1: Write the guard tests**

```go
func TestTier2ServicesRequireDeviceTrust(t *testing.T) {
	for _, d := range defaultDarkServices() {
		if d.tierAttr == "device-trusted" { continue }
		if d.tierAttr != "enrolled-users" {
			t.Errorf("%s has unexpected tier attr %q", d.name, d.tierAttr)
		}
	}
	// admin-api MUST be device-trusted
	for _, d := range defaultDarkServices() {
		if d.name == "openidx-admin-api" && d.tierAttr != "device-trusted" {
			t.Errorf("admin-api must be Tier 2 (#device-trusted), got %q", d.tierAttr)
		}
	}
}
func TestNoTier0SurfaceIsDarked(t *testing.T) {
	for _, d := range defaultDarkServices() {
		for _, forbidden := range []string{"enroll", "oauth", "wellknown", "jwks"} {
			if strings.Contains(d.name, forbidden) {
				t.Errorf("Tier-0 surface %q must never be a dark service", d.name)
			}
		}
	}
}
```

- [x] **Step 2: Run to verify they pass**

Run: `go test ./internal/access/ -run 'TestTier2ServicesRequireDeviceTrust|TestNoTier0SurfaceIsDarked' -v`
Expected: PASS.

- [x] **Step 3: Mutation check (guard actually bites)**

Temporarily set `openidx-admin-api` to `enrolled-users` in `defaultDarkServices()`; rerun; expected FAIL. Revert.

- [x] **Step 4: Wire into the Makefile**

```make
dark-drill:
	@bash scripts/ha-drill.sh "Dark: tier invariants (mutation-tested)" \
		./internal/access/ 'TestTier2ServicesRequireDeviceTrust|TestNoTier0SurfaceIsDarked'
	@bash scripts/dark-mode.sh --verify --self-test
```

- [x] **Step 5: Commit**

```bash
go build ./... && go vet ./internal/access/
git add internal/access/dark_invariants_test.go Makefile
git commit -m "dark: mutation-tested tier invariants wired into make dark-drill"
```

---

## Self-Review notes (coverage against the spec)

- Spec §3 tiers → Phase 5 `defaultDarkServices()` (Tier 1/2) + Phase 4 route set (Tier 0). ✔
- Spec §4 enroll door → Phase 3. ✔
- Spec §5 console-as-dark-app → Task 5.2. ✔
- Spec §6.1 network cut → Phase 1 (bind) + Task 4.1 (drop routes). ✔
- Spec §6.2 attribute groups → Phase 2. ✔
- Spec §6.3 forward-auth on Tier 2 → existing behavior; Task 6.1 runbook requires `require_device_trust` on mgmt routes (verify step). ✔ (add explicit check in Task 6.1 if a mgmt route lacks it)
- Spec §7 rollout/flags/break-glass/verify → Phase 1 flags, Phase 4 tooling, Phase 6 runbook + guards. ✔
- Spec §11 testing → unit + invariants + self-test + staging drill across phases. ✔
- Open questions (spec §12): Tier-1/2 boundary for dual-use endpoints and enroll-as-separate-deployable are deferred; the plan keeps enroll in access-service (decided) and enumerates dark services explicitly in Task 5.1 for review at that task.
