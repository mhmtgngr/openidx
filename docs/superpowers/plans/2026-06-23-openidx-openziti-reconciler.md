# OpenIDX ↔ OpenZiti Reconciler Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the drift-prone, event-driven OpenZiti provisioning with a self-healing reconcile loop whose desired state is the OpenIDX DB — starting with a feature-flagged Phase 1 that replicates today's behavior with zero functional change.

**Architecture:** A `ZitiReconciler` runs a single serialized loop (periodic + event-triggered) that loads desired routes from the DB and idempotently converges the Ziti controller to match. Phase 1 implements the loop + the `identity` (SDK-`Listen`) hosting model only, behind `ZITI_RECONCILER`. Later phases add `direct`/`host.v1` hosting, deployment profiles, and admin UX.

**Tech Stack:** Go 1.22 (access-service), PostgreSQL (pgx), OpenZiti `sdk-golang` v1.7.0 + mgmt REST API, `httptest` for mocking the controller in unit tests.

**Spec:** `docs/superpowers/specs/2026-06-23-openidx-openziti-integration-design.md`

---

## Scope of this plan

This plan fully details **Phase 1** (reconciler skeleton + `hosting_mode` column, feature-flagged, zero behavior change). Phases 2–4 are a **roadmap** at the end; each will get its own detailed plan once Phase 1 lands and Phase 2's open assumptions (BrowZer per-app rendering, CSP handling) are empirically confirmed. Phase 1 produces working, testable software on its own: with the flag off nothing changes; with it on, the reconciler converges Ziti to the same state today's imperative path produces.

## File structure (Phase 1)

- **Create** `internal/migrations/sql_v47.go` — `hosting_mode` column SQL consts.
- **Modify** `internal/migrations/loader.go` — register migration v47.
- **Modify** `internal/common/config/config.go` — add `ZitiReconcilerEnabled` flag.
- **Create** `internal/access/ziti_reconciler.go` — reconciler type, desired-state loader, run loop, `identity`-mode `ensure*` functions, per-object status.
- **Create** `internal/access/ziti_reconciler_test.go` — unit tests (httptest controller + injected desired routes).
- **Modify** `cmd/access-service/main.go` — start the reconciler when the flag is on; keep the imperative path when off.

Responsibilities are split so the reconciler's convergence logic (`reconcile`) is pure and testable against a mock controller, while DB access (`loadDesiredRoutes`) and process wiring (`main.go`) stay thin.

---

## Task 1: Migration v47 — `hosting_mode` column

**Files:**
- Create: `internal/migrations/sql_v47.go`
- Modify: `internal/migrations/loader.go` (after the v46 entry, ~line 329)
- Test: `internal/migrations/loader_test.go` (existing migrations test runs all migrations)

- [ ] **Step 1: Write the SQL consts file**

Create `internal/migrations/sql_v47.go`:

```go
package migrations

// Migration v47 — proxy_routes.hosting_mode.
//
// The Ziti reconciler chooses a hosting model per route: "identity" (the
// access-proxy is the Ziti terminator and injects X-Forwarded-* headers) or
// "direct" (the edge router hosts via host.v1). BrowZer-enabled routes require
// "direct". Backfill preserves today's behavior: every existing ziti route is
// "identity" except BrowZer-enabled ones, which become "direct". Idempotent.
var hostingModeUp = `-- Migration 047: proxy_routes.hosting_mode.
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS hosting_mode TEXT NOT NULL DEFAULT 'identity';
UPDATE proxy_routes SET hosting_mode = 'direct' WHERE browzer_enabled = true;
`

var hostingModeDown = `-- Migration 047 down.
ALTER TABLE proxy_routes DROP COLUMN IF EXISTS hosting_mode;
`
```

- [ ] **Step 2: Register the migration in the loader**

In `internal/migrations/loader.go`, immediately after the v46 entry's closing `},` (before the final `}` that closes the slice), add:

```go
		{
			Version:     47,
			Name:        "proxy_routes_hosting_mode",
			Description: "Add proxy_routes.hosting_mode (identity|direct) for the Ziti reconciler; backfill browzer_enabled routes to 'direct', else 'identity'. Idempotent.",
			UpSQL:       hostingModeUp,
			DownSQL:     hostingModeDown,
		},
```

- [ ] **Step 3: Build + run the migrations test**

Run: `go build ./internal/migrations/ && go test ./internal/migrations/ -run Migration -v`
Expected: PASS (migrations apply cleanly through v47; replay v1→47 succeeds).

- [ ] **Step 4: Commit**

```bash
git add internal/migrations/sql_v47.go internal/migrations/loader.go
git commit -m "feat(migrations): v47 add proxy_routes.hosting_mode for Ziti reconciler"
```

---

## Task 2: Config flag `ZitiReconcilerEnabled`

**Files:**
- Modify: `internal/common/config/config.go` (the Ziti fields block, ~line 86, and wherever defaults/env binding live)
- Test: `internal/common/config/config_test.go` (create if absent)

- [ ] **Step 1: Write the failing test**

Create or append to `internal/common/config/config_test.go`:

```go
package config

import (
	"os"
	"testing"
)

func TestZitiReconcilerFlagDefaultsFalse(t *testing.T) {
	os.Unsetenv("ZITI_RECONCILER")
	c := &Config{}
	if c.ZitiReconcilerEnabled {
		t.Fatalf("ZitiReconcilerEnabled should default to false")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/common/config/ -run TestZitiReconcilerFlagDefaultsFalse -v`
Expected: FAIL — `c.ZitiReconcilerEnabled undefined`.

- [ ] **Step 3: Add the field + env binding**

In `internal/common/config/config.go`, in the Ziti fields block (next to `ZitiEnabled` at ~line 86), add:

```go
	ZitiReconcilerEnabled  bool   `mapstructure:"ziti_reconciler"`
```

Then find where the other `ZITI_*` env vars are bound (search for `BindEnv` / `SetDefault` / `ziti_enabled` in this file) and add the matching binding and default, mirroring `ziti_enabled` exactly:

```go
	v.SetDefault("ziti_reconciler", false)
	_ = v.BindEnv("ziti_reconciler", "ZITI_RECONCILER")
```

(Use the same mechanism the file already uses for `ziti_enabled`; if it uses a different pattern, copy that pattern.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/common/config/ -run TestZitiReconcilerFlagDefaultsFalse -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/common/config/config.go internal/common/config/config_test.go
git commit -m "feat(config): add ZITI_RECONCILER flag (default false)"
```

---

## Task 3: Desired-state types + loader

**Files:**
- Create: `internal/access/ziti_reconciler.go`
- Test: `internal/access/ziti_reconciler_test.go`

- [ ] **Step 1: Write the failing test for DesiredRoute parsing**

Create `internal/access/ziti_reconciler_test.go`:

```go
package access

import "testing"

func TestDesiredRouteHostingModeNormalization(t *testing.T) {
	// browzer-enabled routes are always "direct" regardless of stored mode.
	r := DesiredRoute{ServiceName: "svc", ToURL: "http://10.0.0.1:80", HostingMode: "identity", BrowZerEnabled: true}
	if got := r.EffectiveMode(); got != "direct" {
		t.Fatalf("browzer route should be direct, got %q", got)
	}
	// non-browzer respects stored mode.
	r2 := DesiredRoute{ServiceName: "svc2", ToURL: "http://10.0.0.2:80", HostingMode: "identity"}
	if got := r2.EffectiveMode(); got != "identity" {
		t.Fatalf("expected identity, got %q", got)
	}
	// empty mode defaults to identity.
	r3 := DesiredRoute{ServiceName: "svc3", ToURL: "http://10.0.0.3:80"}
	if got := r3.EffectiveMode(); got != "identity" {
		t.Fatalf("expected identity default, got %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/access/ -run TestDesiredRouteHostingModeNormalization -v`
Expected: FAIL — `DesiredRoute` undefined.

- [ ] **Step 3: Write the types + loader**

Create `internal/access/ziti_reconciler.go`:

```go
// Package access — Ziti reconciler: converges the Ziti controller to the
// desired state declared in the OpenIDX DB. Phase 1 implements the loop plus
// the "identity" (SDK-Listen) hosting model only, behind ZITI_RECONCILER.
package access

import (
	"context"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// HostingMode selects how a Ziti service is hosted.
const (
	HostingModeIdentity = "identity" // access-proxy is the terminator, injects identity headers
	HostingModeDirect   = "direct"   // edge router hosts via host.v1 (Phase 2)
)

// DesiredRoute is the reconciler's view of a ziti-enabled proxy_route.
type DesiredRoute struct {
	ServiceName    string
	ToURL          string
	HostingMode    string
	BrowZerEnabled bool
}

// EffectiveMode resolves the hosting mode, forcing "direct" for BrowZer routes
// and defaulting empty to "identity".
func (r DesiredRoute) EffectiveMode() string {
	if r.BrowZerEnabled {
		return HostingModeDirect
	}
	if r.HostingMode == HostingModeDirect {
		return HostingModeDirect
	}
	return HostingModeIdentity
}

// loadDesiredRoutes reads all ziti-enabled routes from the DB. Install-wide
// (the Ziti service namespace is global), so RLS is bypassed.
func (rec *ZitiReconciler) loadDesiredRoutes(ctx context.Context) ([]DesiredRoute, error) {
	ctx = orgctx.WithBypassRLS(ctx)
	rows, err := rec.db.Pool.Query(ctx,
		//orgscope:ignore install-wide Ziti reconcile; keyed by globally-unique ziti_service_name across all orgs
		`SELECT ziti_service_name, to_url, COALESCE(hosting_mode,'identity'), COALESCE(browzer_enabled,false)
		 FROM proxy_routes
		 WHERE ziti_enabled = true AND enabled = true
		   AND ziti_service_name IS NOT NULL AND ziti_service_name != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DesiredRoute
	for rows.Next() {
		var d DesiredRoute
		if err := rows.Scan(&d.ServiceName, &d.ToURL, &d.HostingMode, &d.BrowZerEnabled); err != nil {
			rec.logger.Warn("reconciler: scan route failed", zap.Error(err))
			continue
		}
		out = append(out, d)
	}
	return out, nil
}
```

(The `ZitiReconciler` struct itself is defined in Task 4; this file compiles once Task 4 is added. To keep this task self-contained for the test, the test only exercises `DesiredRoute.EffectiveMode`, which has no struct dependency.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/access/ -run TestDesiredRouteHostingModeNormalization -v`
Expected: PASS. (If the package fails to compile because `ZitiReconciler` is referenced before Task 4, temporarily comment out `loadDesiredRoutes` to confirm the type test, then restore it in Task 4 — or implement Task 4 immediately after.)

- [ ] **Step 5: Commit**

```bash
git add internal/access/ziti_reconciler.go internal/access/ziti_reconciler_test.go
git commit -m "feat(ziti): reconciler desired-state types + route loader"
```

---

## Task 4: Reconciler struct + serialized run loop

**Files:**
- Modify: `internal/access/ziti_reconciler.go`
- Test: `internal/access/ziti_reconciler_test.go`

- [ ] **Step 1: Write the failing test for coalescing single-worker behavior**

Append to `internal/access/ziti_reconciler_test.go`:

```go
import (
	"sync/atomic"
	"testing"
	"time"
)

func TestReconcilerCoalescesAndSerializes(t *testing.T) {
	var runs int32
	rec := newTestReconciler(func() { atomic.AddInt32(&runs, 1); time.Sleep(20 * time.Millisecond) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec.Start(ctx)
	// Fire a burst of enqueues; they should coalesce into far fewer runs than calls.
	for i := 0; i < 50; i++ {
		rec.Enqueue()
	}
	time.Sleep(150 * time.Millisecond)
	if n := atomic.LoadInt32(&runs); n == 0 || n > 5 {
		t.Fatalf("expected a small coalesced number of runs, got %d", n)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/access/ -run TestReconcilerCoalescesAndSerializes -v`
Expected: FAIL — `ZitiReconciler`/`newTestReconciler` undefined.

- [ ] **Step 3: Implement the struct + loop**

Add to `internal/access/ziti_reconciler.go` (imports: add `sync`, `time`, `database`):

```go
import (
	"sync"
	"time"

	"github.com/openidx/openidx/internal/common/database"
)

// ZitiReconciler converges Ziti to the DB's desired state. One worker, a
// coalescing trigger channel, and a periodic safety-net tick — so concurrent
// mutation races cannot happen (the reconciler is the only mutator of Ziti).
type ZitiReconciler struct {
	db       *database.PostgresDB
	logger   *zap.Logger
	provider *ZitiProvider // source of the live ZitiManager
	period   time.Duration

	trigger chan struct{}      // coalescing: buffered size 1
	runOnce func(context.Context) // overridable in tests; defaults to reconcileOnce
	mu      sync.Mutex         // serializes runs
	status  map[string]string  // serviceName -> "synced" | "error: ..."
}

func NewZitiReconciler(db *database.PostgresDB, logger *zap.Logger, provider *ZitiProvider) *ZitiReconciler {
	rec := &ZitiReconciler{
		db:       db,
		logger:   logger.With(zap.String("component", "ziti-reconciler")),
		provider: provider,
		period:   30 * time.Second,
		trigger:  make(chan struct{}, 1),
		status:   make(map[string]string),
	}
	rec.runOnce = rec.reconcileOnce
	return rec
}

// Enqueue requests a reconcile; coalesces (non-blocking send to a size-1 chan).
func (rec *ZitiReconciler) Enqueue() {
	select {
	case rec.trigger <- struct{}{}:
	default:
	}
}

// Start launches the single worker: drains triggers and ticks periodically.
func (rec *ZitiReconciler) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(rec.period)
		defer ticker.Stop()
		rec.runLocked(ctx) // initial reconcile
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rec.runLocked(ctx)
			case <-rec.trigger:
				rec.runLocked(ctx)
			}
		}
	}()
}

func (rec *ZitiReconciler) runLocked(ctx context.Context) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.runOnce(ctx)
}
```

Then add a test helper at the bottom of `ziti_reconciler_test.go`:

```go
func newTestReconciler(run func()) *ZitiReconciler {
	rec := &ZitiReconciler{
		logger:  zap.NewNop(),
		period:  time.Hour, // disable periodic in this test
		trigger: make(chan struct{}, 1),
		status:  make(map[string]string),
	}
	rec.runOnce = func(context.Context) { run() }
	return rec
}
```

Add `"go.uber.org/zap"` to the test imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/access/ -run TestReconcilerCoalescesAndSerializes -v`
Expected: PASS (a handful of runs, not 50).

- [ ] **Step 5: Commit**

```bash
git add internal/access/ziti_reconciler.go internal/access/ziti_reconciler_test.go
git commit -m "feat(ziti): reconciler run loop (serialized, coalescing, periodic)"
```

---

## Task 5: `ensureService` (idempotent service + role attrs)

**Files:**
- Modify: `internal/access/ziti_reconciler.go`
- Test: `internal/access/ziti_reconciler_test.go`

- [ ] **Step 1: Write the failing test (httptest controller, mirroring ziti_test.go)**

Append to `ziti_reconciler_test.go`:

```go
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/openidx/openidx/internal/common/config"
)

func TestEnsureServiceCreatesWhenMissing(t *testing.T) {
	var created bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/edge/management/v1/services":
			json.NewEncoder(w).Encode(map[string]interface{}{"data": []interface{}{}}) // none exist
		case r.Method == "POST" && r.URL.Path == "/edge/management/v1/services":
			created = true
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]string{"id": "svc-id-1"}})
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{}})
		}
	}))
	defer srv.Close()

	zm := &ZitiManager{logger: zap.NewNop(), mgmtToken: "fake", mgmtClient: srv.Client(),
		cfg: &config.Config{ZitiCtrlURL: srv.URL}, initialized: true}
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}}

	if err := rec.ensureService(context.Background(), zm, DesiredRoute{ServiceName: "openidx-Test", ToURL: "http://10.0.0.9:80"}); err != nil {
		t.Fatalf("ensureService: %v", err)
	}
	if !created {
		t.Fatalf("expected service to be created")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/access/ -run TestEnsureServiceCreatesWhenMissing -v`
Expected: FAIL — `rec.ensureService` undefined.

- [ ] **Step 3: Implement `ensureService`**

Add to `internal/access/ziti_reconciler.go`:

```go
// ensureService makes sure the Ziti service exists with the required role
// attributes. Idempotent: looks up by name, creates if absent, patches attrs
// if drifted. Reuses ZitiManager.SetupZitiForRoute for creation (which already
// handles service + config + base policies), then verifies role attributes.
func (rec *ZitiReconciler) ensureService(ctx context.Context, zm *ZitiManager, d DesiredRoute) error {
	host, port := parseHostPort(d.ToURL)
	if existing, _ := zm.GetServiceByName(d.ServiceName); existing == nil {
		// SetupZitiForRoute is idempotent enough for first creation; routeID ""
		// means no proxy_routes FK is written (NULL), matching existing behavior.
		if err := zm.SetupZitiForRoute(ctx, "", d.ServiceName, host, port); err != nil {
			// A concurrent/previous create may have raced; tolerate if it now exists.
			if again, _ := zm.GetServiceByName(d.ServiceName); again == nil {
				return err
			}
		}
	}
	svc, err := zm.GetServiceByName(d.ServiceName)
	if err != nil || svc == nil {
		return err
	}
	// Ensure the service's role attribute (== service name) is present.
	attrs, aerr := zm.GetServiceRoleAttributes(ctx, svc.ID)
	if aerr != nil {
		return aerr
	}
	want := d.ServiceName
	for _, a := range attrs {
		if a == want {
			return nil // already correct
		}
	}
	return zm.PatchServiceRoleAttributes(ctx, svc.ID, append(attrs, want))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/access/ -run TestEnsureServiceCreatesWhenMissing -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/access/ziti_reconciler.go internal/access/ziti_reconciler_test.go
git commit -m "feat(ziti): reconciler ensureService (idempotent)"
```

---

## Task 6: `ensurePolicies` + `ensureHosting` (identity mode)

**Files:**
- Modify: `internal/access/ziti_reconciler.go`
- Test: `internal/access/ziti_reconciler_test.go`

- [ ] **Step 1: Write the failing test**

Append to `ziti_reconciler_test.go`:

```go
func TestEnsureHostingIdentityCallsHostService(t *testing.T) {
	// A ZitiManager not initialized returns an error from HostService; we assert
	// ensureHosting surfaces that, proving it routes identity-mode to HostService.
	zm := &ZitiManager{logger: zap.NewNop(), initialized: false}
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}}
	err := rec.ensureHosting(context.Background(), zm, DesiredRoute{ServiceName: "openidx-Test", ToURL: "http://10.0.0.9:80", HostingMode: "identity"})
	if err == nil {
		t.Fatalf("expected error from HostService on uninitialized SDK")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/access/ -run TestEnsureHostingIdentityCallsHostService -v`
Expected: FAIL — `rec.ensureHosting` undefined.

- [ ] **Step 3: Implement `ensurePolicies` + `ensureHosting`**

Add to `internal/access/ziti_reconciler.go` (import `"fmt"`):

```go
// ensurePolicies ensures the bind/dial/service-edge-router policies for a
// route's hosting mode. Phase 1 supports identity mode only. CreateServicePolicy
// 400s on an existing name; that's the idempotent no-op path, so errors are
// tolerated (logged at debug).
func (rec *ZitiReconciler) ensurePolicies(ctx context.Context, zm *ZitiManager, d DesiredRoute) error {
	svcRole := "#" + d.ServiceName
	if _, err := zm.CreateServicePolicy(ctx, "openidx-bind-"+d.ServiceName, "Bind",
		[]string{svcRole}, []string{"#access-proxy-clients"}); err != nil {
		rec.logger.Debug("bind policy (may already exist)", zap.String("svc", d.ServiceName), zap.Error(err))
	}
	if _, err := zm.CreateServicePolicy(ctx, "openidx-dial-"+d.ServiceName, "Dial",
		[]string{svcRole}, []string{"#access-proxy-clients"}); err != nil {
		rec.logger.Debug("dial policy (may already exist)", zap.String("svc", d.ServiceName), zap.Error(err))
	}
	if err := zm.EnsureServiceEdgeRouterPolicy(ctx, "openidx-serp-"+d.ServiceName,
		[]string{svcRole}, []string{"#all"}); err != nil {
		rec.logger.Debug("serp (may already exist)", zap.String("svc", d.ServiceName), zap.Error(err))
	}
	return nil
}

// ensureHosting establishes hosting for the route's mode. Phase 1: identity
// mode hosts via the access-proxy SDK (HostService, which is itself idempotent
// — it no-ops if already hosting). direct mode is Phase 2.
func (rec *ZitiReconciler) ensureHosting(ctx context.Context, zm *ZitiManager, d DesiredRoute) error {
	switch d.EffectiveMode() {
	case HostingModeIdentity:
		host, port := parseHostPort(d.ToURL)
		return zm.HostService(d.ServiceName, host, port)
	case HostingModeDirect:
		return fmt.Errorf("direct hosting mode not implemented until Phase 2 (service %s)", d.ServiceName)
	default:
		return fmt.Errorf("unknown hosting mode for service %s", d.ServiceName)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/access/ -run TestEnsureHostingIdentityCallsHostService -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/access/ziti_reconciler.go internal/access/ziti_reconciler_test.go
git commit -m "feat(ziti): reconciler ensurePolicies + ensureHosting (identity mode)"
```

---

## Task 7: `reconcileOnce` orchestration + status

**Files:**
- Modify: `internal/access/ziti_reconciler.go`
- Test: `internal/access/ziti_reconciler_test.go`

- [ ] **Step 1: Write the failing test (status recorded per route)**

Append to `ziti_reconciler_test.go`:

```go
func TestReconcileRouteRecordsStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every service lookup returns the service; attrs already correct; policies 400 (exist).
		switch {
		case r.URL.Path == "/edge/management/v1/services":
			json.NewEncoder(w).Encode(map[string]interface{}{"data": []map[string]interface{}{{"id": "svc1", "name": "openidx-Test", "roleAttributes": []string{"openidx-Test"}}}})
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{}})
		}
	}))
	defer srv.Close()
	zm := &ZitiManager{logger: zap.NewNop(), mgmtToken: "fake", mgmtClient: srv.Client(),
		cfg: &config.Config{ZitiCtrlURL: srv.URL}, initialized: true}
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}}

	rec.reconcileRoute(context.Background(), zm, DesiredRoute{ServiceName: "openidx-Test", ToURL: "http://10.0.0.9:80", HostingMode: "identity"})
	if got := rec.status["openidx-Test"]; got != "synced" {
		t.Fatalf("expected synced, got %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/access/ -run TestReconcileRouteRecordsStatus -v`
Expected: FAIL — `rec.reconcileRoute` undefined.

- [ ] **Step 3: Implement `reconcileRoute` + `reconcileOnce`**

Add to `internal/access/ziti_reconciler.go`:

```go
// reconcileRoute converges one route and records its per-object status.
// Error-isolated: a failure records the error but never panics or aborts the sweep.
func (rec *ZitiReconciler) reconcileRoute(ctx context.Context, zm *ZitiManager, d DesiredRoute) {
	steps := []func(context.Context, *ZitiManager, DesiredRoute) error{
		rec.ensureService, rec.ensurePolicies, rec.ensureHosting,
	}
	for _, step := range steps {
		if err := step(ctx, zm, d); err != nil {
			rec.setStatus(d.ServiceName, "error: "+err.Error())
			rec.logger.Warn("reconcile route failed", zap.String("svc", d.ServiceName), zap.Error(err))
			return
		}
	}
	rec.setStatus(d.ServiceName, "synced")
}

func (rec *ZitiReconciler) setStatus(svc, s string) {
	rec.mu.Lock() // already held during runLocked; this is for direct calls in tests
	// note: reconcileOnce holds rec.mu via runLocked, so use a separate status mutex.
	rec.mu.Unlock()
	rec.statusMu.Lock()
	defer rec.statusMu.Unlock()
	rec.status[svc] = s
}

// reconcileOnce loads desired routes and converges each. The connection check
// happens via the provider; if no live manager, it records and returns.
func (rec *ZitiReconciler) reconcileOnce(ctx context.Context) {
	zm := rec.provider.Get()
	if zm == nil || !zm.IsInitialized() {
		rec.logger.Debug("reconcile skipped: no live Ziti manager")
		return
	}
	desired, err := rec.loadDesiredRoutes(ctx)
	if err != nil {
		rec.logger.Warn("reconcile: load desired failed", zap.Error(err))
		return
	}
	for _, d := range desired {
		rec.reconcileRoute(ctx, zm, d)
	}
	rec.logger.Info("reconcile pass complete", zap.Int("routes", len(desired)))
}
```

Fix the `setStatus` mutex collision: replace the body above with a clean version using a dedicated `statusMu`. Update the struct in Task 4's file to add `statusMu sync.Mutex` and simplify `setStatus`:

```go
func (rec *ZitiReconciler) setStatus(svc, s string) {
	rec.statusMu.Lock()
	defer rec.statusMu.Unlock()
	rec.status[svc] = s
}
```

And add to the `ZitiReconciler` struct (Task 4): `statusMu sync.Mutex`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/access/ -run TestReconcileRouteRecordsStatus -v`
Expected: PASS.

- [ ] **Step 5: Run the whole reconciler test file + vet**

Run: `gofmt -w internal/access/ziti_reconciler.go && go vet ./internal/access/ && go test ./internal/access/ -run 'Reconcil|DesiredRoute|EnsureService|EnsureHosting' -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/access/ziti_reconciler.go internal/access/ziti_reconciler_test.go
git commit -m "feat(ziti): reconcileOnce orchestration + per-route status"
```

---

## Task 8: Wire the reconciler into main.go (flag-gated)

**Files:**
- Modify: `cmd/access-service/main.go` (~lines 264–297, the Ziti boot block)
- Test: manual smoke (documented below) — no unit test for `main`.

- [ ] **Step 1: Add the flag-gated start**

In `cmd/access-service/main.go`, inside the block that runs after `zm, err := access.NewZitiManagerWithConn(...)` succeeds and `zitiProvider.Swap(zm, ...)` has been called (right around where `HostAllServices`/`EnsureZitiServicesForRoutes`/`EnsureBrowZerRouterService` are invoked, ~line 278–297), wrap the imperative provisioning so it's replaced by the reconciler when the flag is on:

```go
		if cfg.ZitiReconcilerEnabled {
			reconciler := access.NewZitiReconciler(db, log, zitiProvider)
			reconciler.Start(zitiCtx)
			accessService.SetZitiReconciler(reconciler) // so handlers can Enqueue() on changes
			log.Info("Ziti reconciler started (ZITI_RECONCILER=true); imperative provisioning skipped")
		} else {
			// existing imperative path — unchanged
			zm.StartUserSyncPoller(zitiCtx)
			zm.HostAllServices(zitiCtx)
			accessService.EnsureZitiServicesForRoutes(zitiCtx, zm)
			accessService.EnsureBrowZerRouterService(zitiCtx, zm)
		}
```

(Adapt to the exact surrounding lines; the key is: flag on → start reconciler instead of the imperative calls; flag off → leave today's calls exactly as they are.)

- [ ] **Step 2: Add the `SetZitiReconciler` setter + `Enqueue` hook on the service**

In `internal/access/service.go`, add a field and setter (mirroring `SetFeatureManager`):

```go
// (field, in the Service struct)
	zitiReconciler *ZitiReconciler

// (setter, near the other Set* methods)
func (s *Service) SetZitiReconciler(r *ZitiReconciler) { s.zitiReconciler = r }

// (helper used by route/feature mutation handlers)
func (s *Service) enqueueReconcile() {
	if s.zitiReconciler != nil {
		s.zitiReconciler.Enqueue()
	}
}
```

- [ ] **Step 3: Call `enqueueReconcile()` after route/feature DB writes**

In the handlers that change ziti/browzer desired state (`handleEnableZitiOnRoute`, `handleDisableZitiFeature`, `handleEnableBrowZerFeature`/`handleDisableBrowZerFeature` in `internal/access/*.go`), add `s.enqueueReconcile()` immediately after the successful DB update (just before writing the HTTP 200 response). This makes admin changes converge promptly under the reconciler while remaining a harmless no-op when the reconciler isn't running.

- [ ] **Step 4: Build everything**

Run: `go build ./... && go vet ./internal/access/`
Expected: clean build.

- [ ] **Step 5: Commit**

```bash
git add cmd/access-service/main.go internal/access/service.go internal/access/ziti_handlers.go internal/access/browzer_config.go
git commit -m "feat(ziti): wire reconciler into access-service (ZITI_RECONCILER flag)"
```

---

## Task 9: Phase 1 acceptance — flag-off unchanged, flag-on converges

**Files:** none (verification task).

- [ ] **Step 1: Flag OFF regression**

Run the access-service with `ZITI_RECONCILER` unset against the existing dev stack and confirm Ziti behavior is byte-for-byte today's: routes host as before (`go test ./internal/access/...` green; manual: a known ziti route still reachable). Expected: no behavioral difference.

- [ ] **Step 2: Flag ON convergence (idempotence)**

Set `ZITI_RECONCILER=true`, start the service, watch logs for `reconcile pass complete`. Then **break** a piece of Ziti state by hand (e.g., delete a service-policy via `ziti edge delete service-policy openidx-dial-<svc>`), wait one reconcile period (~30s), and confirm the reconciler **recreates** it (the policy reappears; route status returns to `synced`). Expected: drift auto-corrected — the core Phase-1 promise.

- [ ] **Step 3: Run full test suite**

Run: `go build ./... && go test ./internal/access/ ./internal/migrations/ ./internal/common/config/`
Expected: PASS.

- [ ] **Step 4: Commit any fixes, tag Phase 1 done**

```bash
git commit -am "test(ziti): phase 1 reconciler acceptance verified" --allow-empty
```

---

# Roadmap — Phases 2–4 (separate detailed plans)

Each phase below becomes its own dated plan once the prior phase lands. They are intentionally outlined, not task-detailed, because their specifics depend on Phase 1's real implementation and on empirical confirmation of the spec's flagged assumptions.

## Phase 2 — `direct`/`host.v1` hosting + per-app BrowZer

**Prerequisite confirmation (do first, gates the rest):** empirically confirm a per-app `direct` (`host.v1`) service renders the app clientlessly in a browser, and determine whether the bootstrapper handles CSP/`X-Frame-Options` (if not, the per-app handling must strip them). This is the one unproven assumption from the spec.

Planned tasks:
- `ensureHostConfig`: idempotent fixed `host.v1` config (`{protocol,address,port}`, **no `forward*`**) attached to the service; replace any `forward*` config.
- `ensureHosting` (direct branch): create/maintain a Bind policy granting edge-router identities (from `ListEdgeRouters`, per the profile's selector) Bind on the service; verify a `tunnel`-bound terminator exists, otherwise nudge.
- Per-app BrowZer: for each `browzer_enabled` route, create its own `direct` service → its backend; generate bootstrapper targets mapping `vhost → per-app service`; retire the shared `browzer-router-zt` + nginx demux + catch-all.
- Artifact rendering: bootstrapper targets generated from DB, written via the (Phase-3) sink, write-if-changed.
- Migration of existing BrowZer routes from shared to per-app, gated per-route.

## Phase 3 — Deployment profiles

Planned tasks:
- Profile type + loader (env/file/secret), with `local-containers` and `k8s-managed` implementations.
- Two-address-view plumbing (control-plane vs client-facing) feeding `ensure*` and bootstrapper config.
- Edge-router selector (all routers / by role attribute).
- Credential/CA refs + `insecure_skip_verify` as profile flags.
- Artifact-delivery adapter interface (file+reload vs ConfigMap+rollout).
- Replace the manual podman/`/tmp` box setup with a scripted/compose stack that *is* the `local-containers` profile.

## Phase 4 — Admin UX

Planned tasks:
- `web/admin-console/src/pages/ziti-network.tsx` (or successor): Zero-Trust Routes table with per-route mode selector + reconcile status; row detail drawer (read-only reconciler output); header strip (connection, profile, reconciler health + Force-reconcile).
- Backend: status read API (`GET /ziti/reconciler/status`), `POST /ziti/reconciler/reconcile` (force), per-route status surfaced.
- BrowZer + Identities & sync sub-views refactored to the desired-state/health model.

---

## Self-review notes (author)

- **Spec coverage:** Phase 1 covers the reconcile loop (single-writer, coalescing, periodic), the `hosting_mode` schema, identity-mode `ensure*`, per-object status, and the feature flag — all spec'd. `direct`/per-app BrowZer/profiles/UX are explicitly deferred to Phases 2–4 with prerequisite gates. No spec requirement is silently dropped.
- **Placeholder scan:** every code step contains complete code; the only non-detailed content is the Phase 2–4 roadmap, which is decomposition (separate plans), not in-task placeholders.
- **Type consistency:** `DesiredRoute`, `EffectiveMode()`, `ensureService`/`ensurePolicies`/`ensureHosting`/`reconcileRoute`/`reconcileOnce`, `ZitiReconciler` fields (`trigger`, `status`, `statusMu`, `runOnce`, `provider`, `period`), and the reused `ZitiManager` methods (`GetServiceByName`, `GetServiceRoleAttributes`, `PatchServiceRoleAttributes`, `SetupZitiForRoute`, `CreateServicePolicy`, `EnsureServiceEdgeRouterPolicy`, `HostService`, `IsInitialized`, `parseHostPort`) are used consistently across tasks.
