# Relations & Integrity Doctor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A check-registry "doctor" in the access-service that scans every source of truth (Postgres, Ziti controller, APISIX, BrowZer config files), reports cross-domain relation gaps/drift, auto-heals safe drift, and exposes one-click fixes for risky drift via an API + admin-console Health page.

**Architecture:** A small engine (`Check` interface → `Finding`s → `Report`) lives **in package `internal/access`** so checks can call existing unexported `Service`/`ZitiManager` routines (`consolidateApp`, `RegenerateConfigs`, `TeardownZitiServiceByName`, `deleteEdgeEntityByName`, `dedupRoutesByHost`, …) without exporting a dozen methods. Each `Check` has `Detect` and `Fix(Safe bool)`. `ScanAndHeal(applySafe)` runs safe fixes automatically; risky fixes need an explicit `FixOne` call. Triggered on-demand (Health page / API) and after route mutations.

**Tech Stack:** Go 1.22, Gin, pgx, zap; React + TS admin console; httptest for fake Ziti/APISIX in unit tests (existing pattern in `internal/access/*_test.go`).

**Spec:** `docs/superpowers/specs/2026-06-26-relations-integrity-doctor-design.md`

---

## File structure

- Create `internal/access/health_engine.go` — `Finding`, `Report`, `Check` interface, `HealthEngine` (registry + `Scan`/`ScanAndHeal`/`FixOne`), constructed from `*Service`.
- Create `internal/access/health_checks.go` — the 12 `Check` implementations (small; reuse existing routines).
- Create `internal/access/health_handlers.go` — `GET /api/v1/access/health/relations`, `POST /api/v1/access/health/fix/:checkId`.
- Create tests: `internal/access/health_engine_test.go`, `internal/access/health_checks_test.go`.
- Modify `internal/access/ziti.go` — add `listEdgeEntities` (paginated list-all; `ListServices` caps at 10).
- Modify `internal/access/service.go` — register the two routes; construct the engine.
- Modify `internal/access/app_publish.go` / `feature_manager.go` — after-mutation hook (call `engine.HealRoute`).
- Create `web/admin-console/src/pages/system-health.tsx` + a nav entry — the Health page.

Reused (already exist): `consolidateApp` (`app_publish.go:1213`), `upsertAppLauncherTile` (`:445`), `deleteAppTile` (`service.go:230`), `enqueueReconcile` (`service.go:194`), `RegenerateConfigs` (`browzer_targets.go:935`), `TeardownZitiServiceByName` (`ziti.go:1543`), `deleteEdgeEntityByName` (`ziti.go:1504`), `dedupRoutesByHost` (`browzer_targets.go:338`), `effectiveHostingMode` (`ziti_reconciler.go:80`), `APISIXClient.ListRouteNames` (`apisix_client.go:72`), `s.ziti()` (`service.go:152`).

---

## Task 1: Engine core (Finding / Report / Check / HealthEngine)

**Files:**
- Create: `internal/access/health_engine.go`
- Test: `internal/access/health_engine_test.go`

- [ ] **Step 1: Write the failing test**

```go
package access

import (
	"context"
	"testing"
)

// stubCheck lets the engine test run without real sources.
type stubCheck struct {
	id, domain string
	findings   []Finding
	fixed      *Finding
}

func (c *stubCheck) ID() string     { return c.id }
func (c *stubCheck) Domain() string { return c.domain }
func (c *stubCheck) Detect(ctx context.Context) ([]Finding, error) { return c.findings, nil }
func (c *stubCheck) Fix(ctx context.Context, f Finding) error      { c.fixed = &f; return nil }

func TestScanAndHealAppliesSafeOnly(t *testing.T) {
	safe := Finding{CheckID: "c1", Domain: "access", Status: "drift", Safe: true, Subject: "r1"}
	risky := Finding{CheckID: "c2", Domain: "ziti", Status: "orphan", Safe: false, Subject: "svc1"}
	c1 := &stubCheck{id: "c1", domain: "access", findings: []Finding{safe}}
	c2 := &stubCheck{id: "c2", domain: "ziti", findings: []Finding{risky}}
	e := &HealthEngine{checks: []Check{c1, c2}}

	rep := e.ScanAndHeal(context.Background(), true)
	if len(rep.Healed) != 1 || rep.Healed[0].CheckID != "c1" {
		t.Fatalf("expected c1 healed, got %+v", rep.Healed)
	}
	if len(rep.Remaining) != 1 || rep.Remaining[0].CheckID != "c2" {
		t.Fatalf("expected c2 remaining (risky), got %+v", rep.Remaining)
	}
	if c1.fixed == nil {
		t.Fatal("safe check c1 must have been fixed")
	}
	if c2.fixed != nil {
		t.Fatal("risky check c2 must NOT have been auto-fixed")
	}
}
```

- [ ] **Step 2: Run it — expect FAIL (undefined: Finding/HealthEngine)**

Run: `go test ./internal/access/ -run TestScanAndHealAppliesSafeOnly`
Expected: build failure — `undefined: HealthEngine`.

- [ ] **Step 3: Implement the engine**

```go
package access

import (
	"context"

	"go.uber.org/zap"
)

// Finding is one relation/integrity observation across the OpenIDX domains.
type Finding struct {
	CheckID  string `json:"check_id"`
	Domain   string `json:"domain"`   // access|apps|ziti|identity|governance|devices
	Severity string `json:"severity"` // info|warn|error
	Status   string `json:"status"`   // ok|drift|orphan
	Subject  string `json:"subject"`  // route/host/service id the finding is about
	Detail   string `json:"detail"`
	Safe     bool   `json:"safe"`   // true → eligible for auto-heal
	Action   string `json:"action"` // human label for the fix
}

// Report is the aggregate result of a scan.
type Report struct {
	Findings  []Finding `json:"findings"`            // everything detected (incl. ok)
	Healed    []Finding `json:"healed,omitempty"`    // safe findings auto-fixed this run
	Remaining []Finding `json:"remaining,omitempty"` // risky findings needing a click
}

// Check is one relation/integrity rule. Detect reports findings; Fix repairs one.
type Check interface {
	ID() string
	Domain() string
	Detect(ctx context.Context) ([]Finding, error)
	Fix(ctx context.Context, f Finding) error
}

// HealthEngine runs the registered checks.
type HealthEngine struct {
	svc    *Service
	logger *zap.Logger
	checks []Check
}

// NewHealthEngine builds the engine and registers all checks (Task 3-6 append here).
func NewHealthEngine(svc *Service) *HealthEngine {
	e := &HealthEngine{svc: svc, logger: svc.logger.With(zap.String("component", "health"))}
	e.checks = registerChecks(svc) // defined in health_checks.go
	return e
}

// Scan runs every check's Detect and aggregates (non-ok) findings.
func (e *HealthEngine) Scan(ctx context.Context) Report {
	var rep Report
	for _, c := range e.checks {
		fs, err := c.Detect(ctx)
		if err != nil {
			e.logger.Warn("check detect failed", zap.String("check", c.ID()), zap.Error(err))
			continue
		}
		rep.Findings = append(rep.Findings, fs...)
	}
	return rep
}

// ScanAndHeal scans, then (if applySafe) fixes every Safe drift/orphan finding.
func (e *HealthEngine) ScanAndHeal(ctx context.Context, applySafe bool) Report {
	rep := e.Scan(ctx)
	byID := map[string]Check{}
	for _, c := range e.checks {
		byID[c.ID()] = c
	}
	for _, f := range rep.Findings {
		if f.Status == "ok" {
			continue
		}
		if applySafe && f.Safe {
			if c := byID[f.CheckID]; c != nil {
				if err := c.Fix(ctx, f); err != nil {
					e.logger.Warn("safe heal failed", zap.String("check", f.CheckID), zap.String("subject", f.Subject), zap.Error(err))
					rep.Remaining = append(rep.Remaining, f)
					continue
				}
				rep.Healed = append(rep.Healed, f)
				continue
			}
		}
		if f.Status != "ok" {
			rep.Remaining = append(rep.Remaining, f)
		}
	}
	return rep
}

// FixOne runs a specific (typically risky) check's Fix for a subject after the
// caller has re-detected it (so the fix targets a current finding).
func (e *HealthEngine) FixOne(ctx context.Context, checkID, subject string) error {
	for _, c := range e.checks {
		if c.ID() != checkID {
			continue
		}
		fs, err := c.Detect(ctx)
		if err != nil {
			return err
		}
		for _, f := range fs {
			if f.Subject == subject && f.Status != "ok" {
				return c.Fix(ctx, f)
			}
		}
		return nil // nothing to fix (already healed)
	}
	return errCheckNotFound
}
```

Add at the bottom of the file:

```go
import "errors"

var errCheckNotFound = errors.New("unknown check id")
```

(Place the `errors` import in the existing import block, not a second block.)

- [ ] **Step 4: Run the test — expect PASS**

Run: `go test ./internal/access/ -run TestScanAndHealAppliesSafeOnly`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/access/health_engine.go internal/access/health_engine_test.go
git commit -m "feat(health): relations doctor engine (Check/Finding/Report + ScanAndHeal)"
```

---

## Task 2: Paginated Ziti list helper (orphan detection needs ALL objects)

`ListServices` (`ziti.go:1229`) and `GetServiceByName` use the management API with the default page size (10), so they cannot enumerate all controller objects for orphan detection. Add a list-all helper.

**Files:**
- Modify: `internal/access/ziti.go`
- Test: `internal/access/health_checks_test.go` (new file; shared by later tasks)

- [ ] **Step 1: Write the failing test (fake controller returns >10 names via filter limit)**

```go
package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

func TestListEdgeEntitiesReturnsAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Must request a high limit so the controller returns everything in one page.
		if r.URL.Query().Get("limit") == "" {
			t.Errorf("expected an explicit limit on %s", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"a","name":"openidx-A"},{"id":"b","name":"openidx-B"}]}`))
	}))
	defer srv.Close()
	zm := &ZitiManager{logger: zap.NewNop(), mgmtToken: "fake", mgmtClient: srv.Client(),
		cfg: &config.Config{ZitiCtrlURL: srv.URL}, initialized: true}
	got, err := zm.listEdgeEntities(context.Background(), "services")
	if err != nil {
		t.Fatalf("listEdgeEntities: %v", err)
	}
	if len(got) != 2 || got[0].Name != "openidx-A" {
		t.Fatalf("expected 2 entities, got %+v", got)
	}
}
```

- [ ] **Step 2: Run it — expect FAIL (undefined: listEdgeEntities)**

Run: `go test ./internal/access/ -run TestListEdgeEntitiesReturnsAll`
Expected: build failure.

- [ ] **Step 3: Implement `listEdgeEntities` near `deleteEdgeEntityByName` in `ziti.go`**

```go
// edgeEntity is the minimal shape of a Ziti management object (service, policy,
// config, serp) used for orphan detection.
type edgeEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// listEdgeEntities returns ALL entities in a management collection. ListServices
// and friends use the default page size (10) and silently truncate; this passes
// an explicit high limit so orphan detection sees everything at our scale.
func (zm *ZitiManager) listEdgeEntities(ctx context.Context, collection string) ([]edgeEntity, error) {
	data, status, err := zm.mgmtRequest("GET",
		"/edge/management/v1/"+collection+"?limit=1000", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing %s", status, collection)
	}
	var resp struct {
		Data []edgeEntity `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}
```

- [ ] **Step 4: Run the test — expect PASS**

Run: `go test ./internal/access/ -run TestListEdgeEntitiesReturnsAll`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/access/ziti.go internal/access/health_checks_test.go
git commit -m "feat(ziti): listEdgeEntities (paginated list-all for orphan detection)"
```

---

## Task 3: Checks registry + edge-cluster checks (tile, APISIX, redirect, dedup)

Implements safe checks #1, #2 (APISIX), #4 (redirect), #9 (browzer_config dedup). Checks #2/#3/#4 share the same fix (`RegenerateConfigs`), so they are represented as one "edge config" drift check to avoid redundant heals. All are `Safe`.

**Files:**
- Create: `internal/access/health_checks.go`
- Test: `internal/access/health_checks_test.go`

- [ ] **Step 1: Write the failing test (browzer_config dedup detect + a base check struct)**

```go
func TestBaseCheckImplementsInterface(t *testing.T) {
	var _ Check = &fnCheck{}
}

func TestDedupBrowzerConfigDetectFlagsExtraRows(t *testing.T) {
	// Pure helper: given a row count, detect should flag >1 as drift.
	if f := dedupBrowzerConfigFinding(56); f.Status != "drift" || !f.Safe {
		t.Fatalf("56 rows should be safe drift, got %+v", f)
	}
	if f := dedupBrowzerConfigFinding(1); f.Status != "ok" {
		t.Fatalf("1 row should be ok, got %+v", f)
	}
}
```

- [ ] **Step 2: Run it — expect FAIL (undefined: fnCheck/dedupBrowzerConfigFinding)**

Run: `go test ./internal/access/ -run 'TestBaseCheckImplementsInterface|TestDedupBrowzerConfigDetectFlagsExtraRows'`
Expected: build failure.

- [ ] **Step 3: Implement the registry + a function-backed check helper + edge checks**

```go
package access

import (
	"context"
	"fmt"
)

// fnCheck adapts plain functions to the Check interface so each rule is a small
// literal in registerChecks (the "compact: add a relation = add one check").
type fnCheck struct {
	id, domain string
	detect     func(ctx context.Context) ([]Finding, error)
	fix        func(ctx context.Context, f Finding) error
}

func (c *fnCheck) ID() string     { return c.id }
func (c *fnCheck) Domain() string { return c.domain }
func (c *fnCheck) Detect(ctx context.Context) ([]Finding, error) {
	if c.detect == nil {
		return nil, nil
	}
	return c.detect(ctx)
}
func (c *fnCheck) Fix(ctx context.Context, f Finding) error {
	if c.fix == nil {
		return nil
	}
	return c.fix(ctx, f)
}

// dedupBrowzerConfigFinding is the pure decision for check #9.
func dedupBrowzerConfigFinding(rowCount int) Finding {
	f := Finding{CheckID: "browzer-config-dedup", Domain: "ziti", Subject: "ziti_browzer_config",
		Severity: "warn", Safe: true, Action: "dedup to newest enabled row"}
	if rowCount > 1 {
		f.Status = "drift"
		f.Detail = fmt.Sprintf("%d rows; expected 1", rowCount)
	} else {
		f.Status = "ok"
	}
	return f
}

// registerChecks builds the full ordered check list. Tasks 4-6 append more.
func registerChecks(s *Service) []Check {
	return []Check{
		// #9 ziti_browzer_config dedup (safe)
		&fnCheck{id: "browzer-config-dedup", domain: "ziti",
			detect: func(ctx context.Context) ([]Finding, error) {
				var n int
				if err := s.db.Pool.QueryRow(ctx, `SELECT count(*) FROM ziti_browzer_config`).Scan(&n); err != nil {
					return nil, err
				}
				return []Finding{dedupBrowzerConfigFinding(n)}, nil
			},
			fix: func(ctx context.Context, f Finding) error {
				_, err := s.db.Pool.Exec(ctx, `
					DELETE FROM ziti_browzer_config WHERE id NOT IN (
						SELECT id FROM ziti_browzer_config ORDER BY enabled DESC, updated_at DESC NULLS LAST LIMIT 1)`)
				return err
			}},

		// #1 route ↔ launcher tile: every browzer/ziti route must have a proxy-app tile; no tile without a route.
		&fnCheck{id: "route-tile", domain: "apps",
			detect: func(ctx context.Context) ([]Finding, error) { return s.detectRouteTileDrift(ctx) },
			fix: func(ctx context.Context, f Finding) error {
				// Safe heal: regenerate from the route. The tile upsert/delete is keyed by route id in f.Subject.
				return s.healRouteTile(ctx, f.Subject)
			}},

		// #2/#3/#4 edge config drift (APISIX route, bootstrapper target, hop block, redirect_uris) — one safe fix.
		&fnCheck{id: "edge-config", domain: "access",
			detect: func(ctx context.Context) ([]Finding, error) { return s.detectEdgeConfigDrift(ctx) },
			fix: func(ctx context.Context, f Finding) error {
				if s.browzerTargetManager == nil {
					return nil
				}
				return s.browzerTargetManager.RegenerateConfigs(ctx)
			}},
	}
}
```

Add the detect/heal helpers (same file):

```go
// detectRouteTileDrift flags ziti/browzer routes whose launcher tile is missing
// (Subject = route id) and proxy-app tiles whose route is gone (Subject = client_id).
func (s *Service) detectRouteTileDrift(ctx context.Context) ([]Finding, error) {
	var out []Finding
	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.id, r.name FROM proxy_routes r
		WHERE (r.ziti_enabled OR r.browzer_enabled)
		  AND NOT EXISTS (SELECT 1 FROM applications a WHERE a.client_id = 'proxy-app-'||r.id::text)`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, name string
		if rows.Scan(&id, &name) == nil {
			out = append(out, Finding{CheckID: "route-tile", Domain: "apps", Severity: "warn", Status: "drift",
				Safe: true, Subject: id, Detail: "route " + name + " has no launcher tile", Action: "create tile"})
		}
	}
	rows.Close()
	orphan, err := s.db.Pool.Query(ctx, `
		SELECT a.client_id FROM applications a
		WHERE a.client_id LIKE 'proxy-app-%'
		  AND NOT EXISTS (SELECT 1 FROM proxy_routes r WHERE 'proxy-app-'||r.id::text = a.client_id)`)
	if err != nil {
		return out, nil
	}
	for orphan.Next() {
		var cid string
		if orphan.Scan(&cid) == nil {
			out = append(out, Finding{CheckID: "route-tile", Domain: "apps", Severity: "warn", Status: "orphan",
				Safe: true, Subject: cid, Detail: "tile " + cid + " has no route", Action: "delete tile"})
		}
	}
	orphan.Close()
	if len(out) == 0 {
		out = append(out, Finding{CheckID: "route-tile", Domain: "apps", Status: "ok"})
	}
	return out, nil
}

// healRouteTile repairs one route-tile finding: Subject is a route id (recreate
// the tile) or a "proxy-app-<id>" client id of an orphan tile (delete it).
func (s *Service) healRouteTile(ctx context.Context, subject string) error {
	if len(subject) > 10 && subject[:10] == "proxy-app-" {
		s.deleteAppTile(ctx, subject[10:])
		return nil
	}
	var name, fromURL, org string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT name, from_url, org_id::text FROM proxy_routes WHERE id=$1`, subject).Scan(&name, &fromURL, &org); err != nil {
		return err
	}
	s.upsertAppLauncherTile(ctx, org, subject, name, "", fromURL+"/")
	return nil
}

// detectEdgeConfigDrift flags browzer routes missing their APISIX edge route or
// whose host is absent from the browzer-client redirect_uris. One safe fix
// (RegenerateConfigs) reconverges all of it, so a single drift finding suffices.
func (s *Service) detectEdgeConfigDrift(ctx context.Context) ([]Finding, error) {
	zm := s.ziti()
	_ = zm
	// Desired browzer hosts from the DB.
	rows, err := s.db.Pool.Query(ctx, `
		SELECT from_url FROM proxy_routes
		WHERE ziti_enabled AND browzer_enabled AND enabled AND ziti_service_name <> ''`)
	if err != nil {
		return nil, err
	}
	var hosts []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			hosts = append(hosts, u)
		}
	}
	rows.Close()

	var drift []string
	// APISIX: each browzer host must have a browzer-<slug> route.
	if s.browzerTargetManager != nil && s.browzerTargetManager.apisixReconciler != nil {
		names, err := s.browzerTargetManager.apisixReconciler.client.ListRouteNames(ctx)
		if err == nil {
			have := map[string]bool{}
			for _, n := range names {
				have[n] = true
			}
			for _, u := range hosts {
				if h := hostOf(u); h != "" && !have["browzer-"+apisixSlug(h)] {
					drift = append(drift, "apisix:"+h)
				}
			}
		}
	}
	// browzer-client redirect_uris must contain every host.
	var redirects []byte
	s.db.Pool.QueryRow(ctx, `SELECT redirect_uris FROM oauth_clients WHERE client_id='browzer-client'`).Scan(&redirects)
	for _, u := range hosts {
		if h := hostOf(u); h != "" && !bytesContainsHost(redirects, h) {
			drift = append(drift, "redirect:"+h)
		}
	}

	if len(drift) == 0 {
		return []Finding{{CheckID: "edge-config", Domain: "access", Status: "ok"}}, nil
	}
	return []Finding{{CheckID: "edge-config", Domain: "access", Severity: "warn", Status: "drift", Safe: true,
		Subject: "edge", Detail: fmt.Sprintf("edge drift: %v", drift), Action: "regenerate edge configs"}}, nil
}

func hostOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Hostname()
	}
	return ""
}

func bytesContainsHost(jsonArr []byte, host string) bool {
	return strings.Contains(string(jsonArr), "//"+host)
}
```

Add imports to `health_checks.go`: `"net/url"`, `"strings"`. (`apisixSlug` is in `apisix_routes.go`; `apisixReconciler`/`client` fields exist on `BrowZerTargetManager`/`APISIXReconciler` — verify field names during implementation and adjust the accessor if private.)

- [ ] **Step 2 (run): expect the new tests FAIL → implement → PASS**

Run: `go test ./internal/access/ -run 'TestBaseCheckImplementsInterface|TestDedupBrowzerConfigDetectFlagsExtraRows'`
Expected after Step 3: PASS.

- [ ] **Step 3 (build): `go build ./internal/access/...`** — fix any field-name mismatches (`apisixReconciler.client`) by reading `apisix_reconciler.go`.

- [ ] **Step 4: Commit**

```bash
git add internal/access/health_checks.go internal/access/health_checks_test.go
git commit -m "feat(health): registry + edge-cluster checks (tile, edge-config, browzer-config dedup)"
```

---

## Task 4: Ziti checks (route↔service drift, orphan objects, per-host uniqueness)

Implements #5 (safe: reconcile), #6 (risky: teardown), #7 (risky: consolidate).

**Files:**
- Modify: `internal/access/health_checks.go` (append checks to `registerChecks` + helpers)
- Test: `internal/access/health_checks_test.go`

- [ ] **Step 1: Write the failing test (orphan-service detection is a pure set-diff)**

```go
func TestOrphanZitiServices(t *testing.T) {
	controller := []string{"openidx-A", "openidx-B", "openidx-Orphan", "non-openidx"}
	desired := map[string]bool{"openidx-A": true, "openidx-B": true}
	got := orphanOpenidxServices(controller, desired)
	if len(got) != 1 || got[0] != "openidx-Orphan" {
		t.Fatalf("expected [openidx-Orphan], got %v", got)
	}
}
```

- [ ] **Step 2: Run → FAIL (undefined: orphanOpenidxServices)**

Run: `go test ./internal/access/ -run TestOrphanZitiServices`

- [ ] **Step 3: Implement the pure helper + append the three checks**

```go
// orphanOpenidxServices returns controller service names that we own (openidx-*)
// but that no desired route claims. Non-openidx services are left alone.
func orphanOpenidxServices(controller []string, desired map[string]bool) []string {
	var out []string
	for _, n := range controller {
		if strings.HasPrefix(n, "openidx-") && !desired[n] {
			out = append(out, n)
		}
	}
	return out
}
```

Append to the slice returned by `registerChecks`:

```go
		// #5 route ↔ Ziti service (DB desired vs controller) — safe: reconcile converges.
		&fnCheck{id: "route-ziti", domain: "ziti",
			detect: func(ctx context.Context) ([]Finding, error) {
				rows, err := s.db.Pool.Query(ctx,
					`SELECT ziti_service_name FROM proxy_routes WHERE ziti_enabled AND enabled AND ziti_service_name <> ''`)
				if err != nil {
					return nil, err
				}
				var want []string
				for rows.Next() {
					var n string
					if rows.Scan(&n) == nil {
						want = append(want, n)
					}
				}
				rows.Close()
				zm := s.ziti()
				if zm == nil {
					return []Finding{{CheckID: "route-ziti", Domain: "ziti", Status: "ok"}}, nil
				}
				ents, err := zm.listEdgeEntities(ctx, "services")
				if err != nil {
					return nil, err
				}
				have := map[string]bool{}
				for _, e := range ents {
					have[e.Name] = true
				}
				var out []Finding
				for _, n := range want {
					if !have[n] {
						out = append(out, Finding{CheckID: "route-ziti", Domain: "ziti", Severity: "error",
							Status: "drift", Safe: true, Subject: n, Detail: "route service missing on controller", Action: "reconcile"})
					}
				}
				if len(out) == 0 {
					out = append(out, Finding{CheckID: "route-ziti", Domain: "ziti", Status: "ok"})
				}
				return out, nil
			},
			fix: func(ctx context.Context, f Finding) error { s.enqueueReconcile(); return nil }},

		// #6 orphan Ziti controller services (openidx-* with no route) — RISKY: teardown.
		&fnCheck{id: "ziti-orphan", domain: "ziti",
			detect: func(ctx context.Context) ([]Finding, error) {
				zm := s.ziti()
				if zm == nil {
					return []Finding{{CheckID: "ziti-orphan", Domain: "ziti", Status: "ok"}}, nil
				}
				rows, _ := s.db.Pool.Query(ctx,
					`SELECT ziti_service_name FROM proxy_routes WHERE ziti_enabled AND ziti_service_name <> ''`)
				desired := map[string]bool{}
				for rows.Next() {
					var n string
					if rows.Scan(&n) == nil {
						desired[n] = true
					}
				}
				rows.Close()
				ents, err := zm.listEdgeEntities(ctx, "services")
				if err != nil {
					return nil, err
				}
				var names []string
				for _, e := range ents {
					names = append(names, e.Name)
				}
				var out []Finding
				for _, n := range orphanOpenidxServices(names, desired) {
					out = append(out, Finding{CheckID: "ziti-orphan", Domain: "ziti", Severity: "warn",
						Status: "orphan", Safe: false, Subject: n, Detail: "controller service with no owning route", Action: "tear down service"})
				}
				if len(out) == 0 {
					out = append(out, Finding{CheckID: "ziti-orphan", Domain: "ziti", Status: "ok"})
				}
				return out, nil
			},
			fix: func(ctx context.Context, f Finding) error {
				zm := s.ziti()
				if zm == nil {
					return nil
				}
				return zm.TeardownZitiServiceByName(ctx, f.Subject)
			}},

		// #7 per-host uniqueness: >1 proxy_route on one host — RISKY: consolidate (subject = host).
		&fnCheck{id: "host-unique", domain: "access",
			detect: func(ctx context.Context) ([]Finding, error) {
				rows, err := s.db.Pool.Query(ctx, `
					SELECT lower(split_part(split_part(from_url,'//',2),'/',1)) AS host, count(*)
					FROM proxy_routes WHERE ziti_enabled AND enabled
					GROUP BY 1 HAVING count(*) > 1`)
				if err != nil {
					return nil, err
				}
				var out []Finding
				for rows.Next() {
					var host string
					var n int
					if rows.Scan(&host, &n) == nil {
						out = append(out, Finding{CheckID: "host-unique", Domain: "access", Severity: "error",
							Status: "drift", Safe: false, Subject: host,
							Detail: fmt.Sprintf("%d routes share host %s", n, host), Action: "consolidate app"})
					}
				}
				rows.Close()
				if len(out) == 0 {
					out = append(out, Finding{CheckID: "host-unique", Domain: "access", Status: "ok"})
				}
				return out, nil
			},
			fix: func(ctx context.Context, f Finding) error {
				var appID, org string
				err := s.db.Pool.QueryRow(ctx, `
					SELECT pa.id::text, pa.org_id::text FROM published_apps pa
					JOIN proxy_routes r ON r.from_url LIKE 'https://'||$1||'%'
					WHERE pa.public_host = $1 LIMIT 1`, f.Subject).Scan(&appID, &org)
				if err != nil {
					return fmt.Errorf("no published_app for host %s: %w", f.Subject, err)
				}
				_, _, err = s.consolidateApp(ctx, org, appID, "")
				return err
			}},
```

- [ ] **Step 4: Run → PASS**

Run: `go test ./internal/access/ -run TestOrphanZitiServices`
Then `go build ./internal/access/...`.

- [ ] **Step 5: Commit**

```bash
git add internal/access/health_checks.go internal/access/health_checks_test.go
git commit -m "feat(health): ziti checks (route-service drift, orphan teardown, per-host uniqueness)"
```

---

## Task 5: Data + presence checks (app↔client, published_app, identity, governance/devices)

Implements #8, #10 (data) and #11, #12 (presence, report-only).

**Files:**
- Modify: `internal/access/health_checks.go`
- Test: `internal/access/health_checks_test.go`

- [ ] **Step 1: Write the failing test (presence finding helper)**

```go
func TestPresenceFinding(t *testing.T) {
	f := presenceFinding("devices", "devices", 0)
	if f.Status != "drift" || f.Safe {
		t.Fatalf("empty domain should be report-only drift, got %+v", f)
	}
	if presenceFinding("devices", "devices", 3).Status != "ok" {
		t.Fatal("non-empty should be ok")
	}
}
```

- [ ] **Step 2: Run → FAIL**

Run: `go test ./internal/access/ -run TestPresenceFinding`

- [ ] **Step 3: Implement the helper + append checks**

```go
// presenceFinding flags an empty/unwired domain as report-only drift (info).
func presenceFinding(checkID, domain string, count int) Finding {
	f := Finding{CheckID: checkID, Domain: domain, Severity: "info", Subject: domain, Safe: false,
		Action: "wire up domain (manual)"}
	if count == 0 {
		f.Status = "drift"
		f.Detail = domain + " has no records (not wired up)"
	} else {
		f.Status = "ok"
	}
	return f
}
```

Append to `registerChecks`:

```go
		// #8 app ↔ oauth_client: real OIDC app (non-proxy tile) without a client — report only.
		&fnCheck{id: "app-client", domain: "apps",
			detect: func(ctx context.Context) ([]Finding, error) {
				rows, err := s.db.Pool.Query(ctx, `
					SELECT a.name, a.client_id FROM applications a
					WHERE a.client_id NOT LIKE 'proxy-app-%'
					  AND NOT EXISTS (SELECT 1 FROM oauth_clients oc WHERE oc.client_id=a.client_id)`)
				if err != nil {
					return nil, err
				}
				var out []Finding
				for rows.Next() {
					var name, cid string
					if rows.Scan(&name, &cid) == nil {
						out = append(out, Finding{CheckID: "app-client", Domain: "apps", Severity: "warn",
							Status: "orphan", Safe: false, Subject: cid, Detail: "application " + name + " has no oauth_client", Action: "review (manual)"})
					}
				}
				rows.Close()
				if len(out) == 0 {
					out = append(out, Finding{CheckID: "app-client", Domain: "apps", Status: "ok"})
				}
				return out, nil
			}},

		// #10 published_app status consistency — safe: mark published if it has a linked route.
		&fnCheck{id: "published-app", domain: "apps",
			detect: func(ctx context.Context) ([]Finding, error) {
				rows, err := s.db.Pool.Query(ctx, `
					SELECT pa.id::text, pa.name FROM published_apps pa
					WHERE pa.status <> 'published'
					  AND EXISTS (SELECT 1 FROM discovered_paths dp WHERE dp.app_id=pa.id AND dp.route_id IS NOT NULL)`)
				if err != nil {
					return nil, err
				}
				var out []Finding
				for rows.Next() {
					var id, name string
					if rows.Scan(&id, &name) == nil {
						out = append(out, Finding{CheckID: "published-app", Domain: "apps", Severity: "info",
							Status: "drift", Safe: true, Subject: id, Detail: name + " has routes but status<>published", Action: "set status=published"})
					}
				}
				rows.Close()
				if len(out) == 0 {
					out = append(out, Finding{CheckID: "published-app", Domain: "apps", Status: "ok"})
				}
				return out, nil
			},
			fix: func(ctx context.Context, f Finding) error {
				_, err := s.db.Pool.Exec(ctx, `UPDATE published_apps SET status='published', updated_at=NOW() WHERE id=$1`, f.Subject)
				return err
			}},

		// #11 users ↔ ziti_identities — report only.
		&fnCheck{id: "identity-ziti", domain: "identity",
			detect: func(ctx context.Context) ([]Finding, error) {
				var unlinked int
				s.db.Pool.QueryRow(ctx,
					`SELECT count(*) FROM ziti_identities zi WHERE zi.user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id=zi.user_id)`).Scan(&unlinked)
				if unlinked > 0 {
					return []Finding{{CheckID: "identity-ziti", Domain: "identity", Severity: "warn", Status: "orphan",
						Safe: false, Subject: "ziti_identities", Detail: fmt.Sprintf("%d identities reference a missing user", unlinked), Action: "review (manual)"}}, nil
				}
				return []Finding{{CheckID: "identity-ziti", Domain: "identity", Status: "ok"}}, nil
			}},

		// #12 governance + devices wired? — presence only.
		&fnCheck{id: "domain-presence", domain: "governance",
			detect: func(ctx context.Context) ([]Finding, error) {
				var policies, devices int
				s.db.Pool.QueryRow(ctx, `SELECT count(*) FROM policies`).Scan(&policies)
				s.db.Pool.QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&devices)
				return []Finding{presenceFinding("domain-presence", "governance", policies), presenceFinding("domain-presence", "devices", devices)}, nil
			}},
```

- [ ] **Step 4: Run → PASS + build**

Run: `go test ./internal/access/ -run TestPresenceFinding` then `go build ./internal/access/...`.
(If `devices` table doesn't exist in some envs, guard the query with a `to_regclass('devices')` check or ignore the error — the live box has the table.)

- [ ] **Step 5: Commit**

```bash
git add internal/access/health_checks.go internal/access/health_checks_test.go
git commit -m "feat(health): data + presence checks (app-client, published-app, identity, domain presence)"
```

---

## Task 6: API handlers + wiring

**Files:**
- Create: `internal/access/health_handlers.go`
- Modify: `internal/access/service.go` (construct engine; register routes)

- [ ] **Step 1: Implement the handlers**

```go
package access

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// GET /api/v1/access/health/relations[?heal=safe]
func (s *Service) handleHealthRelations(c *gin.Context) {
	if s.healthEngine == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "health engine not initialized"})
		return
	}
	rep := s.healthEngine.Scan(c.Request.Context())
	if c.Query("heal") == "safe" {
		rep = s.healthEngine.ScanAndHeal(c.Request.Context(), true)
	}
	c.JSON(http.StatusOK, rep)
}

// POST /api/v1/access/health/fix/:checkId  body: {"subject":"..."}
func (s *Service) handleHealthFix(c *gin.Context) {
	if s.healthEngine == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "health engine not initialized"})
		return
	}
	var req struct {
		Subject string `json:"subject"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.healthEngine.FixOne(c.Request.Context(), c.Param("checkId"), req.Subject); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.logAuditEvent(c, "health_fix_applied", c.Param("checkId"), "system_health", map[string]interface{}{"subject": req.Subject})
	c.JSON(http.StatusOK, gin.H{"message": "fix applied", "check": c.Param("checkId"), "subject": req.Subject})
}
```

- [ ] **Step 2: Add `healthEngine *HealthEngine` field to `Service`** (`service.go`, struct near `browzerTargetManager`), and a setter/constructor call. In `cmd/access-service/main.go` after the service + browzerTargetManager + zitiProvider are wired, add: `accessService.SetHealthEngine(access.NewHealthEngine(accessService))`. Add to `service.go`:

```go
func (s *Service) SetHealthEngine(e *HealthEngine) { s.healthEngine = e }
```

- [ ] **Step 3: Register routes** in `RegisterRoutes` (the `api` group, near the `/apps` routes ~`service.go:519`):

```go
		api.GET("/health/relations", svc.handleHealthRelations)
		api.POST("/health/fix/:checkId", svc.handleHealthFix)
```

- [ ] **Step 4: Build**

Run: `go build ./... && go vet ./internal/access/...`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add internal/access/health_handlers.go internal/access/service.go cmd/access-service/main.go
git commit -m "feat(health): API (GET /health/relations, POST /health/fix) + engine wiring"
```

---

## Task 7: After-mutation hook

Heal the touched route's safe drift right after publish/toggle/delete (no full scan).

**Files:**
- Modify: `internal/access/health_engine.go` (add `HealRoute`)
- Modify: `internal/access/app_publish.go` (call it at the end of `handlePublishPaths`, `consolidateApp`) and `internal/access/feature_manager.go` (after enable/disable toggles)

- [ ] **Step 1: Add `HealRoute` to the engine**

```go
// HealRoute runs the safe checks after a single-route mutation. Cheap subset:
// regenerate edge configs + reconcile + tile sync already happen in those flows;
// this guarantees the safe checks are applied even if a caller forgets.
func (e *HealthEngine) HealRoute(ctx context.Context, routeID string) {
	if e == nil {
		return
	}
	if err := e.svc.healRouteTile(ctx, routeID); err != nil {
		e.logger.Debug("post-mutation tile heal", zap.String("route", routeID), zap.Error(err))
	}
	if e.svc.browzerTargetManager != nil {
		_ = e.svc.browzerTargetManager.RegenerateConfigs(ctx)
	}
	e.svc.enqueueReconcile()
}
```

- [ ] **Step 2: Call it** at the end of `handlePublishPaths` and `consolidateApp` (`s.healthEngine.HealRoute(ctx, appRouteID)` / `canonicalID`) and after the feature toggle commit in `feature_manager.go` (guard nil). These flows already call most of this; the call makes "safe heal after mutation" explicit and centralized.

- [ ] **Step 3: Build + full access tests**

Run: `go build ./... && go test ./internal/access/`
Expected: clean/green.

- [ ] **Step 4: Commit**

```bash
git add internal/access/health_engine.go internal/access/app_publish.go internal/access/feature_manager.go
git commit -m "feat(health): heal touched route's safe drift after mutations"
```

---

## Task 8: Admin console — System Health page

**Files:**
- Create: `web/admin-console/src/pages/system-health.tsx`
- Modify: the router/nav (follow `proxy-routes.tsx` registration pattern) to add a "System Health" entry.

- [ ] **Step 1: Implement the page** (React Query; mirrors `proxy-routes.tsx` data patterns)

```tsx
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { useToast } from '@/components/ui/use-toast'

interface Finding {
  check_id: string; domain: string; severity: string; status: string
  subject: string; detail: string; safe: boolean; action: string
}
interface Report { findings: Finding[]; healed?: Finding[]; remaining?: Finding[] }

export function SystemHealthPage() {
  const qc = useQueryClient(); const { toast } = useToast()
  const { data, isLoading } = useQuery({
    queryKey: ['health-relations'],
    queryFn: () => api.get<Report>('/api/v1/access/health/relations'),
  })
  const heal = useMutation({
    mutationFn: () => api.get<Report>('/api/v1/access/health/relations?heal=safe'),
    onSuccess: (r) => { toast({ title: 'Healed', description: `${r.healed?.length ?? 0} safe fixes applied`, variant: 'success' }); qc.invalidateQueries({ queryKey: ['health-relations'] }) },
  })
  const fix = useMutation({
    mutationFn: (f: Finding) => api.post(`/api/v1/access/health/fix/${f.check_id}`, { subject: f.subject }),
    onSuccess: () => { toast({ title: 'Fixed', variant: 'success' }); qc.invalidateQueries({ queryKey: ['health-relations'] }) },
    onError: (e: Error) => toast({ title: 'Fix failed', description: e.message, variant: 'destructive' }),
  })

  const findings = (data?.findings ?? []).filter(f => f.status !== 'ok')
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div><h1 className="text-2xl font-semibold">System Health</h1>
          <p className="text-sm text-muted-foreground">Cross-domain relations & integrity</p></div>
        <Button onClick={() => heal.mutate()} disabled={heal.isPending}>
          {heal.isPending ? 'Healing…' : 'Scan & heal (safe)'}
        </Button>
      </div>
      {isLoading ? <p>Loading…</p> : findings.length === 0 ? (
        <Card className="p-6">✓ No drift detected.</Card>
      ) : findings.map((f, i) => (
        <Card key={i} className="p-4 flex items-center justify-between">
          <div>
            <div className="text-sm font-medium">[{f.domain}] {f.check_id} — {f.status}</div>
            <div className="text-xs text-muted-foreground">{f.detail || f.subject}</div>
          </div>
          {f.safe
            ? <span className="text-xs text-green-600">auto-heals on scan</span>
            : <Button variant="outline" size="sm" disabled={fix.isPending} onClick={() => fix.mutate(f)}>{f.action || 'Fix'}</Button>}
        </Card>
      ))}
    </div>
  )
}
```

- [ ] **Step 2: Register the route/nav** following the existing pattern (where `ProxyRoutesPage` is wired). Add a sidebar link "System Health".

- [ ] **Step 3: Typecheck + build**

Run: `cd web/admin-console && npx tsc --noEmit && npm run build`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add web/admin-console/src/pages/system-health.tsx web/admin-console/src/<router/nav files>
git commit -m "feat(console): System Health (relations & integrity) page"
```

---

## Task 9: Live verification

- [ ] **Step 1: Build + deploy + restart**

```bash
cd /home/cmit/openidx
go build -o /home/cmit/oidx-runtime/bin/oidx-access-service ./cmd/access-service
systemctl --user restart oidx-access && sleep 4 && systemctl --user is-active oidx-access
cd web/admin-console && npm run build   # served by oidx-nginx from dist/
```

- [ ] **Step 2: Scan (expect today's real gaps)**

Run: `curl -s http://127.0.0.1:8007/api/v1/access/health/relations | python3 -m json.tool` (python3 unavailable in containers but present on host).
Expected findings include: `browzer-config-dedup` drift (56 rows), `app-client` orphan (the 1 app without a client), `domain-presence` drift (governance/devices empty), and `ok` for the route/edge/ziti checks (already consolidated this cycle).

- [ ] **Step 3: Heal safe**

Run: `curl -s 'http://127.0.0.1:8007/api/v1/access/health/relations?heal=safe'`
Expected: `healed` contains `browzer-config-dedup`; re-scan shows `ziti_browzer_config` count = 1.

- [ ] **Step 4: Verify a risky fix path (do NOT auto-run)** — confirm `ziti-orphan`/`host-unique` appear in `remaining` only (not auto-healed). If a real orphan exists, `POST /health/fix/ziti-orphan {"subject":"<svc>"}` tears it down; re-scan clean.

- [ ] **Step 5: Commit any fixups; open PR**

```bash
git add -A && git commit -m "test(health): live verification fixups" || true
```

---

## Self-review notes (author)

- **Spec coverage:** engine (Task 1) ✓; sources-of-truth incl. paginated Ziti list (Task 2) ✓; checks #1–#12 mapped — #1 route-tile (T3), #2/#3/#4 folded into `edge-config` (T3), #5 route-ziti (T4), #6 ziti-orphan (T4), #7 host-unique (T4), #8 app-client (T5), #9 browzer-config-dedup (T3), #10 published-app (T5), #11 identity-ziti (T5), #12 domain-presence (T5) ✓; API + console + after-mutation hook (T6–T8) ✓; testing per task + live (T9) ✓.
- **Field/accessor risk:** `s.browzerTargetManager.apisixReconciler.client` and `APISIXReconciler.client` field visibility must be confirmed in `apisix_reconciler.go`/`apisix_client.go` during T3; if unexported and cross-file-but-same-package they're fine (all in `internal/access`). If the reconciler lacks a reusable client accessor, add `func (r *APISIXReconciler) Client() *APISIXClient`.
- **Type consistency:** `Finding`/`Report`/`Check`/`fnCheck`/`HealthEngine` names are used identically across tasks; `s.healthEngine` field + `SetHealthEngine` consistent T6–T7.
- **YAGNI:** #2/#3/#4 share one fix → one `edge-config` check (no per-artifact redundancy). Presence checks are report-only (no premature governance/device work).
```
