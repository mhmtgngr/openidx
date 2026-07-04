# OpenZiti Phase 2 — Per-App BrowZer Services (direct / host.v1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each BrowZer-enabled route its own Ziti service hosted by the edge router via a fixed-target `host.v1` config, so multiple clientless apps coexist without the shared `browzer-router` Host-demux — and HTTPS upstreams work via the runtime's end-to-end WASM TLS.

**Architecture:** Today every BrowZer route is multiplexed over one Ziti service (`browzer-router-zt`) into one nginx that demuxes by `Host`. The BrowZer WASM runtime sends a fixed `Host: unknown` on overlay requests, so that demux can only ever serve one app (the nginx `default_server`). Phase 2 replaces this: the reconciler's **`direct`** hosting mode creates a per-route Ziti service whose `host.v1` config points at a **fixed** upstream (`{protocol,address,port}` — NOT the `forward*` form), grants **Bind to the edge-router identity** (the router hosts it, no SDK terminator), and the bootstrapper target maps `vhost → that per-app service` with `scheme` taken from the route's `to_url`. The browser dials the app's own service directly; for `scheme:https` the runtime does WASM TLS end-to-end to the upstream, so no nginx TLS hop is needed. The shared `browzer-router-zt` + nginx demux is retired for `direct` routes.

**Tech Stack:** Go 1.22, OpenZiti management REST API (`ziti.go` `mgmtRequest`), `sdk-golang` v1.7.0, the reconciler (`internal/access/ziti_reconciler.go`, flag `ZITI_RECONCILER`), Postgres (`proxy_routes.hosting_mode` from v47), the BrowZer bootstrapper (config.json `targetArray`).

---

## Background the implementer needs

- **Reconciler shape** (`internal/access/ziti_reconciler.go`): `reconcileRoute` runs `ensureService → ensurePolicies → ensureHosting` per `DesiredRoute{ServiceName,ToURL,HostingMode,BrowZerEnabled}`. `EffectiveMode()` already returns `"direct"` for BrowZer routes. `ensureHosting`'s `direct` case is currently `return fmt.Errorf("direct hosting mode not implemented until Phase 2 ...")`. The reconciler is the ONLY mutator when `ZITI_RECONCILER=true`; it must not write back to the DB.
- **host.v1 gotcha** (confirmed in a prior session): a config built with `forwardProtocol/forwardAddress/forwardPort: true` requires the *dialer* to supply protocol/address/port, which the BrowZer runtime does not — it fails with `dst_protocol required`. A **fixed** target must therefore be `{"protocol":"tcp","address":<host>,"port":<port>}` and OMIT every `forward*` / `allowed*` key. The existing `SetupZitiForRoute` (`ziti.go:1253`) builds the *forward* form — do not reuse it for direct mode.
- **Identity vs direct hosting:** identity mode = the access-proxy SDK binds a terminator and forwards (today's default). direct mode = the service carries a `host.v1` config and the **edge-router identity** holds the Bind, so the router hosts it. The router identity on this box is named `oidx-router` (Ziti edge-router). Its role attributes are empty by default; the plan adds a stable role attribute `#ziti-routers` to all routers and binds direct services to that role.
- **Bootstrapper target** (`browzer_targets.go` `BrowZerTarget`): `{VHost, Service, Path, Scheme, IDPIssuerURL, IDPClientID}`. Today `Service` is hardcoded to `BrowZerRouterServiceName` ("browzer-router-zt") and `Scheme` to `"http"`. Phase 2: `Service = route.ziti_service_name`, `Scheme = url.Parse(to_url).Scheme`.
- **Mock controller for tests:** `ziti_reconciler_test.go` already stands up an `httptest.Server` that answers the Ziti management API and injects `DesiredRoute`s via the overridable `runOnce`. New tests follow that pattern — assert on the JSON bodies POSTed to `/edge/management/v1/configs`, `/services`, `/service-policies`.

---

## File structure

- **Modify** `internal/access/ziti.go` — add `CreateHostV1ConfigFixed(ctx, name, host, port) (string, error)` (fixed-target config) and `EnsureRouterRoleAttribute(ctx)` (tag routers `#ziti-routers`). Small, focused additions next to the existing config/mgmt helpers.
- **Modify** `internal/access/ziti_reconciler.go` — implement `ensureHosting` direct mode + a new `ensureDirectService`/`ensureDirectPolicies`; route `ensureService`/`ensurePolicies` by `EffectiveMode()`.
- **Modify** `internal/access/ziti_reconciler_test.go` — tests for the direct-mode path (config body shape, router bind, no SDK Listen).
- **Modify** `internal/access/browzer_targets.go` — per-app `Service` + `Scheme` in `GenerateBrowZerTargets`; skip `direct` routes in `GenerateBrowZerRouterConfig` (retire the shared demux for them).
- **Modify** `internal/access/browzer_targets_test.go` (create if absent) — target/scheme assertions.
- **No migration** — `hosting_mode` (v47) and `landing_path` (v48) already exist.

---

## Phase 2a — `host.v1` fixed-target config + router role attribute

### Task 1: `CreateHostV1ConfigFixed` — fixed-target host.v1 config

**Files:**
- Modify: `internal/access/ziti.go` (add after `CreateServiceWithConfig`, ~line 1674)
- Test: `internal/access/ziti_hostv1_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `internal/access/ziti_hostv1_test.go`:

```go
package access

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateHostV1ConfigFixedOmitsForwardKeys(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/edge/management/v1/configs" && r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &gotBody)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"cfg-1"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	zm := newTestZitiManager(t, srv.URL) // existing test helper; see ziti_reconciler_test.go
	id, err := zm.CreateHostV1ConfigFixed(context.Background(), "psm-zt-host", "192.168.152.112", 443)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "cfg-1" {
		t.Fatalf("want config id cfg-1, got %q", id)
	}
	data, _ := gotBody["data"].(map[string]interface{})
	if data == nil {
		t.Fatalf("config body missing data object: %+v", gotBody)
	}
	for _, forbidden := range []string{"forwardProtocol", "forwardAddress", "forwardPort", "allowedProtocols", "allowedAddresses", "allowedPortRanges"} {
		if _, present := data[forbidden]; present {
			t.Fatalf("fixed host.v1 config must omit %q; got %+v", forbidden, data)
		}
	}
	if data["protocol"] != "tcp" || data["address"] != "192.168.152.112" || data["port"].(float64) != 443 {
		t.Fatalf("fixed target wrong: %+v", data)
	}
}
```

> If `newTestZitiManager` does not exist, add a tiny helper in the test file that builds a `&ZitiManager{}` with `mgmtURL`/`mgmtToken`/`httpClient` pointed at `srv.URL` exactly as `ziti_reconciler_test.go` already does for its mock controller — copy that construction, do not invent new fields.

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/access/ -run TestCreateHostV1ConfigFixedOmitsForwardKeys -v`
Expected: FAIL — `zm.CreateHostV1ConfigFixed undefined`.

- [ ] **Step 3: Implement `CreateHostV1ConfigFixed`**

In `internal/access/ziti.go`, after `CreateServiceWithConfig`:

```go
// CreateHostV1ConfigFixed creates a host.v1 config that points at a FIXED
// upstream. Unlike the forward* form (which makes the dialer choose the target
// and fails BrowZer with "dst_protocol required"), this pins protocol/address/
// port so the edge router hosts the service straight to the upstream. Returns
// the new config's id.
func (zm *ZitiManager) CreateHostV1ConfigFixed(ctx context.Context, name, host string, port int) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"name":         name,
		"configTypeId": zm.resolveConfigTypeID("host.v1"),
		"data": map[string]interface{}{
			"protocol": "tcp",
			"address":  host,
			"port":     port,
		},
	})
	data, status, err := zm.mgmtRequest("POST", "/edge/management/v1/configs", body)
	if err != nil {
		return "", fmt.Errorf("create host.v1 config: %w", err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d creating host.v1 config: %s", status, string(data))
	}
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("parse host.v1 config response: %w", err)
	}
	return resp.Data.ID, nil
}
```

- [ ] **Step 4: Run it, verify it passes**

Run: `go test ./internal/access/ -run TestCreateHostV1ConfigFixedOmitsForwardKeys -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/access/ziti.go internal/access/ziti_hostv1_test.go
git commit -m "feat(ziti): CreateHostV1ConfigFixed — fixed-target host.v1 config for direct hosting"
```

### Task 2: `EnsureRouterRoleAttribute` — tag edge routers `#ziti-routers`

**Files:**
- Modify: `internal/access/ziti.go` (after Task 1's function)
- Test: `internal/access/ziti_hostv1_test.go`

- [ ] **Step 1: Write the failing test**

Append to `ziti_hostv1_test.go`:

```go
func TestEnsureRouterRoleAttributePatchesEachRouter(t *testing.T) {
	patched := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/edge/management/v1/edge-routers" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"data":[{"id":"r1","roleAttributes":[]},{"id":"r2","roleAttributes":["x"]}]}`))
		case r.Method == "PATCH":
			id := r.URL.Path[len("/edge/management/v1/edge-routers/"):]
			patched[id] = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	zm := newTestZitiManager(t, srv.URL)
	if err := zm.EnsureRouterRoleAttribute(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !patched["r1"] || !patched["r2"] {
		t.Fatalf("expected both routers patched with #ziti-routers, got %+v", patched)
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/access/ -run TestEnsureRouterRoleAttributePatchesEachRouter -v`
Expected: FAIL — `zm.EnsureRouterRoleAttribute undefined`.

- [ ] **Step 3: Implement**

```go
// EnsureRouterRoleAttribute tags every edge router with the "ziti-routers" role
// attribute (idempotent), so direct-mode Bind policies can grant the routers as
// a stable role (#ziti-routers) instead of by id.
func (zm *ZitiManager) EnsureRouterRoleAttribute(ctx context.Context) error {
	data, status, err := zm.mgmtRequest("GET", "/edge/management/v1/edge-routers?limit=1000", nil)
	if err != nil {
		return fmt.Errorf("list edge routers: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("unexpected status %d listing edge routers: %s", status, string(data))
	}
	var resp struct {
		Data []struct {
			ID             string   `json:"id"`
			RoleAttributes []string `json:"roleAttributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("parse edge routers: %w", err)
	}
	for _, r := range resp.Data {
		has := false
		for _, a := range r.RoleAttributes {
			if a == "ziti-routers" {
				has = true
				break
			}
		}
		if has {
			continue
		}
		patch, _ := json.Marshal(map[string]interface{}{
			"roleAttributes": append(r.RoleAttributes, "ziti-routers"),
		})
		if _, s, perr := zm.mgmtRequest("PATCH", "/edge/management/v1/edge-routers/"+r.ID, patch); perr != nil || (s != http.StatusOK && s != http.StatusAccepted) {
			zm.logger.Warn("failed to tag edge router with #ziti-routers", zap.String("router", r.ID), zap.Int("status", s), zap.Error(perr))
		}
	}
	return nil
}
```

- [ ] **Step 4: Run it, verify it passes**

Run: `go test ./internal/access/ -run TestEnsureRouterRoleAttributePatchesEachRouter -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/access/ziti.go internal/access/ziti_hostv1_test.go
git commit -m "feat(ziti): EnsureRouterRoleAttribute — tag routers #ziti-routers for direct-mode binds"
```

---

## Phase 2b — reconciler direct-mode hosting

### Task 3: `ensureHosting` direct mode = host.v1 service + router bind

**Files:**
- Modify: `internal/access/ziti_reconciler.go` (`ensureService`, `ensurePolicies`, `ensureHosting`)
- Test: `internal/access/ziti_reconciler_test.go`

- [ ] **Step 1: Write the failing test**

Append to `ziti_reconciler_test.go` (mirror the existing `TestEnsureHosting*` mock-controller tests):

```go
func TestEnsureHostingDirectCreatesHostV1AndRouterBind(t *testing.T) {
	var createdConfig, createdServiceWithConfig bool
	var bindIdentityRoles []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/edge/management/v1/configs" && r.Method == "POST":
			createdConfig = true
			w.WriteHeader(http.StatusCreated); _, _ = w.Write([]byte(`{"data":{"id":"cfg-1"}}`))
		case r.URL.Path == "/edge/management/v1/services" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"data":[]}`)) // not yet present
		case r.URL.Path == "/edge/management/v1/services" && r.Method == "POST":
			b, _ := io.ReadAll(r.Body)
			createdServiceWithConfig = bytesContains(b, "cfg-1")
			w.WriteHeader(http.StatusCreated); _, _ = w.Write([]byte(`{"data":{"id":"svc-1"}}`))
		case r.URL.Path == "/edge/management/v1/service-policies" && r.Method == "POST":
			b, _ := io.ReadAll(r.Body)
			if bytesContains(b, "Bind") {
				bindIdentityRoles = extractIdentityRoles(b) // small test helper: json-parse identityRoles
			}
			w.WriteHeader(http.StatusCreated); _, _ = w.Write([]byte(`{"data":{"id":"pol-1"}}`))
		default:
			w.WriteHeader(http.StatusOK); _, _ = w.Write([]byte(`{"data":{}}`))
		}
	}))
	defer srv.Close()

	rec := newTestReconciler(t, srv.URL) // existing helper in this test file
	d := DesiredRoute{ServiceName: "psm-zt", ToURL: "https://192.168.152.112:443", BrowZerEnabled: true}
	rec.reconcileRoute(context.Background(), rec.provider.Get(), d)

	if !createdConfig {
		t.Fatal("direct mode must create a host.v1 config")
	}
	if !createdServiceWithConfig {
		t.Fatal("direct mode must create the service attached to the host.v1 config")
	}
	if len(bindIdentityRoles) != 1 || bindIdentityRoles[0] != "#ziti-routers" {
		t.Fatalf("direct Bind must grant #ziti-routers, got %+v", bindIdentityRoles)
	}
	if rec.statusFor("psm-zt") != "synced" {
		t.Fatalf("want synced, got %q", rec.statusFor("psm-zt"))
	}
}
```

> Add the two tiny test helpers `bytesContains(b []byte, s string) bool` (`strings.Contains(string(b), s)`) and `extractIdentityRoles(b []byte) []string` (json-unmarshal `{identityRoles:[]}`) at the bottom of the test file if not already present. `newTestReconciler` and `statusFor` already exist from Phase 1 — reuse them.

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/access/ -run TestEnsureHostingDirectCreatesHostV1AndRouterBind -v`
Expected: FAIL — direct mode returns the "not implemented" error, so status is `error: ...` and no config is created.

- [ ] **Step 3: Implement direct-mode hosting**

In `ziti_reconciler.go`, replace the `direct` arm of `ensureHosting` and split service/policy creation by mode. Replace `ensureHosting`:

```go
// ensureHosting starts hosting for the route. identity mode uses SDK Listen
// (HostService, idempotent). direct mode relies on the host.v1 config created
// in ensureService and the router Bind created in ensurePolicies, so there is
// nothing further to do here — the edge router hosts the service itself.
func (rec *ZitiReconciler) ensureHosting(ctx context.Context, zm *ZitiManager, d DesiredRoute) error {
	switch d.EffectiveMode() {
	case HostingModeIdentity:
		host, port := parseHostPort(d.ToURL)
		return zm.HostService(d.ServiceName, host, port)
	case HostingModeDirect:
		return nil // router hosts via host.v1; see ensureService/ensurePolicies
	default:
		return fmt.Errorf("unknown hosting mode for service %s", d.ServiceName)
	}
}
```

Then make `ensureService` create the service WITH a fixed host.v1 config for direct routes. Replace `ensureService`:

```go
func (rec *ZitiReconciler) ensureService(ctx context.Context, zm *ZitiManager, d DesiredRoute) error {
	if existing, _ := zm.GetServiceByName(d.ServiceName); existing != nil {
		return rec.ensureServiceAttr(ctx, zm, existing.ID, d.ServiceName)
	}
	var err error
	switch d.EffectiveMode() {
	case HostingModeDirect:
		host, port := parseHostPort(d.ToURL)
		cfgID, cerr := zm.CreateHostV1ConfigFixed(ctx, d.ServiceName+"-host", host, port)
		if cerr != nil {
			return cerr
		}
		_, err = zm.createServiceWithConfigID(ctx, d.ServiceName, []string{d.ServiceName}, cfgID)
	default:
		_, err = zm.CreateService(ctx, d.ServiceName, []string{d.ServiceName})
	}
	if err != nil {
		if again, _ := zm.GetServiceByName(d.ServiceName); again == nil {
			return err
		}
	}
	svc, gerr := zm.GetServiceByName(d.ServiceName)
	if gerr != nil || svc == nil {
		return gerr
	}
	return rec.ensureServiceAttr(ctx, zm, svc.ID, d.ServiceName)
}

// ensureServiceAttr ensures the service carries its name as a role attribute.
func (rec *ZitiReconciler) ensureServiceAttr(ctx context.Context, zm *ZitiManager, svcID, name string) error {
	attrs, err := zm.GetServiceRoleAttributes(ctx, svcID)
	if err != nil {
		return err
	}
	for _, a := range attrs {
		if a == name {
			return nil
		}
	}
	return zm.PatchServiceRoleAttributes(ctx, svcID, append(attrs, name))
}
```

Add `createServiceWithConfigID` to `ziti.go` (thin wrapper around the existing service-POST that attaches a config id):

```go
// createServiceWithConfigID creates an encryption-required service with the
// given role attributes and an attached config id (e.g. a host.v1 config).
func (zm *ZitiManager) createServiceWithConfigID(ctx context.Context, name string, attrs []string, configID string) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"name":               name,
		"roleAttributes":     attrs,
		"encryptionRequired": true,
		"configs":            []string{configID},
	})
	data, status, err := zm.mgmtRequest("POST", "/edge/management/v1/services", body)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d creating service: %s", status, string(data))
	}
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(data, &resp)
	return resp.Data.ID, nil
}
```

Then make `ensurePolicies` grant Bind to the routers for direct routes. Replace `ensurePolicies`:

```go
func (rec *ZitiReconciler) ensurePolicies(ctx context.Context, zm *ZitiManager, d DesiredRoute) error {
	svcRole := "#" + d.ServiceName
	bindIdentity := "#access-proxy-clients"
	dialIdentity := "#access-proxy-clients"
	if d.EffectiveMode() == HostingModeDirect {
		// The router hosts the service via host.v1, so Bind goes to the routers;
		// BrowZer clients (synced users) dial via #browzer-users.
		if err := zm.EnsureRouterRoleAttribute(ctx); err != nil {
			rec.logger.Debug("tag routers (may already be tagged)", zap.Error(err))
		}
		bindIdentity = "#ziti-routers"
		dialIdentity = "#browzer-users"
	}
	if _, err := zm.CreateServicePolicy(ctx, "openidx-bind-"+d.ServiceName, "Bind",
		[]string{svcRole}, []string{bindIdentity}); err != nil {
		rec.logger.Debug("bind policy (may already exist)", zap.String("svc", d.ServiceName), zap.Error(err))
	}
	if _, err := zm.CreateServicePolicy(ctx, "openidx-dial-"+d.ServiceName, "Dial",
		[]string{svcRole}, []string{dialIdentity}); err != nil {
		rec.logger.Debug("dial policy (may already exist)", zap.String("svc", d.ServiceName), zap.Error(err))
	}
	if err := zm.EnsureServiceEdgeRouterPolicy(ctx, "openidx-serp-"+d.ServiceName,
		[]string{svcRole}, []string{"#all"}); err != nil {
		rec.logger.Debug("serp (may already exist)", zap.String("svc", d.ServiceName), zap.Error(err))
	}
	return nil
}
```

- [ ] **Step 4: Run it, verify it passes**

Run: `go test ./internal/access/ -run 'TestEnsureHosting|TestReconcile|TestEnsureService' -v`
Expected: PASS (the new direct test plus the existing Phase 1 identity-mode tests — confirm none regressed).

- [ ] **Step 5: Commit**

```bash
git add internal/access/ziti_reconciler.go internal/access/ziti.go internal/access/ziti_reconciler_test.go
git commit -m "feat(ziti): reconciler direct mode — per-app host.v1 service + router Bind"
```

---

## Phase 2c — bootstrapper targets: per-app service + scheme

### Task 4: `GenerateBrowZerTargets` emits per-app service + scheme; router-config skips direct routes

**Files:**
- Modify: `internal/access/browzer_targets.go` (`queryBrowZerRoutes` to also select `hosting_mode`; `GenerateBrowZerTargets`; `GenerateBrowZerRouterConfig`)
- Test: `internal/access/browzer_targets_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `internal/access/browzer_targets_test.go`:

```go
package access

import "testing"

func TestBrowZerTargetUsesPerAppServiceAndScheme(t *testing.T) {
	routes := []browzerRouteInfo{
		{hostname: "psm.tdv.org", toURL: "https://192.168.152.112:443", serviceName: "psm-zt", hostingMode: "direct", pathPrefix: "/"},
		{hostname: "netgraph.tdv.org", toURL: "http://127.0.0.1:8088", serviceName: "openidx-Netgraph", hostingMode: "direct", pathPrefix: "/"},
	}
	got := buildBrowZerTargets(routes, "browzer.localtest.me", "https://openidx.tdv.org", "browzer-client")
	byVHost := map[string]BrowZerTarget{}
	for _, tt := range got {
		byVHost[tt.VHost] = tt
	}
	if byVHost["psm.tdv.org"].Service != "psm-zt" || byVHost["psm.tdv.org"].Scheme != "https" {
		t.Fatalf("psm target wrong: %+v", byVHost["psm.tdv.org"])
	}
	if byVHost["netgraph.tdv.org"].Service != "openidx-Netgraph" || byVHost["netgraph.tdv.org"].Scheme != "http" {
		t.Fatalf("netgraph target wrong: %+v", byVHost["netgraph.tdv.org"])
	}
}
```

> This requires extracting the pure target-assembly into a testable free function `buildBrowZerTargets(routes []browzerRouteInfo, domain, idpIssuer, idpClientID string) []BrowZerTarget`. `GenerateBrowZerTargets` becomes a thin wrapper that queries the DB then calls it.

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/access/ -run TestBrowZerTargetUsesPerAppServiceAndScheme -v`
Expected: FAIL — `buildBrowZerTargets undefined` and `browzerRouteInfo` has no `hostingMode` field.

- [ ] **Step 3: Implement**

1. Add `hostingMode string` to `browzerRouteInfo` (struct ~line 194) and select it: change the `queryBrowZerRoutes` SELECT to `SELECT from_url, to_url, ziti_service_name, COALESCE(landing_path,'/'), COALESCE(hosting_mode,'identity')` and scan into `landingPath, hostingMode`.

2. Extract `buildBrowZerTargets`:

```go
// buildBrowZerTargets maps each BrowZer route to a bootstrapper target. Each app
// uses its OWN Ziti service (per-app direct hosting) so the browser dials it
// directly — no shared Host-demux. Scheme comes from the route's to_url so the
// runtime's WASM TLS connects end-to-end for https upstreams.
func buildBrowZerTargets(routes []browzerRouteInfo, domain, idpIssuer, idpClientID string) []BrowZerTarget {
	targets := make([]BrowZerTarget, 0, len(routes))
	for _, r := range routes {
		scheme := "http"
		if parsed, err := url.Parse(r.toURL); err == nil && parsed.Scheme != "" {
			scheme = parsed.Scheme
		}
		targets = append(targets, BrowZerTarget{
			VHost:        r.hostname,
			Service:      r.serviceName,
			Path:         "/",
			Scheme:       scheme,
			IDPIssuerURL: idpIssuer,
			IDPClientID:  idpClientID,
		})
	}
	return targets
}
```

3. Rewrite `GenerateBrowZerTargets` to call it (keep the OIDC-settings query, then `return &BrowZerTargetArray{TargetArray: buildBrowZerTargets(routes, tm.GetDomain(), oidcIssuer, oidcClientID)}, nil`).

4. In `GenerateBrowZerRouterConfig`, skip `direct` routes so the retired shared demux no longer references them — at the top of the `for _, r := range routes` loop add:

```go
		if r.hostingMode == HostingModeDirect {
			continue // per-app direct route: hosted by the router via host.v1, not the shared browzer-router
		}
```

- [ ] **Step 4: Run it, verify it passes**

Run: `go test ./internal/access/ -run TestBrowZerTargetUsesPerAppServiceAndScheme -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/access/browzer_targets.go internal/access/browzer_targets_test.go
git commit -m "feat(browzer): per-app service + scheme in bootstrapper targets; skip direct routes in shared router config"
```

---

## Phase 2d — migrate netgraph (verify), then add psm

### Task 5: Migrate netgraph to per-app direct and verify it renders

**Files:** none (operational; runs against the live box with `ZITI_RECONCILER=true`).

- [ ] **Step 1: Build + enable the reconciler**

```bash
go build -o /tmp/oidx-access-service ./cmd/access-service/
grep -q 'ZITI_RECONCILER=' /tmp/run-access.sh || sed -i '/export BROWZER_HOST_LOOPBACK_ALIAS=/a export ZITI_RECONCILER=true' /tmp/run-access.sh
```

- [ ] **Step 2: Restart, let the reconciler converge netgraph to direct**

```bash
pkill -9 oidx-access; sleep 4; : > /tmp/oidx-logs/access.log
setsid bash /tmp/run-access.sh >/dev/null 2>&1 < /dev/null & disown
sleep 30
grep -iE "reconcile pass complete|host.v1|psm|Netgraph" /tmp/oidx-logs/access.log | tail
```

Expected: a `reconcile pass complete` log; `openidx-Netgraph` now has a host.v1 config + a Bind to `#ziti-routers` (verify with `ziti edge list configs` / `list service-policies`).

- [ ] **Step 3: Verify the netgraph terminator is now router-hosted (not SDK)**

```bash
podman exec oidx-ziti-controller ziti edge list terminators 'service.name="openidx-Netgraph"' -j
```
Expected: a terminator whose `binding` is `host.v1` (router-hosted), not `edge` (SDK).

- [ ] **Step 4: Browser verification (Playwright, host-resolver override)**

Reuse the harness from the session (`--host-resolver-rules='MAP *.tdv.org 127.0.0.1'`, login `admin`/`Admin@123`). Navigate to `https://netgraph.tdv.org/`. Expected: the netgraph SPA (`title "netgraph — topology"`) still renders clientlessly — now via its own per-app direct service.
If it does NOT render, STOP — do not proceed to psm. Capture console + `ziti edge list terminators` and debug the host.v1 path first.

- [ ] **Step 5: Commit the run-state note**

```bash
git add docs/superpowers/plans/2026-06-23-openidx-openziti-phase2-per-app-browzer.md
git commit -m "docs(ziti): mark Phase 2c netgraph direct-mode verification done"
```

### Task 6: Publish psm.tdv.org as a per-app direct BrowZer route

**Files:** none (operational, via the admin API/DB on the live box).

- [ ] **Step 1: Create the psm route (ziti + browzer enabled, https upstream)**

```bash
podman exec oidx-pg psql -U openidx -d openidx -c \
"INSERT INTO proxy_routes (id, name, description, from_url, to_url, require_auth, enabled, priority, ziti_enabled, ziti_service_name, browzer_enabled, hosting_mode, landing_path, org_id)
 SELECT gen_random_uuid(), 'PSM', 'PSM behind BrowZer', 'https://psm.tdv.org', 'https://192.168.152.112:443', true, true, 0, true, 'psm-zt', true, 'direct', '/', org_id
 FROM proxy_routes WHERE name='Netgraph';"
```

> Reuses Netgraph's `org_id`. `to_url` is the IP so the host.v1 fixed target is deterministic; the browser's WASM TLS sends SNI `psm.tdv.org` (the page origin), which the real cert serves.

- [ ] **Step 2: Trigger reconcile + bootstrapper-target regen**

```bash
curl -s -X POST http://127.0.0.1:8007/api/v1/access/ziti/browzer/restart >/dev/null 2>&1 || true
pkill -9 oidx-access; sleep 4; : > /tmp/oidx-logs/access.log
setsid bash /tmp/run-access.sh >/dev/null 2>&1 < /dev/null & disown
sleep 30
```

Expected: `psm-zt` service created with a host.v1 fixed config → `192.168.152.112:443`, Bind to `#ziti-routers`, Dial to `#browzer-users`; bootstrapper `config.json` has a `psm.tdv.org → psm-zt, scheme:https` target.

- [ ] **Step 3: nginx vhost for psm → bootstrapper (operator + reload)**

Add to `/tmp/oidx-tls/nginx.conf` a `server_name psm.tdv.org` block identical to the netgraph one (proxy to `https://127.0.0.1:8445`, `proxy_ssl_server_name on`, WSS upgrade headers), then `podman restart oidx-nginx` (the bind-mount inode caveat: restart, not reload).
**Operator action:** the browser machine's `/etc/hosts` must map `psm.tdv.org → 192.168.31.76` (overriding the real 192.168.152.112) for clientless access via this box.

- [ ] **Step 4: Verify psm AND netgraph both render clientlessly**

Playwright: load `https://psm.tdv.org/` (login) → expect PSM's UI (not netgraph, not the BrowZer landing). Then reload `https://netgraph.tdv.org/` → still the netgraph SPA. Both served via their own per-app direct services — no Host-demux collision.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/plans/2026-06-23-openidx-openziti-phase2-per-app-browzer.md
git commit -m "docs(ziti): Phase 2d — psm published via per-app direct BrowZer service, both apps verified"
```

---

## Final review task

After all tasks: dispatch a code reviewer over the diff. Confirm (1) identity-mode routes are untouched (Phase 1 tests green), (2) no DB write-back from the reconciler, (3) the shared `browzer-router-zt` is only retired for `direct` routes (a still-`identity` browzer route — if any — would break; verify none exist or document it), (4) `go build ./... && go vet ./... && gofmt -l` clean, (5) the host.v1 config bodies contain no `forward*` keys.

## Risks

- **host.v1 fixed-target schema:** the #1 failure mode. Assert (unit test) the config body has `{protocol,address,port}` and none of `forward*`/`allowed*`.
- **Router Bind:** routers must carry `#ziti-routers`; `EnsureRouterRoleAttribute` runs before the Bind policy. If a router enrolls later, the periodic reconcile re-tags it.
- **WASM TLS to https upstream unproven end-to-end** — Task 5 (netgraph, http) must render before Task 6 (psm, https). If https-over-host.v1 fails, the fallback is a per-app TLS-terminating nginx hop (a follow-up task, not this plan).
- **`browzer-router-zt` retirement:** only `direct` routes are removed from the shared config. Identity-mode routes (none today, since v47 backfilled all browzer routes to `direct`) would still need it.
- **Single-app default_server:** once netgraph is direct, the shared browzer-router has zero vhosts — the `#198` default_server is moot but harmless.
