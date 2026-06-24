# APISIX BrowZer edge — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make APISIX the single `:443` TLS edge and have the access-service push
BrowZer (and later all) routes to APISIX's Admin API, replacing the generated-nginx
edge — migrated in phases with nginx as a fallback upstream until each surface moves.

**Architecture:** APISIX (3.15.0, etcd-backed, adopted from the live
`apisix-docker2` stack) owns `:443`. A new **APISIX route reconciler** in the
access-service renders route objects from `proxy_routes` and `PUT`s them to the
Admin API (idempotent by name, deletes stale `browzer-*` routes). BrowZer apps get
native routes (overlay → bootstrapper with `pass_host: rewrite`+`upstream_host`
to set the upstream SNI — proven in the §3.1 spike — plus a higher-priority OIDC
`form_post` bypass route → the hop). Unmigrated hosts fall through a low-priority
catch-all to a demoted `oidx-nginx`. nginx ends as the SPA static upstream.

**Tech Stack:** Go 1.22 (access-service), Apache APISIX 3.15.0 + etcd, podman
(host-net), the existing `queryBrowZerRoutes` / `assignHopPorts` helpers, the
`platform_certs` APISIX-SSL writer, the `handleAuthDecide` forward-auth endpoint.

**Spec:** `docs/superpowers/specs/2026-06-24-apisix-browzer-edge-design.md`
(§3.1 SNI spike RESOLVED; §8 decisions resolved).

**Conventions for every code task:** `gofmt -w`, `go build ./...`, `go vet`, and
the package test pass before commit. Code tasks are TDD (test first → fail →
implement → pass → commit). Tasks 7–11 are operational/config + live verification,
not TDD; each ends with a verification step and a documented rollback.

---

## Phase 1 code — the APISIX route reconciler

### Task 1: APISIX route object builder (pure)

**Files:**
- Create: `internal/access/apisix_routes.go`
- Test: `internal/access/apisix_routes_test.go`

- [ ] **Step 1: Write the failing test**

```go
package access

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildBrowZerAPISIXRoutes(t *testing.T) {
	routes := []browzerRouteInfo{
		{hostname: "psm.tdv.org", serviceName: "psm-zt", hostingMode: "hop"},
		{hostname: "netgraph.tdv.org", serviceName: "openidx-Netgraph", hostingMode: "direct"},
	}
	opts := apisixRouteOpts{
		bootstrapperNode: "127.0.0.1:8445",
		hopBasePort:      8095,
		oidcCallbacks:    []string{"signin-oidc", "signout-callback-oidc"},
	}
	got := buildBrowZerAPISIXRoutes(routes, opts)
	byName := map[string]map[string]interface{}{}
	names := []string{}
	for _, r := range got {
		var m map[string]interface{}
		if err := json.Unmarshal(r.Body, &m); err != nil {
			t.Fatalf("route %s body is not valid JSON: %v", r.Name, err)
		}
		byName[r.Name] = m
		names = append(names, r.Name)
	}

	// psm (hop): overlay route + OIDC bypass route. netgraph (direct): overlay only.
	for _, want := range []string{"browzer-psm-tdv-org", "browzer-psm-tdv-org-oidc", "browzer-netgraph-tdv-org"} {
		if byName[want] == nil {
			t.Fatalf("missing route %s; got %v", want, names)
		}
	}
	if byName["browzer-netgraph-tdv-org-oidc"] != nil {
		t.Fatal("direct-mode route must NOT get an OIDC bypass route")
	}

	// Overlay route: host match, bootstrapper upstream, SNI via pass_host=rewrite+upstream_host, WSS.
	ov := byName["browzer-psm-tdv-org"]
	up := ov["upstream"].(map[string]interface{})
	if hosts := ov["hosts"].([]interface{}); hosts[0] != "psm.tdv.org" {
		t.Fatalf("overlay host wrong: %v", hosts)
	}
	if up["scheme"] != "https" || up["pass_host"] != "rewrite" || up["upstream_host"] != "psm.tdv.org" {
		t.Fatalf("overlay upstream must set SNI via pass_host=rewrite+upstream_host: %v", up)
	}
	if _, ok := up["nodes"].(map[string]interface{})["127.0.0.1:8445"]; !ok {
		t.Fatalf("overlay must target the bootstrapper node: %v", up["nodes"])
	}
	if ov["enable_websocket"] != true {
		t.Fatal("overlay route must enable websocket")
	}

	// OIDC route: higher priority, suffix-regex vars, hop-port upstream (psm-zt sole hop -> 8095).
	oidc := byName["browzer-psm-tdv-org-oidc"]
	if oidc["priority"].(float64) <= ov["priority"].(float64) {
		t.Fatal("OIDC route must outrank the overlay route")
	}
	varsJSON, _ := json.Marshal(oidc["vars"])
	if !strings.Contains(string(varsJSON), "signin-oidc|signout-callback-oidc") {
		t.Fatalf("OIDC route must match the callback suffixes: %s", varsJSON)
	}
	oup := oidc["upstream"].(map[string]interface{})
	if _, ok := oup["nodes"].(map[string]interface{})["127.0.0.1:8095"]; !ok {
		t.Fatalf("OIDC route must target the hop port 8095: %v", oup["nodes"])
	}
}

func TestBuildBrowZerAPISIXRoutesSkipsEmptyHost(t *testing.T) {
	got := buildBrowZerAPISIXRoutes(
		[]browzerRouteInfo{{hostname: "", serviceName: "x", hostingMode: "hop"}},
		apisixRouteOpts{bootstrapperNode: "127.0.0.1:8445", hopBasePort: 8095})
	if len(got) != 0 {
		t.Fatalf("a route with no hostname must be skipped: %v", got)
	}
}

func TestAPISIXSlug(t *testing.T) {
	if got := apisixSlug("psm.tdv.org"); got != "psm-tdv-org" {
		t.Fatalf("apisixSlug: got %q", got)
	}
}
```

- [ ] **Step 2: Run it — expect compile failure** (`undefined: buildBrowZerAPISIXRoutes`).
  Run: `go test ./internal/access/ -run TestBuildBrowZerAPISIXRoutes`

- [ ] **Step 3: Implement**

```go
package access

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// apisixRouteOpts carries the static inputs for the generated BrowZer routes.
type apisixRouteOpts struct {
	bootstrapperNode string   // e.g. "127.0.0.1:8445"
	hopBasePort      int      // base for assignHopPorts
	oidcCallbacks    []string // form_post callback suffixes (hop-mode only)
}

// apisixRoute is a single Admin API route object: PUT .../routes/<Name> with Body.
type apisixRoute struct {
	Name string
	Body []byte
}

var apisixSlugNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// apisixSlug turns a hostname into a stable, name-safe route slug.
func apisixSlug(host string) string {
	s := apisixSlugNonAlnum.ReplaceAllString(strings.ToLower(host), "-")
	return strings.Trim(s, "-")
}

// buildBrowZerAPISIXRoutes renders the Admin API route objects for the
// BrowZer-enabled routes: an overlay route → bootstrapper for each, plus an OIDC
// form_post bypass route → the hop for hop-mode routes. The overlay upstream sets
// the TLS SNI to the app vhost via pass_host=rewrite + upstream_host (the §3.1
// spike proved upstream.tls.sni is a no-op on 3.15.0).
func buildBrowZerAPISIXRoutes(routes []browzerRouteInfo, opts apisixRouteOpts) []apisixRoute {
	if opts.bootstrapperNode == "" {
		opts.bootstrapperNode = "127.0.0.1:8445"
	}
	var hopNames []string
	for _, r := range routes {
		if r.hostingMode == HostingModeHop {
			hopNames = append(hopNames, r.serviceName)
		}
	}
	ports := assignHopPorts(hopNames, opts.hopBasePort)

	var out []apisixRoute
	for _, r := range routes {
		if r.hostname == "" {
			continue
		}
		slug := apisixSlug(r.hostname)

		overlay := map[string]interface{}{
			"name":             "browzer-" + slug,
			"hosts":            []string{r.hostname},
			"uri":              "/*",
			"priority":         0,
			"enable_websocket": true,
			"upstream": map[string]interface{}{
				"type":          "roundrobin",
				"scheme":        "https",
				"pass_host":     "rewrite",
				"upstream_host": r.hostname,
				"nodes":         map[string]interface{}{opts.bootstrapperNode: 1},
				"tls":           map[string]interface{}{"verify": false},
				"timeout":       map[string]interface{}{"connect": 60, "send": 86400, "read": 86400},
			},
		}
		body, _ := json.Marshal(overlay)
		out = append(out, apisixRoute{Name: "browzer-" + slug, Body: body})

		if r.hostingMode == HostingModeHop && len(opts.oidcCallbacks) > 0 {
			suffix := strings.Join(opts.oidcCallbacks, "|")
			oidc := map[string]interface{}{
				"name":     "browzer-" + slug + "-oidc",
				"hosts":    []string{r.hostname},
				"uri":      "/*",
				"vars":     [][]interface{}{{"uri", "~~", fmt.Sprintf("/(%s)$", suffix)}},
				"priority": 10,
				"upstream": map[string]interface{}{
					"type":          "roundrobin",
					"scheme":        "http",
					"pass_host":     "rewrite",
					"upstream_host": r.hostname,
					"nodes":         map[string]interface{}{fmt.Sprintf("127.0.0.1:%d", ports[r.serviceName]): 1},
				},
			}
			body, _ := json.Marshal(oidc)
			out = append(out, apisixRoute{Name: "browzer-" + slug + "-oidc", Body: body})
		}
	}
	return out
}
```

- [ ] **Step 4: Run — expect PASS.** `go test ./internal/access/ -run 'TestBuildBrowZerAPISIXRoutes|TestAPISIXSlug'`
- [ ] **Step 5: Commit** — `git add internal/access/apisix_routes*.go && git commit -m "feat(apisix): BrowZer route object builder"`

---

### Task 2: APISIX Admin API client

**Files:**
- Create: `internal/access/apisix_client.go`
- Test: `internal/access/apisix_client_test.go`

- [ ] **Step 1: Write the failing test** (uses `httptest`, no live APISIX)

```go
package access

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPISIXClientPutListDelete(t *testing.T) {
	var gotKey, gotMethod, gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotMethod, gotPath = r.Header.Get("X-API-KEY"), r.Method, r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		if r.Method == http.MethodGet {
			w.Write([]byte(`{"list":[{"value":{"id":"browzer-a"}},{"value":{"id":"other"}}]}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := NewAPISIXClient(srv.URL, "secret")
	if err := c.PutRoute(context.Background(), "browzer-a", []byte(`{"uri":"/*"}`)); err != nil {
		t.Fatalf("PutRoute: %v", err)
	}
	if gotKey != "secret" || gotMethod != "PUT" || !strings.HasSuffix(gotPath, "/apisix/admin/routes/browzer-a") || gotBody != `{"uri":"/*"}` {
		t.Fatalf("PUT wrong: key=%s method=%s path=%s body=%s", gotKey, gotMethod, gotPath, gotBody)
	}
	names, err := c.ListRouteNames(context.Background())
	if err != nil {
		t.Fatalf("ListRouteNames: %v", err)
	}
	if len(names) != 2 || names[0] != "browzer-a" {
		t.Fatalf("ListRouteNames got %v", names)
	}
	if err := c.DeleteRoute(context.Background(), "browzer-a"); err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}
	if gotMethod != "DELETE" {
		t.Fatalf("expected DELETE, got %s", gotMethod)
	}
}
```

- [ ] **Step 2: Run — expect compile failure.** `go test ./internal/access/ -run TestAPISIXClient`
- [ ] **Step 3: Implement**

```go
package access

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// APISIXClient is a thin Admin API client for managing routes.
type APISIXClient struct {
	adminURL string
	adminKey string
	http     *http.Client
}

func NewAPISIXClient(adminURL, adminKey string) *APISIXClient {
	return &APISIXClient{adminURL: adminURL, adminKey: adminKey, http: &http.Client{Timeout: 10 * time.Second}}
}

func (c *APISIXClient) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var r *bytes.Reader
	if body != nil {
		r = bytes.NewReader(body)
	} else {
		r = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.adminURL+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", c.adminKey)
	req.Header.Set("Content-Type", "application/json")
	return c.http.Do(req)
}

// PutRoute upserts a route by name (Admin API PUT is idempotent).
func (c *APISIXClient) PutRoute(ctx context.Context, name string, body []byte) error {
	resp, err := c.do(ctx, http.MethodPut, "/apisix/admin/routes/"+name, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("PUT route %s: status %d", name, resp.StatusCode)
	}
	return nil
}

// DeleteRoute removes a route by name (404 tolerated as already-gone).
func (c *APISIXClient) DeleteRoute(ctx context.Context, name string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/apisix/admin/routes/"+name, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("DELETE route %s: status %d", name, resp.StatusCode)
	}
	return nil
}

// ListRouteNames returns the ids of all configured routes.
func (c *APISIXClient) ListRouteNames(ctx context.Context) ([]string, error) {
	resp, err := c.do(ctx, http.MethodGet, "/apisix/admin/routes", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("LIST routes: status %d", resp.StatusCode)
	}
	var parsed struct {
		List []struct {
			Value struct {
				ID string `json:"id"`
			} `json:"value"`
		} `json:"list"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(parsed.List))
	for _, it := range parsed.List {
		names = append(names, it.Value.ID)
	}
	return names, nil
}
```

- [ ] **Step 4: Run — expect PASS.** `go test ./internal/access/ -run TestAPISIXClient`
- [ ] **Step 5: Commit** — `feat(apisix): Admin API route client`

---

### Task 3: stale-route diff helper (pure)

**Files:**
- Modify: `internal/access/apisix_routes.go`
- Test: `internal/access/apisix_routes_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestStaleBrowZerRouteNames(t *testing.T) {
	existing := []string{"browzer-a", "browzer-b", "browzer-b-oidc", "identity-service", "other"}
	desired := []string{"browzer-a"}
	stale := staleBrowZerRouteNames(existing, desired)
	// Only browzer-* routes not in desired are stale; non-browzer routes are left alone.
	want := map[string]bool{"browzer-b": true, "browzer-b-oidc": true}
	if len(stale) != 2 {
		t.Fatalf("got %v", stale)
	}
	for _, s := range stale {
		if !want[s] {
			t.Fatalf("unexpected stale name %s (got %v)", s, stale)
		}
	}
}
```

- [ ] **Step 2: Run — expect fail.**
- [ ] **Step 3: Implement** (append to `apisix_routes.go`)

```go
// staleBrowZerRouteNames returns the browzer-* routes that exist but are no longer
// desired (so they should be deleted). Non-browzer routes are never touched.
func staleBrowZerRouteNames(existing, desired []string) []string {
	want := make(map[string]bool, len(desired))
	for _, d := range desired {
		want[d] = true
	}
	var stale []string
	for _, e := range existing {
		if strings.HasPrefix(e, "browzer-") && !want[e] {
			stale = append(stale, e)
		}
	}
	return stale
}
```

- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit** — `feat(apisix): stale browzer-route diff helper`

---

### Task 4: APISIX route reconciler

**Files:**
- Create: `internal/access/apisix_reconciler.go`
- Test: `internal/access/apisix_reconciler_test.go`

- [ ] **Step 1: Write the failing test** — drive the apply/prune logic through a
  fake client + an injected desired-route list (no DB).

```go
package access

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

type fakeAPISIX struct {
	put      map[string][]byte
	deleted  []string
	existing []string
}

func (f *fakeAPISIX) PutRoute(_ context.Context, name string, body []byte) error {
	if f.put == nil {
		f.put = map[string][]byte{}
	}
	f.put[name] = body
	return nil
}
func (f *fakeAPISIX) DeleteRoute(_ context.Context, name string) error {
	f.deleted = append(f.deleted, name)
	return nil
}
func (f *fakeAPISIX) ListRouteNames(_ context.Context) ([]string, error) { return f.existing, nil }

func TestAPISIXReconcilerApplyAndPrune(t *testing.T) {
	f := &fakeAPISIX{existing: []string{"browzer-old", "identity-service"}}
	rec := &APISIXReconciler{
		logger: zap.NewNop(),
		client: f,
		opts:   apisixRouteOpts{bootstrapperNode: "127.0.0.1:8445", hopBasePort: 8095, oidcCallbacks: []string{"signin-oidc"}},
	}
	desired := []browzerRouteInfo{{hostname: "psm.tdv.org", serviceName: "psm-zt", hostingMode: "hop"}}
	if err := rec.applyRoutes(context.Background(), desired); err != nil {
		t.Fatalf("applyRoutes: %v", err)
	}
	if _, ok := f.put["browzer-psm-tdv-org"]; !ok {
		t.Fatalf("overlay route not PUT: %v keys", f.put)
	}
	if _, ok := f.put["browzer-psm-tdv-org-oidc"]; !ok {
		t.Fatal("oidc route not PUT")
	}
	// browzer-old is gone from desired → deleted; identity-service is left alone.
	if len(f.deleted) != 1 || f.deleted[0] != "browzer-old" {
		t.Fatalf("prune wrong: %v", f.deleted)
	}
}
```

- [ ] **Step 2: Run — expect compile failure.**
- [ ] **Step 3: Implement** — the reconciler holds an interface (so the test fakes
  it), builds + PUTs desired routes, lists existing, deletes stale.

```go
package access

import (
	"context"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// apisixAdmin is the subset of the Admin client the reconciler needs (fakeable).
type apisixAdmin interface {
	PutRoute(ctx context.Context, name string, body []byte) error
	DeleteRoute(ctx context.Context, name string) error
	ListRouteNames(ctx context.Context) ([]string, error)
}

// APISIXReconciler converges APISIX routes to the BrowZer-enabled proxy_routes.
// Replaces the nginx public-vhost generator when APISIX owns the edge.
type APISIXReconciler struct {
	db     *database.PostgresDB
	logger *zap.Logger
	client apisixAdmin
	tm     *BrowZerTargetManager // for queryBrowZerRoutes
	opts   apisixRouteOpts
}

func NewAPISIXReconciler(db *database.PostgresDB, log *zap.Logger, client apisixAdmin, tm *BrowZerTargetManager, opts apisixRouteOpts) *APISIXReconciler {
	return &APISIXReconciler{db: db, logger: log.With(zap.String("component", "apisix-reconciler")), client: client, tm: tm, opts: opts}
}

// Reconcile loads the desired BrowZer routes and converges APISIX.
func (rec *APISIXReconciler) Reconcile(ctx context.Context) error {
	ctx = orgctx.WithBypassRLS(ctx)
	desired, err := rec.tm.queryBrowZerRoutes(ctx)
	if err != nil {
		return err
	}
	return rec.applyRoutes(ctx, desired)
}

// applyRoutes PUTs the desired routes and prunes stale browzer-* routes.
func (rec *APISIXReconciler) applyRoutes(ctx context.Context, desired []browzerRouteInfo) error {
	objs := buildBrowZerAPISIXRoutes(desired, rec.opts)
	desiredNames := make([]string, 0, len(objs))
	for _, o := range objs {
		if err := rec.client.PutRoute(ctx, o.Name, o.Body); err != nil {
			rec.logger.Warn("PUT route failed", zap.String("name", o.Name), zap.Error(err))
			continue
		}
		desiredNames = append(desiredNames, o.Name)
	}
	existing, err := rec.client.ListRouteNames(ctx)
	if err != nil {
		return err
	}
	for _, name := range staleBrowZerRouteNames(existing, desiredNames) {
		if err := rec.client.DeleteRoute(ctx, name); err != nil {
			rec.logger.Warn("DELETE stale route failed", zap.String("name", name), zap.Error(err))
		}
	}
	return nil
}
```

- [ ] **Step 4: Run — expect PASS.** `go test ./internal/access/ -run TestAPISIXReconciler`
- [ ] **Step 5: Commit** — `feat(apisix): BrowZer route reconciler`

---

### Task 5: config plumbing

**Files:**
- Modify: `internal/common/config/config.go` (struct fields + `setDefaults` + `bindEnvVars`)

- [ ] **Step 1:** Add fields (mirror the existing BrowZer block):

```go
	// APISIX edge (opt-in). When APISIXEdgeEnabled, the access-service pushes
	// BrowZer routes to APISIX's Admin API instead of generating nginx vhosts.
	APISIXEdgeEnabled    bool   `mapstructure:"apisix_edge_enabled"`
	APISIXAdminURL       string `mapstructure:"apisix_admin_url"`
	APISIXAdminKey       string `mapstructure:"apisix_admin_key"`
	APISIXBootstrapperNode string `mapstructure:"apisix_bootstrapper_node"`
```

- [ ] **Step 2:** Defaults:

```go
	v.SetDefault("apisix_edge_enabled", false)
	v.SetDefault("apisix_admin_url", "http://127.0.0.1:9180")
	v.SetDefault("apisix_bootstrapper_node", "127.0.0.1:8445")
```

- [ ] **Step 3:** Env bindings:

```go
	"apisix_edge_enabled":      "APISIX_EDGE_ENABLED",
	"apisix_admin_url":         "APISIX_ADMIN_URL",
	"apisix_admin_key":         "APISIX_ADMIN_KEY",
	"apisix_bootstrapper_node": "APISIX_BOOTSTRAPPER_NODE",
```

- [ ] **Step 4:** `go build ./... && go vet ./internal/common/config/`
- [ ] **Step 5: Commit** — `feat(config): APISIX edge knobs`

---

### Task 6: wire the reconciler in main.go (behind the flag)

**Files:**
- Modify: `cmd/access-service/main.go`
- Modify: `internal/access/browzer_targets.go` (`RegenerateConfigs` triggers the APISIX reconciler when set)

- [ ] **Step 1:** In `main.go`, after `browzerTargetManager` is built and Ziti is
  up, construct the client + reconciler when `cfg.APISIXEdgeEnabled` and run an
  initial reconcile + register it on the target manager so toggles re-converge:

```go
	if cfg.APISIXEdgeEnabled && browzerTargetManager != nil {
		apisixClient := access.NewAPISIXClient(cfg.APISIXAdminURL, cfg.APISIXAdminKey)
		_, hopPort := access.ParseHopAddr(cfg.ZitiBrowZerHopAddr)
		apisixRec := access.NewAPISIXReconciler(db, log, apisixClient, browzerTargetManager,
			access.APISIXRouteOpts(cfg.APISIXBootstrapperNode, hopPort, access.SplitCSV(cfg.BrowZerOIDCCallbackPaths)))
		browzerTargetManager.SetAPISIXReconciler(apisixRec)
		go func() {
			if err := apisixRec.Reconcile(bgCtx); err != nil {
				log.Warn("initial APISIX reconcile failed", zap.Error(err))
			} else {
				log.Info("APISIX edge routes reconciled")
			}
		}()
	}
```

  (Add a small exported `access.APISIXRouteOpts(node string, hopBase int, cb []string) apisixRouteOpts`
  constructor since `apisixRouteOpts` is unexported, plus `SetAPISIXReconciler` +
  an `apisixReconciler` field on `BrowZerTargetManager`.)

- [ ] **Step 2:** In `RegenerateConfigs` (browzer_targets.go), after the existing
  writes, trigger the APISIX reconcile if registered (it owns the public edge
  when APISIX is on; the nginx vhost write becomes a no-op when its path is unset):

```go
	if rec := tm.apisixReconciler; rec != nil {
		if err := rec.Reconcile(ctx); err != nil {
			tm.logger.Warn("APISIX reconcile failed", zap.Error(err))
		}
	}
```

- [ ] **Step 3:** `gofmt -w`, `go build ./...`, `go vet`, `go test ./internal/access/ ./internal/common/config/`
- [ ] **Step 4: Commit** — `feat(apisix): wire route reconciler into access-service (flag-gated)`

---

## Phase 0 (ops): APISIX takes `:443`, nginx → fallback

**Files:** `deployments/docker/apisix/config.yaml` (repo-managed copy), the live
APISIX config, `oidx-nginx` run, a backup of `nginx.conf`.

- [ ] Back up: `cp /tmp/oidx-tls/nginx.conf /tmp/oidx-tls/nginx.conf.pre-apisix`.
- [ ] Add the `*.tdv.org` wildcard cert as an APISIX `ssl` object via the Admin API
  (`PUT /apisix/admin/ssls/tdv-wildcard` with cert/key + `snis: ["*.tdv.org","tdv.org"]`).
- [ ] Reconfigure APISIX to listen on `:443` (add to `apisix.ssl.listen`), keeping
  `:9443`/`:9080`/`:9180`. Reload APISIX.
- [ ] Demote `oidx-nginx`: change its `:443` server blocks to `listen 8443 ssl;`
  (internal) and recreate the container (it no longer owns `:443`).
- [ ] Add the **catch-all fallback** route to APISIX (Admin API):
  `{"uri":"/*","name":"edge-fallback-nginx","priority":-100,"enable_websocket":true,
    "upstream":{"type":"roundrobin","scheme":"https","pass_host":"pass",
    "nodes":{"127.0.0.1:8443":1},"tls":{"verify":false},
    "timeout":{"send":86400,"read":86400}}}`.
- [ ] **Verify** every host through APISIX `:443`: `openidx`, `netgraph`, `psm`,
  `browzer`, `ctrl`, a `*.tdv.org` access-proxy host, and the psm OIDC POST — all
  must match pre-cutover status codes.
- [ ] **Rollback:** restore `nginx.conf.pre-apisix`, give `:443` back to nginx
  (recreate), remove the APISIX `:443` listener.

---

## Phase 1 (ops): BrowZer routes native in APISIX

- [ ] Set `APISIX_EDGE_ENABLED=true`, `APISIX_ADMIN_KEY=add1c9f0…` in
  `/tmp/run-access.sh`; rebuild + restart the access-service.
- [ ] Confirm the reconciler created `browzer-netgraph-tdv-org` and
  `browzer-psm-tdv-org` (+ `-oidc`) via `GET /apisix/admin/routes`.
- [ ] **Verify** (these now win over the catch-all by host match): netgraph + psm
  render clientlessly through APISIX; the psm Entra `form_post` login completes
  (302 to the app, not bootstrapper 403); WSS overlay works.
- [ ] Toggle a BrowZer route off/on in the admin console → confirm the reconciler
  removes/recreates its APISIX routes.
- [ ] Once stable, set `BROWZER_VHOST_CONFIG_PATH=` (empty) so the nginx vhost
  generator no-ops (it is now superseded by APISIX). Keep the file/entrypoint in
  the tree for rollback.
- [ ] **Rollback:** `APISIX_EDGE_ENABLED=false` + restore `BROWZER_VHOST_CONFIG_PATH`;
  the catch-all serves netgraph/psm via nginx again.

---

## Phase 2 (ops): admin SPA + API fan-out

- [ ] Add APISIX routes for `openidx.tdv.org` API prefixes
  (`/api/v1/identity|governance|provisioning|audit|access`, `/api/`, `/oauth/`,
  `/.well-known/`, `/scim/`) → their `:800x` upstreams — adapt the existing
  `deployments/docker/apisix/apisix.yaml` route bodies.
- [ ] Add the SPA route: `host=openidx.tdv.org`, `uri:/*`, low priority →
  `oidx-nginx:8443` (which still does `try_files … /index.html`).
- [ ] **Verify** the admin console loads + every API tab works through APISIX;
  remove `openidx.tdv.org` reliance on the catch-all.

---

## Phase 3 (ops): OAuth, ctrl, browzer, and the access-proxy wildcard

- [ ] Add routes: `browzer.tdv.org`→bootstrapper, `ctrl.tdv.org`→controller
  `:1280` (tls verify off).
- [ ] Add the `*.tdv.org` access-proxy route → access-proxy `:8007` with the
  **`forward-auth`** plugin pointing at the access-service `handleAuthDecide`
  (`request_headers: ["Authorization","Cookie"]`, `upstream_headers:
  ["X-Forwarded-Route"]`, forwarding `X-Forwarded-Host/Uri/Method`).
- [ ] **Verify** an edge-gated app: unauthenticated → 403/redirect, authenticated
  → allowed; OAuth login round-trip works; ctrl edge API reachable by the SDK.

---

## Phase 4 (ops): reduce nginx to the SPA upstream

- [ ] Remove the broad `edge-fallback-nginx` catch-all (all proxy hosts now have
  native routes).
- [ ] Trim `oidx-nginx` (`:8443`) to only the SPA static `server` block for
  `openidx.tdv.org`.
- [ ] **Verify** the full surface one more time; **update**
  `docs/browzer-public-vhost-generator.md` + `CHANGELOG.md` to note the edge now
  runs on APISIX (nginx = SPA static upstream only).

---

## Final review

- [ ] Dispatch a code reviewer over the whole change (reconciler correctness,
  prune-only-`browzer-*` safety, flag gating, no regression when
  `APISIX_EDGE_ENABLED=false`).
- [ ] `superpowers:finishing-a-development-branch`.

## Notes / risks
- The reconciler **only ever deletes `browzer-*` routes** — it must never prune the
  API/SPA/access-proxy routes (Task 3 enforces this; keep it that way).
- etcd is now load-bearing for the edge; production etcd quorum + backups are a
  tracked follow-up (spec §8.5), not in this plan.
- Phases 0–4 are sequenced; each keeps the catch-all as the safety net for
  un-migrated hosts and has an explicit rollback.
