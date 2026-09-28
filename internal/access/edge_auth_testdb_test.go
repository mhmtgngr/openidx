package access

import (
	"context"
	"encoding/json"
	"sort"
	"testing"

	"go.uber.org/zap"
)

// A POOL-BACKED ROUTE THAT REQUIRES SIGN-IN IS NOT PUBLIC AT THE EDGE.
//
// APISIX serves a pool-backed route straight from the pool, not through the
// access proxy, so the edge is the only place its sign-in can be enforced.
// BuildEdgeRoutesForPools rendered host -> pool with no plugin at all: linking
// a pool to a route made it public, whatever its require_auth, roles, groups,
// device trust or assignments said.
//
// The reconciler is built as cmd/access-service builds it, over a migrated
// database, and what it PUTs to a fake Admin API is read back: with a
// forward-auth endpoint configured, and without one.

type renderedEdge struct {
	Name     string   `json:"name"`
	Hosts    []string `json:"hosts"`
	URI      string   `json:"uri"`
	Priority int      `json:"priority"`
	Plugins  struct {
		ForwardAuth *struct {
			URI             string   `json:"uri"`
			RequestHeaders  []string `json:"request_headers"`
			UpstreamHeaders []string `json:"upstream_headers"`
			ClientHeaders   []string `json:"client_headers"`
		} `json:"forward-auth"`
		ProxyRewrite *struct {
			Headers struct {
				Remove []string `json:"remove"`
			} `json:"headers"`
		} `json:"proxy-rewrite"`
	} `json:"plugins"`
	Upstream struct {
		Scheme   string         `json:"scheme"`
		PassHost string         `json:"pass_host"`
		Nodes    map[string]int `json:"nodes"`
	} `json:"upstream"`
}

func TestAPoolBackedRouteThatRequiresSignInIsNotPublicAtTheEdge(t *testing.T) {
	f := newAdminGateFixture(t)
	var pool string
	if err := f.db.Pool.QueryRow(f.ctx, `
		INSERT INTO upstream_pools (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`, f.orgA, "web-"+f.suffix).Scan(&pool); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"10.0.0.1", "10.0.0.2"} {
		if _, err := f.db.Pool.Exec(f.ctx, `
			INSERT INTO upstream_pool_members (pool_id, org_id, host, port) VALUES ($1::uuid, $2::uuid, $3, 8080)`, pool, f.orgA, m); err != nil {
			t.Fatal(err)
		}
	}
	route := func(name string, requireAuth bool) (id, host string) {
		t.Helper()
		host = name + "-" + f.suffix + ".example.test"
		if err := f.db.Pool.QueryRow(f.ctx, `
			INSERT INTO proxy_routes (org_id, name, from_url, to_url, require_auth, allowed_roles, priority, upstream_pool_id)
			VALUES ($1::uuid, $2, $3, 'http://10.0.0.9:8080', $4, '["finance"]', 7, $5::uuid) RETURNING id::text`,
			f.orgA, name+"-"+f.suffix, "https://"+host, requireAuth, pool).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		return id, host
	}
	privateID, privateHost := route("payroll", true)
	publicID, publicHost := route("status", false)

	reconcile := func(forwardAuthURI string, existing ...string) *fakeAPISIX {
		t.Helper()
		api := &fakeAPISIX{existing: existing}
		rec := NewAPISIXReconciler(f.db, zap.NewNop(), api, NewBrowZerTargetManager(f.db, zap.NewNop(), ""),
			APISIXRouteOpts("127.0.0.1:8445", 8095, nil, forwardAuthURI))
		if err := rec.Reconcile(context.Background()); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		return api
	}
	decode := func(api *fakeAPISIX, name string) *renderedEdge {
		t.Helper()
		body, ok := api.put[name]
		if !ok {
			return nil
		}
		var r renderedEdge
		if err := json.Unmarshal(body, &r); err != nil {
			t.Fatal(err)
		}
		return &r
	}
	stripsEveryIdentityHeader := func(what string, r *renderedEdge) {
		t.Helper()
		if r.Plugins.ProxyRewrite == nil {
			t.Errorf("%s removes no header from the caller's request", what)
			return
		}
		got := map[string]bool{}
		for _, h := range r.Plugins.ProxyRewrite.Headers.Remove {
			got[h] = true
		}
		for _, h := range namedIdentityHeaders() {
			if !got[h] {
				t.Errorf("%s passes the caller's %s to the pool", what, h)
			}
		}
	}

	// With the access service's decide endpoint configured.
	const decide = "http://access-service:8007/api/v1/access/auth/decide"
	api := reconcile(decide)
	private := decode(api, "oidx-route-"+privateID)
	if private == nil {
		t.Fatalf("the route that requires sign-in was not rendered; PUT %v", keys(api.put))
	}
	fa := private.Plugins.ForwardAuth
	if fa == nil || fa.URI != decide {
		t.Fatalf("the route that requires sign-in reaches its pool without forward-auth: %+v", private.Plugins)
	}
	for _, h := range []string{"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Roles", "X-Forwarded-Route", "Cookie", "Authorization"} {
		if !contains(fa.UpstreamHeaders, h) {
			t.Errorf("forward-auth does not replace the caller's %s with decide's answer: %v", h, fa.UpstreamHeaders)
		}
	}
	if !contains(fa.RequestHeaders, "Cookie") || !contains(fa.RequestHeaders, "Authorization") {
		t.Errorf("forward-auth does not send decide the credentials: %v", fa.RequestHeaders)
	}
	if !contains(fa.ClientHeaders, "Location") || !contains(fa.ClientHeaders, "Set-Cookie") {
		t.Errorf("a browser sent to sign in does not get decide's redirect: %v", fa.ClientHeaders)
	}
	if len(private.Hosts) != 1 || private.Hosts[0] != privateHost || len(private.Upstream.Nodes) != 2 {
		t.Errorf("the protected route is %v -> %v, want its host -> both pool members", private.Hosts, private.Upstream.Nodes)
	}
	stripsEveryIdentityHeader("the protected route", private)
	flow := decode(api, "oidx-route-"+privateID+"-auth")
	if flow == nil {
		t.Fatalf("no route takes the sign-in flow on the protected host; decide's redirect would loop; PUT %v", keys(api.put))
	}
	if flow.URI != "/access/.auth/*" || len(flow.Hosts) != 1 || flow.Hosts[0] != privateHost ||
		flow.Upstream.Nodes["access-service:8007"] != 1 || flow.Upstream.PassHost != "pass" || flow.Priority <= private.Priority {
		t.Errorf("the sign-in flow route is %+v, want /access/.auth/* on the host to the access service, ahead of the app", flow)
	}
	if flow.Plugins.ForwardAuth != nil {
		t.Error("the sign-in flow itself is behind forward-auth, so a browser can never sign in")
	}
	public := decode(api, "oidx-route-"+publicID)
	if public == nil {
		t.Fatalf("the public route was not rendered; PUT %v", keys(api.put))
	}
	if public.Plugins.ForwardAuth != nil || decode(api, "oidx-route-"+publicID+"-auth") != nil {
		t.Error("a route that needs no sign-in was put behind forward-auth")
	}
	if len(public.Hosts) != 1 || public.Hosts[0] != publicHost {
		t.Errorf("the public route is on %v", public.Hosts)
	}
	stripsEveryIdentityHeader("the public route", public)

	// Without one, the protected route is not rendered, and the object a
	// previous pass left at the edge is pruned; the public route stays.
	api = reconcile("", "oidx-route-"+privateID, "oidx-route-"+privateID+"-auth", "oidx-route-"+publicID)
	if decode(api, "oidx-route-"+privateID) != nil {
		t.Error("with no forward-auth endpoint the route that requires sign-in was rendered anyway")
	}
	sort.Strings(api.deleted)
	if len(api.deleted) != 2 || api.deleted[0] != "oidx-route-"+privateID || api.deleted[1] != "oidx-route-"+privateID+"-auth" {
		t.Errorf("pruned %v, want the protected route's two objects", api.deleted)
	}
	if decode(api, "oidx-route-"+publicID) == nil {
		t.Error("the public route was dropped with the protected one")
	}
	// An endpoint that is not an http(s) URL is no endpoint.
	api = reconcile("access-service:8007/decide")
	if decode(api, "oidx-route-"+privateID) != nil {
		t.Error("a forward-auth endpoint that is not a URL rendered the protected route")
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The named list generated configuration removes is the proxy's own list:
// every name in it is one the proxy strips, and it names every exact header
// the proxy strips.
func TestTheNamedIdentityHeadersAreTheOnesTheProxyStrips(t *testing.T) {
	names := namedIdentityHeaders()
	for _, h := range names {
		if !isProxyIdentityHeader(h) {
			t.Errorf("%s is removed at the edge but is not an identity header to the proxy", h)
		}
	}
	for _, h := range proxyIdentityHeaders {
		if !contains(names, h) {
			t.Errorf("the proxy strips %s and generated configuration does not", h)
		}
	}
	// The prefix cannot be written into nginx or APISIX, so the family's
	// names are.
	for _, h := range []string{"X-Auth-Request-User", "X-Auth-Request-Email", "X-Auth-Request-Groups",
		"X-Auth-Request-Preferred-Username", "X-Auth-Request-Access-Token"} {
		if !contains(names, h) {
			t.Errorf("generated configuration does not remove %s", h)
		}
	}
}
