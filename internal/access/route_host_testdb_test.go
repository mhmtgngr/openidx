package access

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// ONE ENABLED ROUTE HOLDS A HOST, IN THE WHOLE INSTALLATION.
//
// The proxy and forward-auth found a request's route with from_url LIKE
// '%'||host||'%' across every organization, highest priority first, and the
// route API took any from_url, so an administrator of one organization could
// create a route on another organization's host at a higher priority, or a
// route whose from_url merely contained the host, and receive that host's
// traffic -- its users' requests, with the identity headers the proxy adds --
// at an upstream of their choosing.
//
// Every request here goes through the real route table behind the middleware
// cmd/access-service mounts in production, to httptest upstreams that record
// what they receive, over a migrated Postgres and a Redis. The other
// organization's administrator uses every API that can put a route on a host.

// asAdmin is the header set of an API call by user, an administrator of org,
// sent to the organization slug names (the default organization when empty).
func (p *proxyFlow) asAdmin(t *testing.T, user, org, slug string, roles ...string) http.Header {
	t.Helper()
	if len(roles) == 0 {
		roles = []string{"admin"}
	}
	h := http.Header{
		"Authorization": {"Bearer " + p.issuer.bearer(t, user, org, roles...)},
		"Content-Type":  {"application/json"},
	}
	if slug != "" {
		h.Set("X-Org-Slug", slug)
	}
	return h
}

func decodeJSON(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return m
}

func TestAnotherOrganizationCannotTakeARoutesHost(t *testing.T) {
	p := newProxyFlow(t)
	host := p.routeHost("payroll")
	victimUp, evilUp := newRecordingUpstream(t), newRecordingUpstream(t)
	routeName := "a-payroll-" + p.f.suffix
	var route string
	if err := p.f.db.Pool.QueryRow(p.f.ctx, `
		INSERT INTO proxy_routes (org_id, name, from_url, to_url, require_auth)
		VALUES ($1::uuid, $2, $3, $4, true) RETURNING id::text`,
		p.f.orgA, routeName, "https://"+host, victimUp.srv.URL).Scan(&route); err != nil {
		t.Fatal(err)
	}
	p.issuer.as(p.f.userA, "user-a@example.test", "staff")
	session, _ := p.signIn(t, host, "/")

	adminB := p.asAdmin(t, p.f.adminB, p.f.orgB, "tenant-"+p.f.suffix)
	refused := func(what string, resp *http.Response, body string) {
		t.Helper()
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("%s: %d %s, want 409", what, resp.StatusCode, body)
			return
		}
		if !strings.Contains(body, "another organization") {
			t.Errorf("%s: the 409 does not say another organization routes the host: %s", what, body)
		}
		if strings.Contains(body, routeName) || strings.Contains(body, route) {
			t.Errorf("%s: the 409 describes the other organization's route: %s", what, body)
		}
	}

	// The route API, under other spellings of the host and a higher priority.
	for _, from := range []string{
		"https://" + host,
		"https://" + strings.ToUpper(host) + ":8443/",
		"http://" + host + "./takeover",
		host,
	} {
		resp, body := p.send(t, http.MethodPost, proxyFlowDomain, "/api/v1/access/routes", adminB,
			`{"name":"takeover-`+p.f.suffix+`","from_url":"`+from+`","to_url":"`+evilUp.srv.URL+`","priority":1000}`)
		refused("create a route on "+from, resp, body)
	}
	// Quick create and bulk create.
	resp, body := p.send(t, http.MethodPost, proxyFlowDomain, "/api/v1/access/services/quick-create", adminB,
		`{"name":"quick-`+p.f.suffix+`","target_url":"`+evilUp.srv.URL+`","domain":"`+host+`"}`)
	refused("quick create on the host", resp, body)
	resp, body = p.send(t, http.MethodPost, proxyFlowDomain, "/api/v1/access/routes/bulk", adminB,
		`{"routes":[{"name":"bulk-free-`+p.f.suffix+`","from_url":"https://`+p.routeHost("bulk-free")+`","to_url":"`+evilUp.srv.URL+`"},`+
			`{"name":"bulk-`+p.f.suffix+`","from_url":"https://`+host+`","to_url":"`+evilUp.srv.URL+`"}]}`)
	refused("bulk create naming the host", resp, body)
	var bulkCreated int
	if err := p.f.db.Pool.QueryRow(p.f.ctx, `SELECT COUNT(*) FROM proxy_routes WHERE name LIKE 'bulk-%'`).Scan(&bulkCreated); err != nil {
		t.Fatal(err)
	}
	if bulkCreated != 0 {
		t.Errorf("a refused bulk request created %d routes", bulkCreated)
	}
	// A disabled route may name the host.
	resp, body = p.send(t, http.MethodPost, proxyFlowDomain, "/api/v1/access/routes", adminB,
		`{"name":"parked-`+p.f.suffix+`","from_url":"https://`+host+`","to_url":"`+evilUp.srv.URL+`","enabled":false}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("a disabled route on the host: %d %s", resp.StatusCode, body)
	}
	parked, _ := decodeJSON(t, body)["id"].(string)
	// Publishing an app on the host, which the parked route's from_url names:
	// refused before the publish replaces anything.
	var appID string
	if err := p.f.db.Pool.QueryRow(p.f.ctx, `
		INSERT INTO published_apps (name, target_url, org_id) VALUES ($1, $2, $3::uuid) RETURNING id::text`,
		"app-"+p.f.suffix, evilUp.srv.URL, p.f.orgB).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	resp, body = p.send(t, http.MethodPost, proxyFlowDomain, "/api/v1/access/apps/"+appID+"/publish-app", adminB,
		`{"public_host":"`+host+`"}`)
	refused("publish an app on the host", resp, body)
	var parkedLeft int
	if err := p.f.db.Pool.QueryRow(p.f.ctx, `SELECT COUNT(*) FROM proxy_routes WHERE id = $1::uuid`, parked).Scan(&parkedLeft); err != nil {
		t.Fatal(err)
	}
	if parkedLeft != 1 {
		t.Error("a refused publish deleted the organization's own disabled route on the host")
	}
	// A disabled route may name the host; enabling it may not. Nor may an
	// enabled route move onto it.
	resp, body = p.send(t, http.MethodPut, proxyFlowDomain, "/api/v1/access/routes/"+parked, adminB, `{"enabled":true}`)
	refused("enable a route on the host", resp, body)
	resp, body = p.send(t, http.MethodPost, proxyFlowDomain, "/api/v1/access/routes", adminB,
		`{"name":"own-`+p.f.suffix+`","from_url":"https://`+p.routeHost("own")+`","to_url":"`+evilUp.srv.URL+`"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("a route on a free host: %d %s", resp.StatusCode, body)
	}
	own, _ := decodeJSON(t, body)["id"].(string)
	resp, body = p.send(t, http.MethodPut, proxyFlowDomain, "/api/v1/access/routes/"+own, adminB,
		`{"from_url":"https://`+host+`/","priority":1000}`)
	refused("move a route onto the host", resp, body)
	// A from_url that only contains the host is a route on its own host.
	resp, body = p.send(t, http.MethodPost, proxyFlowDomain, "/api/v1/access/routes", adminB,
		`{"name":"substring-`+p.f.suffix+`","from_url":"https://`+p.routeHost("attacker")+`/?`+host+`","to_url":"`+evilUp.srv.URL+`","priority":1000}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("a route on another host whose from_url contains this one: %d %s", resp.StatusCode, body)
	}

	// The host's traffic still reaches its own organization's upstream, with
	// its user's identity; nothing reached the other organization's.
	resp, body = p.send(t, http.MethodGet, host, "/payslips", http.Header{"Cookie": {signedIn(session)}}, "")
	if resp.StatusCode != http.StatusOK || body != "upstream-ok" {
		t.Fatalf("a signed-in request to the host: %d %q", resp.StatusCode, body)
	}
	if got := victimUp.last(t).Header.Get("X-Forwarded-User"); got != p.f.userA {
		t.Errorf("the host's upstream received X-Forwarded-User %q", got)
	}
	if n := evilUp.count(); n != 0 {
		t.Errorf("the other organization's upstream received %d requests for the host", n)
	}
	// Forward-auth resolves the host to the same route.
	resp, body = p.send(t, http.MethodGet, proxyFlowDomain, "/api/v1/access/auth/decide", http.Header{
		"Authorization":    {"Bearer " + p.issuer.bearer(t, p.f.userA, p.f.orgA, "staff")},
		"X-Forwarded-Host": {host},
		"X-Forwarded-Uri":  {"/payslips"},
	}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("forward-auth for the host: %d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Forwarded-Route"); got != routeName {
		t.Errorf("forward-auth answered for route %q, want the host's own %q", got, routeName)
	}

	// The host's own organization is told which of its routes holds it.
	adminA := p.asAdmin(t, p.f.adminA, p.f.orgA, "")
	resp, body = p.send(t, http.MethodPost, proxyFlowDomain, "/api/v1/access/routes", adminA,
		`{"name":"second-`+p.f.suffix+`","from_url":"https://`+host+`/admin","to_url":"`+victimUp.srv.URL+`"}`)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, routeName) || !strings.Contains(body, route) {
		t.Errorf("a second route on its own host: %d %s, want 409 naming %s", resp.StatusCode, body, routeName)
	}
	// And the route that holds the host is updated as before.
	resp, body = p.send(t, http.MethodPut, proxyFlowDomain, "/api/v1/access/routes/"+route, adminA,
		`{"from_url":"https://`+strings.ToUpper(host)+`/","priority":5}`)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("updating the route that holds the host: %d %s", resp.StatusCode, body)
	}
}

// The same holds for a host with no route yet: the first organization to
// route it has it, and the second is refused.
func TestTheFirstOrganizationToRouteAHostHoldsIt(t *testing.T) {
	p := newProxyFlow(t)
	host := p.routeHost("fresh")
	up := newRecordingUpstream(t)
	adminA := p.asAdmin(t, p.f.adminA, p.f.orgA, "")
	adminB := p.asAdmin(t, p.f.adminB, p.f.orgB, "tenant-"+p.f.suffix)

	resp, body := p.send(t, http.MethodPost, proxyFlowDomain, "/api/v1/access/routes", adminB,
		`{"name":"b-first-`+p.f.suffix+`","from_url":"https://`+host+`","to_url":"`+up.srv.URL+`","require_auth":false}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("the first route on a free host: %d %s", resp.StatusCode, body)
	}
	resp, body = p.send(t, http.MethodPost, proxyFlowDomain, "/api/v1/access/routes", adminA,
		`{"name":"a-second-`+p.f.suffix+`","from_url":"https://`+host+`","to_url":"http://127.0.0.1:9/","priority":1000}`)
	if resp.StatusCode != http.StatusConflict || strings.Contains(body, "b-first-") {
		t.Errorf("the second organization on the host: %d %s, want 409 that does not name the route", resp.StatusCode, body)
	}
	if resp, _ := p.send(t, http.MethodGet, host, "/", nil, ""); resp.StatusCode != http.StatusOK || up.count() != 1 {
		t.Errorf("the host's traffic: %d, upstream saw %d requests", resp.StatusCode, up.count())
	}
}

// The BrowZer domain is the host of every BrowZer path route. Changing it
// moves the routes on that host, exactly, and a domain another organization
// already routes is refused before anything changes.
func TestTheBrowZerDomainMovesOnlyTheRoutesOnItsHost(t *testing.T) {
	p := newProxyFlow(t)
	seed := func(org, name, fromURL string, browzer bool) string {
		t.Helper()
		var id string
		if err := p.f.db.Pool.QueryRow(p.f.ctx, `
			INSERT INTO proxy_routes (org_id, name, from_url, to_url, enabled, ziti_enabled, browzer_enabled, ziti_service_name)
			VALUES ($1::uuid, $2, $3, 'http://10.0.0.9:8080', true, $4, $4, $2) RETURNING id::text`,
			org, name+"-"+p.f.suffix, fromURL, browzer).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		return id
	}
	fromURL := func(id string) string {
		t.Helper()
		var u string
		if err := p.f.db.Pool.QueryRow(p.f.ctx, `SELECT from_url FROM proxy_routes WHERE id = $1::uuid`, id).Scan(&u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	taken := p.routeHost("taken")
	seed(p.f.orgB, "taken", "https://"+taken, false)
	platform := p.asAdmin(t, p.f.superA, p.f.orgA, "", "admin", "super_admin")
	change := func(domain string) (*http.Response, string) {
		return p.send(t, http.MethodPut, proxyFlowDomain, "/api/v1/access/ziti/browzer/domain", platform, `{"domain":"`+domain+`"}`)
	}
	// Refused whether or not a route would move onto it: the domain is the
	// bootstrapper's host too.
	resp, body := change(taken)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "another organization") {
		t.Errorf("a domain another organization routes, with no route to move: %d %s, want 409", resp.StatusCode, body)
	}

	pathRoute := seed(p.f.orgA, "path", "http://"+DefaultBrowZerDomain+"/app", true)
	// A host that contains the domain is another host.
	subdomain := seed(p.f.orgA, "sub", "https://app."+DefaultBrowZerDomain+"/", true)

	resp, body = change(strings.ToUpper(taken))
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "another organization") {
		t.Errorf("a domain another organization routes: %d %s, want 409", resp.StatusCode, body)
	}
	resp, body = change("not a host/x")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a domain that is not a host name: %d %s, want 400", resp.StatusCode, body)
	}
	if got := fromURL(pathRoute); got != "http://"+DefaultBrowZerDomain+"/app" {
		t.Fatalf("a refused change moved the path route to %q", got)
	}

	moved := p.routeHost("moved")
	resp, body = change(moved)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a free domain: %d %s", resp.StatusCode, body)
	}
	if got := fromURL(pathRoute); got != "http://"+moved+"/app" {
		t.Errorf("the path route is at %q, want it on the new domain with its path", got)
	}
	if got := fromURL(subdomain); got != "https://app."+DefaultBrowZerDomain+"/" {
		t.Errorf("a route on another host that contains the domain was rewritten to %q", got)
	}
}

// Enabling BrowZer on a Ziti service with a domain, and importing a Ziti
// service with a from_url, create routes too: a host another organization
// routes is refused before the controller is changed.
func TestBrowZerAndZitiImportCannotTakeAnotherOrganizationsHost(t *testing.T) {
	s, stub, db, ctx, cleanup := browzerFixture(t)
	if s == nil {
		return
	}
	defer cleanup()
	const otherOrg = "00000000-0000-0000-0000-0000000000b2"
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO proxy_routes (name, from_url, to_url, enabled, org_id)
		VALUES ('held', 'https://held.example.test/', 'http://10.0.0.7:8080', true, $1::uuid)`, otherOrg); err != nil {
		t.Fatal(err)
	}

	w := call(t, s, ctx, http.MethodPost, browzerZitiID, map[string]any{"domain": "HELD.example.test"}, s.handleEnableBrowZerOnService)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "another organization") {
		t.Errorf("BrowZer on a domain another organization routes: %d %s, want 409", w.Code, w.Body.String())
	}
	if stub.saw("PATCH /edge/management/v1/services") {
		t.Errorf("the refused request changed the service on the controller: %v", stub.received())
	}
	var n int
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM proxy_routes WHERE host = 'held.example.test'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d routes on the held host after a refused request", n)
	}

	s.ziti().initialized = true
	stub.ok("GET /edge/management/v1/services", `{"data":[{"id":"svc-import","name":"import-me"}]}`)
	w = call(t, s, ctx, http.MethodPost, "", map[string]any{"ziti_id": "svc-import", "from_url": "http://held.example.test:8080/"},
		s.handleImportZitiService)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "another organization") {
		t.Errorf("importing a Ziti service onto a host another organization routes: %d %s, want 409", w.Code, w.Body.String())
	}

	// The positive control: a free domain goes through.
	w = call(t, s, ctx, http.MethodPost, browzerZitiID, map[string]any{"domain": "free.example.test"}, s.handleEnableBrowZerOnService)
	if w.Code != http.StatusOK {
		t.Errorf("BrowZer on a free domain: %d %s", w.Code, w.Body.String())
	}
}

// The edge and the BrowZer configuration render a route on its host as the
// route table holds it -- the host the unique index gives one route -- and a
// from_url that only mentions another host renders on its own.
func TestTheEdgeAndBrowZerRenderTheRoutesOwnHost(t *testing.T) {
	f := newAdminGateFixture(t)
	ctx := context.Background()
	var pool string
	if err := f.db.Pool.QueryRow(f.ctx, `
		INSERT INTO upstream_pools (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`, f.orgA, "web-"+f.suffix).Scan(&pool); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(f.ctx, `
		INSERT INTO upstream_pool_members (pool_id, org_id, host, port) VALUES ($1::uuid, $2::uuid, '10.0.0.1', 8080)`, pool, f.orgA); err != nil {
		t.Fatal(err)
	}
	shop := "shop-" + f.suffix + ".example.test"
	route := func(org, name, fromURL string, browzer bool, pool any) {
		t.Helper()
		if _, err := f.db.Pool.Exec(f.ctx, `
			INSERT INTO proxy_routes (org_id, name, from_url, to_url, enabled, ziti_enabled, browzer_enabled, ziti_service_name, upstream_pool_id)
			VALUES ($1::uuid, $2, $3, 'http://10.0.0.9:8080', true, $4, $4, $2, $5::uuid)`,
			org, name+"-"+f.suffix, fromURL, browzer, pool); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	route(f.orgA, "shop", "HTTPS://"+strings.ToUpper(shop)+".:8443/x", false, pool)
	route(f.orgB, "mention", "https://attacker-"+f.suffix+".example.test/?"+shop, false, pool)
	route(f.orgA, "portal", "http://Portal-"+f.suffix+".Example.Test/", true, nil)

	objs, err := BuildEdgeRoutesForPools(ctx, f.db, zap.NewNop(), "http://access-service:8007/api/v1/access/auth/decide")
	if err != nil {
		t.Fatalf("render the edge: %v", err)
	}
	hosts := map[string]bool{}
	for _, o := range objs {
		var obj struct {
			Hosts []string `json:"hosts"`
		}
		if err := json.Unmarshal(o.body, &obj); err != nil {
			t.Fatal(err)
		}
		for _, h := range obj.Hosts {
			hosts[h] = true
		}
	}
	if !hosts[shop] || !hosts["attacker-"+f.suffix+".example.test"] || len(hosts) != 2 {
		t.Errorf("the edge renders hosts %v, want %s and the attacker's own host", hosts, shop)
	}

	tm := NewBrowZerTargetManager(f.db, zap.NewNop(), "")
	bz, err := tm.queryBrowZerRoutes(orgctx.WithBypassRLS(ctx))
	if err != nil {
		t.Fatal(err)
	}
	if len(bz) != 1 || bz[0].hostname != "portal-"+f.suffix+".example.test" {
		t.Errorf("BrowZer renders %+v, want the portal route on its host as stored", bz)
	}
}
