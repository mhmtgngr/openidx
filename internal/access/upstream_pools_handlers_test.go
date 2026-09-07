package access

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The half of upstream pools an operator can reach.
//
// These tests are written against the questions the endpoints exist to answer,
// not against the round trip. A round-trip test would have passed on the state
// this feature was already in: the schema accepted an INSERT and the renderer
// rendered it, and neither fact meant a pool could be created or would ever
// serve traffic.
//
// So: does creating a pool with members produce one that says it is not yet in
// effect; does draining the last member say the routes have fallen back; does
// deleting a pool that routes use refuse; and can one tenant reach another's
// pool by id.

const upstreamPoolSchema = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS upstream_pools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    algorithm TEXT NOT NULL DEFAULT 'roundrobin' CHECK (algorithm IN ('roundrobin','chash')),
    hash_on TEXT NOT NULL DEFAULT 'vars' CHECK (hash_on IN ('vars','header','cookie')),
    hash_key TEXT NOT NULL DEFAULT 'remote_addr',
    health_check_enabled BOOLEAN NOT NULL DEFAULT true,
    health_check_path TEXT NOT NULL DEFAULT '/',
    healthy_threshold INT NOT NULL DEFAULT 2 CHECK (healthy_threshold BETWEEN 1 AND 10),
    unhealthy_threshold INT NOT NULL DEFAULT 3 CHECK (unhealthy_threshold BETWEEN 1 AND 10),
    health_check_interval INT NOT NULL DEFAULT 5 CHECK (health_check_interval BETWEEN 1 AND 300),
    health_check_timeout INT NOT NULL DEFAULT 3 CHECK (health_check_timeout BETWEEN 1 AND 60),
    retries INT CHECK (retries IS NULL OR retries BETWEEN 0 AND 10),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT upstream_pools_org_name_key UNIQUE (org_id, name));
CREATE TABLE IF NOT EXISTS upstream_pool_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_id UUID NOT NULL REFERENCES upstream_pools(id) ON DELETE CASCADE,
    org_id UUID NOT NULL,
    host TEXT NOT NULL,
    port INT NOT NULL CHECK (port BETWEEN 1 AND 65535),
    weight INT NOT NULL DEFAULT 1 CHECK (weight BETWEEN 0 AND 1000),
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT upstream_pool_members_unique UNIQUE (pool_id, host, port));
CREATE TABLE IF NOT EXISTS proxy_routes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID, name TEXT NOT NULL, from_url TEXT, to_url TEXT,
    enabled BOOLEAN DEFAULT true, priority INT DEFAULT 0,
    browzer_enabled BOOLEAN DEFAULT false, ziti_enabled BOOLEAN DEFAULT false,
    ziti_service_name TEXT, landing_path TEXT DEFAULT '/',
    hosting_mode TEXT DEFAULT 'identity',
    upstream_pool_id UUID REFERENCES upstream_pools(id) ON DELETE SET NULL);`

const (
	poolOrg      = "00000000-0000-0000-0000-0000000000b1"
	poolOtherOrg = "00000000-0000-0000-0000-0000000000b2"
)

func poolFixture(t *testing.T) (*Service, *database.PostgresDB, context.Context, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil, nil, func() {}
	}
	gin.SetMode(gin.TestMode)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: poolOrg})
	if _, err := db.Pool.Exec(ctx, upstreamPoolSchema); err != nil {
		cleanup()
		t.Fatalf("schema: %v", err)
	}
	return &Service{db: db, logger: zap.NewNop()}, db, ctx, cleanup
}

// poolCall drives one handler with a JSON body and the given path params.
func poolCall(t *testing.T, ctx context.Context, method string, params gin.Params,
	body any, h func(*gin.Context)) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var buf []byte
	if body != nil {
		var err error
		if buf, err = json.Marshal(body); err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, "/x", bytes.NewReader(buf)).WithContext(ctx)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = params
	c.Set("roles", []string{"admin"})
	h(c)

	var decoded map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("decode response %q: %v", w.Body.String(), err)
		}
	}
	return w, decoded
}

// createPool is the arrange step for the tests below: it goes through the
// handler rather than an INSERT, because "can a pool be created at all" is the
// finding, and an INSERT in the fixture would step around it.
func createPool(t *testing.T, s *Service, ctx context.Context, body any) string {
	t.Helper()
	w, resp := poolCall(t, ctx, http.MethodPost, nil, body, s.handleCreateUpstreamPool)
	if w.Code != http.StatusCreated {
		t.Fatalf("create pool: %d %s", w.Code, w.Body.String())
	}
	id, _ := resp["id"].(string)
	if id == "" {
		t.Fatalf("create pool returned no id: %s", w.Body.String())
	}
	return id
}

// A pool with two healthy members exists, and says it is NOT in effect, because
// no route points at it.
//
// The distinction is the reason the endpoint reports more than the row. An
// operator who has just defined a backend set will next ask why traffic has not
// moved, and "you have not linked a route" is the answer the product can give
// but never did.
func TestACreatedPoolSaysItIsNotInEffectUntilARoutePointsAtIt(t *testing.T) {
	s, db, ctx, cleanup := poolFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	id := createPool(t, s, ctx, map[string]any{
		"name": "payroll-backends",
		"members": []map[string]any{
			{"host": "203.0.113.1", "port": 8080},
			{"host": "203.0.113.2", "port": 8080, "weight": 3},
		},
	})

	w, got := poolCall(t, ctx, http.MethodGet, gin.Params{{Key: "id", Value: id}}, nil, s.handleGetUpstreamPool)
	if w.Code != http.StatusOK {
		t.Fatalf("get pool: %d %s", w.Code, w.Body.String())
	}
	if members, _ := got["members"].([]any); len(members) != 2 {
		t.Fatalf("want the two members the create declared, got %v", got["members"])
	}
	if got["in_effect"] != false {
		t.Fatalf("a pool no route names is not in effect; got in_effect=%v", got["in_effect"])
	}
	if reason, _ := got["not_in_effect_reason"].(string); reason == "" {
		t.Fatal("in_effect=false with no reason is the same silence this endpoint exists to break")
	}
	if n, _ := got["routes_using"].(float64); n != 0 {
		t.Fatalf("routes_using: want 0, got %v", n)
	}

	// Point a route at it and the same pool now reports itself in effect.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO proxy_routes (org_id, name, from_url, to_url, upstream_pool_id)
		 VALUES ($1::uuid, 'payroll', 'https://payroll.example', 'http://203.0.113.1:8080', $2::uuid)`,
		poolOrg, id); err != nil {
		t.Fatalf("link a route: %v", err)
	}
	_, got = poolCall(t, ctx, http.MethodGet, gin.Params{{Key: "id", Value: id}}, nil, s.handleGetUpstreamPool)
	if got["in_effect"] != true {
		t.Fatalf("a pool with usable members and a route is in effect; got %v (%v)",
			got["in_effect"], got["not_in_effect_reason"])
	}
	if n, _ := got["routes_using"].(float64); n != 1 {
		t.Fatalf("routes_using: want 1, got %v", n)
	}
}

// Draining the last member does not stop the route -- it sends it back to
// to_url -- and the response says so.
//
// This is the display-without-enforcement case in miniature. BuildUpstream
// refuses to render a pool with no usable node because an empty upstream
// black-holes the route, so the route keeps serving from its single address.
// An operator draining a pool for maintenance and told only "member updated"
// would believe traffic had stopped.
func TestDrainingTheLastMemberSaysTheRoutesHaveFallenBack(t *testing.T) {
	s, db, ctx, cleanup := poolFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	id := createPool(t, s, ctx, map[string]any{
		"name":    "single-backend",
		"members": []map[string]any{{"host": "203.0.113.9", "port": 8080}},
	})
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO proxy_routes (org_id, name, from_url, to_url, upstream_pool_id)
		 VALUES ($1::uuid, 'app', 'https://app.example', 'http://203.0.113.9:8080', $2::uuid)`,
		poolOrg, id); err != nil {
		t.Fatalf("link a route: %v", err)
	}

	var memberID string
	if err := db.Pool.QueryRow(ctx,
		`SELECT id::text FROM upstream_pool_members WHERE pool_id = $1::uuid`, id).Scan(&memberID); err != nil {
		t.Fatalf("read the member the create made: %v", err)
	}

	params := gin.Params{{Key: "id", Value: id}, {Key: "memberId", Value: memberID}}
	w, resp := poolCall(t, ctx, http.MethodPut, params,
		map[string]any{"enabled": false}, s.handleUpdateUpstreamPoolMember)
	if w.Code != http.StatusOK {
		t.Fatalf("disable the member: %d %s", w.Code, w.Body.String())
	}

	pool, ok := resp["pool"].(map[string]any)
	if !ok {
		t.Fatalf("a member change must answer with the pool's resulting state, got %s", w.Body.String())
	}
	if pool["in_effect"] != false {
		t.Fatalf("with its only member disabled the pool serves nothing; got in_effect=%v", pool["in_effect"])
	}
	if reason, _ := pool["not_in_effect_reason"].(string); reason == "" {
		t.Fatal("the operator is told the pool is not in effect but not that the route fell back to its single target")
	}

	// The route is still linked -- it has not been unlinked, it has fallen
	// back. Reporting routes_using=0 here would read as "nothing is affected".
	if n, _ := pool["routes_using"].(float64); n != 1 {
		t.Fatalf("the route still names this pool; routes_using want 1, got %v", n)
	}
}

// A pool that routes still point at cannot be deleted.
//
// The foreign key is ON DELETE SET NULL, so the database would accept this and
// silently move every route back to one backend with no health checking.
func TestDeletingAPoolRoutesUseIsRefusedAndNamesThem(t *testing.T) {
	s, db, ctx, cleanup := poolFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	id := createPool(t, s, ctx, map[string]any{
		"name":    "in-use",
		"members": []map[string]any{{"host": "203.0.113.1", "port": 80}},
	})
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO proxy_routes (org_id, name, from_url, to_url, upstream_pool_id)
		 VALUES ($1::uuid, 'billing', 'https://billing.example', 'http://203.0.113.1:80', $2::uuid)`,
		poolOrg, id); err != nil {
		t.Fatalf("link a route: %v", err)
	}

	w, resp := poolCall(t, ctx, http.MethodDelete, gin.Params{{Key: "id", Value: id}},
		nil, s.handleDeleteUpstreamPool)
	if w.Code != http.StatusConflict {
		t.Fatalf("deleting a pool in use must be refused, got %d %s", w.Code, w.Body.String())
	}
	routes, _ := resp["routes"].([]any)
	if len(routes) != 1 || routes[0] != "billing" {
		t.Fatalf("the refusal must name the routes that would be moved; got %v", resp["routes"])
	}

	// The pool is still there: a refused delete that deleted anyway is worse
	// than either outcome.
	var n int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM upstream_pools WHERE id = $1::uuid`, id).Scan(&n); err != nil {
		t.Fatalf("count pools: %v", err)
	}
	if n != 1 {
		t.Fatal("the pool was deleted by a request that answered 409")
	}

	// Unlink the route and the same delete succeeds.
	if _, err := db.Pool.Exec(ctx, `UPDATE proxy_routes SET upstream_pool_id = NULL`); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	w, _ = poolCall(t, ctx, http.MethodDelete, gin.Params{{Key: "id", Value: id}},
		nil, s.handleDeleteUpstreamPool)
	if w.Code != http.StatusOK {
		t.Fatalf("delete after unlinking: %d %s", w.Code, w.Body.String())
	}
}

// One tenant cannot read, change or destroy another tenant's pool by id, and
// cannot add a member to it.
//
// The member case is the one worth stating: without the ownership check before
// the INSERT, the row would carry the caller's org_id under another tenant's
// pool_id -- a member this org can see and that org's routes would serve.
func TestAPoolIsNotReachableFromAnotherTenant(t *testing.T) {
	s, db, ctx, cleanup := poolFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	id := createPool(t, s, ctx, map[string]any{
		"name":    "tenant-a-backends",
		"members": []map[string]any{{"host": "203.0.113.1", "port": 8080}},
	})

	other := orgctx.With(context.Background(), orgctx.Org{ID: poolOtherOrg})
	one := gin.Params{{Key: "id", Value: id}}

	w, _ := poolCall(t, other, http.MethodGet, one, nil, s.handleGetUpstreamPool)
	if w.Code != http.StatusNotFound {
		t.Fatalf("another tenant's pool id must be 404, got %d %s", w.Code, w.Body.String())
	}

	w, _ = poolCall(t, other, http.MethodGet, nil, nil, s.handleListUpstreamPools)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d", w.Code)
	}
	var list struct {
		Pools []upstreamPoolView `json:"pools"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Pools) != 0 {
		t.Fatalf("another tenant's list must be empty, got %d pools", len(list.Pools))
	}

	w, _ = poolCall(t, other, http.MethodPut, one,
		map[string]any{"name": "stolen"}, s.handleUpdateUpstreamPool)
	if w.Code != http.StatusNotFound {
		t.Fatalf("update across tenants must be 404, got %d %s", w.Code, w.Body.String())
	}

	w, _ = poolCall(t, other, http.MethodPost, one,
		map[string]any{"host": "203.0.113.99", "port": 8080}, s.handleAddUpstreamPoolMember)
	if w.Code != http.StatusNotFound {
		t.Fatalf("adding a member to another tenant's pool must be 404, got %d %s", w.Code, w.Body.String())
	}

	w, _ = poolCall(t, other, http.MethodDelete, one, nil, s.handleDeleteUpstreamPool)
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete across tenants must be 404, got %d %s", w.Code, w.Body.String())
	}

	// After all of that, the pool is untouched: still named what tenant A named
	// it, still with the one member tenant A gave it.
	var name string
	var members int
	if err := db.Pool.QueryRow(ctx,
		`SELECT p.name, (SELECT COUNT(*) FROM upstream_pool_members m WHERE m.pool_id = p.id)
		 FROM upstream_pools p WHERE p.id = $1::uuid`, id).Scan(&name, &members); err != nil {
		t.Fatalf("re-read the pool: %v", err)
	}
	if name != "tenant-a-backends" || members != 1 {
		t.Fatalf("another tenant changed this pool: name=%q members=%d", name, members)
	}
}

// A route cannot be pointed at another tenant's pool.
//
// The FK alone would accept it: upstream_pool_id references upstream_pools(id)
// with no org predicate, so a route in org B naming org A's pool would be a
// valid row -- and the reconciler, which reads pools with RLS bypassed, would
// render org B's hostname onto org A's backends.
func TestARouteCannotBePointedAtAnotherTenantsPool(t *testing.T) {
	s, _, ctx, cleanup := poolFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	id := createPool(t, s, ctx, map[string]any{
		"name":    "tenant-a-backends",
		"members": []map[string]any{{"host": "203.0.113.1", "port": 8080}},
	})

	other := orgctx.With(context.Background(), orgctx.Org{ID: poolOtherOrg})
	if _, err := s.resolvePoolForRoute(other, poolOtherOrg, id); err == nil {
		t.Fatal("a route in another org resolved this org's pool: its traffic would be sent to our backends")
	}
	// The same id from its own org resolves.
	if got, err := s.resolvePoolForRoute(ctx, poolOrg, id); err != nil || got == nil || *got != id {
		t.Fatalf("own-org pool must resolve: got %v err %v", got, err)
	}
	// Empty means "back to to_url" and is not an error.
	if got, err := s.resolvePoolForRoute(ctx, poolOrg, ""); err != nil || got != nil {
		t.Fatalf("clearing the link must be allowed: got %v err %v", got, err)
	}
}

// Values the schema would reject are refused with a message naming the field.
//
// The CHECK constraints are the backstop. Left to them, an operator typing 400
// into "healthy threshold" gets a 500 and a log line about SQLSTATE 23514.
func TestPoolValidationRefusesValuesTheSchemaWouldRejectWithAUsableMessage(t *testing.T) {
	s, _, ctx, cleanup := poolFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	for _, tc := range []struct {
		name string
		body map[string]any
		want string
	}{
		{"algorithm", map[string]any{"name": "p", "algorithm": "leastconn"}, "algorithm"},
		{"hash_on", map[string]any{"name": "p", "hash_on": "querystring"}, "hash_on"},
		{"healthy threshold", map[string]any{"name": "p", "healthy_threshold": 400}, "healthy_threshold"},
		{"interval", map[string]any{"name": "p", "health_check_interval": 9000}, "health_check_interval"},
		{"retries", map[string]any{"name": "p", "retries": 99}, "retries"},
		{"health path", map[string]any{"name": "p", "health_check_path": "healthz"}, "health_check_path"},
		{"member port", map[string]any{"name": "p",
			"members": []map[string]any{{"host": "203.0.113.1", "port": 70000}}}, "port"},
		{"member weight", map[string]any{"name": "p",
			"members": []map[string]any{{"host": "203.0.113.1", "port": 80, "weight": 5000}}}, "weight"},
		// The commonest real mistake: pasting a URL into the host field.
		{"member host with scheme", map[string]any{"name": "p",
			"members": []map[string]any{{"host": "http://203.0.113.1", "port": 80}}}, "host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, resp := poolCall(t, ctx, http.MethodPost, nil, tc.body, s.handleCreateUpstreamPool)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d %s", w.Code, w.Body.String())
			}
			msg, _ := resp["error"].(string)
			if !strings.Contains(msg, tc.want) {
				t.Fatalf("the message must name the field %q; got %q", tc.want, msg)
			}
		})
	}
}

// A backend listed twice would silently double its share of traffic.
func TestTheSameBackendCannotBeAddedTwice(t *testing.T) {
	s, _, ctx, cleanup := poolFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	id := createPool(t, s, ctx, map[string]any{
		"name":    "dupes",
		"members": []map[string]any{{"host": "203.0.113.1", "port": 8080}},
	})
	w, _ := poolCall(t, ctx, http.MethodPost, gin.Params{{Key: "id", Value: id}},
		map[string]any{"host": "203.0.113.1", "port": 8080}, s.handleAddUpstreamPoolMember)
	if w.Code != http.StatusConflict {
		t.Fatalf("a duplicate member must be 409, got %d %s", w.Code, w.Body.String())
	}
}

// A create that fails partway leaves no pool behind.
//
// Without the transaction, a duplicate member in the request would leave a pool
// carrying some of the backends the operator declared -- a load balancer
// weighted differently from what they asked for, and reported as a failure, so
// nobody would go looking for it.
func TestAFailedCreateLeavesNoHalfBuiltPool(t *testing.T) {
	s, db, ctx, cleanup := poolFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	w, _ := poolCall(t, ctx, http.MethodPost, nil, map[string]any{
		"name": "half-built",
		"members": []map[string]any{
			{"host": "203.0.113.1", "port": 8080},
			{"host": "203.0.113.2", "port": 8080},
			{"host": "203.0.113.1", "port": 8080}, // the same backend again
		},
	}, s.handleCreateUpstreamPool)
	if w.Code != http.StatusConflict {
		t.Fatalf("want 409 on the duplicate member, got %d %s", w.Code, w.Body.String())
	}

	var pools, members int
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM upstream_pools`).Scan(&pools); err != nil {
		t.Fatalf("count pools: %v", err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM upstream_pool_members`).Scan(&members); err != nil {
		t.Fatalf("count members: %v", err)
	}
	if pools != 0 || members != 0 {
		t.Fatalf("a refused create left %d pool(s) and %d member(s) behind", pools, members)
	}
}

// The renderer sees what the handlers wrote.
//
// This is the third half of the finding, and the one the register did not name.
// BuildEdgeRoutesForPools existed, was tested against hand-built structs, and
// was called by nothing -- so a pool could be created, linked to a route, and
// still never reach the data plane. This drives the real path: create through
// the handler, link a route, and ask the function the reconciler calls what the
// edge should look like.
func TestWhatTheHandlersWriteIsWhatTheEdgeRendererReads(t *testing.T) {
	s, db, ctx, cleanup := poolFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	id := createPool(t, s, ctx, map[string]any{
		"name":      "rendered",
		"algorithm": "roundrobin",
		"members": []map[string]any{
			{"host": "203.0.113.1", "port": 8080, "weight": 1},
			{"host": "203.0.113.2", "port": 8080, "weight": 4},
		},
	})
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO proxy_routes (org_id, name, from_url, to_url, upstream_pool_id)
		 VALUES ($1::uuid, 'shop', 'https://shop.example', 'http://203.0.113.1:8080', $2::uuid)`,
		poolOrg, id); err != nil {
		t.Fatalf("link a route: %v", err)
	}

	objs, err := BuildEdgeRoutesForPools(context.Background(), db, zap.NewNop())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(objs) != 1 {
		t.Fatalf("want one rendered route, got %d", len(objs))
	}
	if objs[0].name != "oidx-route-shop" {
		t.Fatalf("route name: %q", objs[0].name)
	}

	obj := decodeRenderedRoute(t, objs[0].body)
	if len(obj.Hosts) != 1 || obj.Hosts[0] != "shop.example" {
		t.Fatalf("hosts: %v", obj.Hosts)
	}
	// The weights the operator declared are the weights the data plane gets.
	// This is the assertion a round-trip test would have skipped, and it is the
	// whole product of the feature.
	if obj.Upstream.Nodes["203.0.113.1:8080"] != 1 || obj.Upstream.Nodes["203.0.113.2:8080"] != 4 {
		t.Fatalf("declared weights 1 and 4 did not reach the upstream: %v", obj.Upstream.Nodes)
	}
	if obj.Upstream.Checks == nil {
		t.Fatal("health checking defaults to on and must appear in the rendered upstream")
	}

	// Drain both members and the route falls back to its single target rather
	// than rendering an upstream with no node.
	if _, err := db.Pool.Exec(ctx, `UPDATE upstream_pool_members SET enabled = false`); err != nil {
		t.Fatalf("drain: %v", err)
	}
	objs, err = BuildEdgeRoutesForPools(context.Background(), db, zap.NewNop())
	if err != nil {
		t.Fatalf("render after drain: %v", err)
	}
	if len(objs) != 1 {
		t.Fatalf("the route is still served, from to_url; got %d objects", len(objs))
	}
	drained := decodeRenderedRoute(t, objs[0].body)
	if len(drained.Nodes()) != 1 || drained.Upstream.Nodes["203.0.113.1:8080"] != 1 {
		t.Fatalf("a fully drained pool must fall back to to_url's single node, got %v", drained.Upstream.Nodes)
	}
	if drained.Upstream.Checks != nil {
		t.Fatal("the to_url fallback carries no health checking; rendering checks over one node would claim a property the route does not have")
	}
}

// renderedRoute is the part of an APISIX route object these tests read.
type renderedRoute struct {
	Hosts    []string `json:"hosts"`
	Upstream struct {
		Type   string         `json:"type"`
		Nodes  map[string]int `json:"nodes"`
		Checks map[string]any `json:"checks"`
	} `json:"upstream"`
}

func (r renderedRoute) Nodes() map[string]int { return r.Upstream.Nodes }

// decodeRenderedRoute decodes into a FRESH value every time, deliberately.
//
// Unmarshalling into a struct that already holds a non-nil map merges keys
// instead of replacing them, so reusing one variable across two renders would
// show the first render's nodes surviving into the second — a test reading a
// value the code never produced. That is exactly what this test caught on
// itself the first time it ran.
func decodeRenderedRoute(t *testing.T, body []byte) renderedRoute {
	t.Helper()
	var out renderedRoute
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode rendered route %s: %v", body, err)
	}
	return out
}

// THE RECONCILER ACTUALLY CALLS THE RENDERER.
//
// This is the guard for the layer of the finding the register did not name.
// BuildEdgeRoutesForPools existed, was correct, and was called by nobody:
// Reconcile loaded the BrowZer routes and nothing else, so a pool could be
// created, linked to a route, rendered perfectly by a tested function, and
// still never reach APISIX. Every other test in this file would have passed in
// that state.
//
// So this one drives Reconcile itself against a real database and a fake Admin
// API, and asserts the PUT. Delete the BuildEdgeRoutesForPools call from
// Reconcile and this is the test that goes red.
func TestReconcileSendsPoolBackedRoutesToTheDataPlane(t *testing.T) {
	s, db, ctx, cleanup := poolFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	id := createPool(t, s, ctx, map[string]any{
		"name":    "reconciled",
		"members": []map[string]any{{"host": "203.0.113.11", "port": 9000}, {"host": "203.0.113.12", "port": 9000}},
	})
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO proxy_routes (org_id, name, from_url, to_url, upstream_pool_id)
		 VALUES ($1::uuid, 'orders', 'https://orders.example', 'http://203.0.113.11:9000', $2::uuid)`,
		poolOrg, id); err != nil {
		t.Fatalf("link a route: %v", err)
	}

	// An oidx-route-* object at the edge for a route that no longer names a
	// pool: the pass is entitled to prune it, and must.
	f := &fakeAPISIX{existing: []string{"oidx-route-retired", "identity-service"}}
	rec := &APISIXReconciler{
		db:     db,
		logger: zap.NewNop(),
		client: f,
		tm:     &BrowZerTargetManager{db: db, logger: zap.NewNop()},
		opts:   apisixRouteOpts{bootstrapperNode: "127.0.0.1:8445", hopBasePort: 8095},
	}
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	body, ok := f.put["oidx-route-orders"]
	if !ok {
		t.Fatalf("the pool-backed route never reached the data plane; PUT %v", f.put)
	}
	got := decodeRenderedRoute(t, body)
	if len(got.Upstream.Nodes) != 2 {
		t.Fatalf("both members must be in the upstream APISIX was given: %v", got.Upstream.Nodes)
	}

	if len(f.deleted) != 1 || f.deleted[0] != "oidx-route-retired" {
		t.Fatalf("want only the retired generated route pruned, got %v", f.deleted)
	}
}
