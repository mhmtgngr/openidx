package access

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// THE ROUTE TABLE AND THE PROXY SESSIONS ARE ADMINISTRATION.
//
// A proxy route decides who may reach which upstream, with which headers, and
// whether sign-in is needed at all; the session list names every user of every
// route and revoking one ends somebody's access. Both are driven here through
// RegisterRoutes -- the table cmd/access-service serves -- with the access
// service's own admin gate in front:
//
//   - a caller without an admin role -- a plain user, or an operator, the tier
//     the console gives helpdesk staff -- is refused with 403 on every route,
//     and the route or session it aimed at is read back unchanged, including a
//     session that belongs to somebody else;
//   - an admin of the organization gets through and the change lands;
//   - that admin still cannot see or change another organization's route or
//     session: the gate is in front of the organization scoping, not instead
//     of it.
func TestRouteAndSessionAPIsNeedTheAdminRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newAdminGateFixture(t)
	e := f.serve(t, f.db)

	type routeState struct {
		exists      bool
		requireAuth bool
		toURL       string
		headers     string
	}
	route := func(id string) routeState {
		t.Helper()
		var s routeState
		err := f.db.Pool.QueryRow(f.ctx,
			`SELECT require_auth, to_url, COALESCE(custom_headers::text, '')
			   FROM proxy_routes WHERE id = $1::uuid`, id).Scan(&s.requireAuth, &s.toURL, &s.headers)
		s.exists = err == nil
		return s
	}
	revoked := func(id string) bool {
		t.Helper()
		var r bool
		if err := f.db.Pool.QueryRow(f.ctx, `SELECT revoked FROM proxy_sessions WHERE id = $1::uuid`, id).Scan(&r); err != nil {
			t.Fatalf("read session %s: %v", id, err)
		}
		return r
	}
	routeCount := func(name string) int {
		t.Helper()
		var n int
		if err := f.db.Pool.QueryRow(f.ctx, `SELECT COUNT(*) FROM proxy_routes WHERE name = $1`, name).Scan(&n); err != nil {
			t.Fatalf("count routes: %v", err)
		}
		return n
	}
	before := route(f.routeA)

	for _, who := range []struct{ name, key string }{
		{"a plain user", e.caller(f.userA, f.orgA, "user")},
		{"an operator", e.caller(f.operatorA, f.orgA, "operator")},
	} {
		t.Run(who.name+" is refused everywhere", func(t *testing.T) {
			for _, rq := range []struct{ method, path, body string }{
				{http.MethodGet, "/api/v1/access/routes", ""},
				{http.MethodPost, "/api/v1/access/routes", `{"name":"planted-` + f.suffix + `","from_url":"https://planted.example.test","to_url":"http://127.0.0.1:1/","require_auth":false}`},
				{http.MethodGet, "/api/v1/access/routes/" + f.routeA, ""},
				{http.MethodPut, "/api/v1/access/routes/" + f.routeA, `{"require_auth":false,"to_url":"http://127.0.0.1:1/","custom_headers":{"X-Forwarded-User":"admin"}}`},
				{http.MethodDelete, "/api/v1/access/routes/" + f.routeA, ""},
				{http.MethodGet, "/api/v1/access/sessions", ""},
				// Somebody else's session, then the plain user's own: the
				// admin API is not the way to end either. A user signs out of
				// their own through /access/.auth/logout.
				{http.MethodDelete, "/api/v1/access/sessions/" + f.adminSessionA, ""},
				{http.MethodDelete, "/api/v1/access/sessions/" + f.userSessionA, ""},
			} {
				code, body := e.do(who.key, rq.method, rq.path, rq.body)
				if code != http.StatusForbidden || !strings.Contains(body, "admin access required") {
					t.Errorf("%s %s: %d %s, want 403 admin access required", rq.method, rq.path, code, body)
				}
			}
			if n := routeCount("planted-" + f.suffix); n != 0 {
				t.Errorf("a refused create still wrote %d route(s)", n)
			}
			if after := route(f.routeA); after != before {
				t.Errorf("a refused update or delete still changed the route: %+v, was %+v", after, before)
			}
			if revoked(f.adminSessionA) || revoked(f.userSessionA) {
				t.Error("a refused revoke still revoked a session")
			}
		})
	}

	t.Run("an admin manages the organization's routes and sessions", func(t *testing.T) {
		as := e.caller(f.adminA, f.orgA, "admin")

		code, body := e.do(as, http.MethodGet, "/api/v1/access/routes", "")
		if code != http.StatusOK || !strings.Contains(body, f.routeA) {
			t.Fatalf("list routes: %d %s", code, body)
		}
		if strings.Contains(body, f.routeB) {
			t.Error("the route list carried another organization's route")
		}
		if code, body := e.do(as, http.MethodGet, "/api/v1/access/routes/"+f.routeA, ""); code != http.StatusOK {
			t.Errorf("get route: %d %s", code, body)
		}
		if code, _ := e.do(as, http.MethodGet, "/api/v1/access/routes/"+f.routeB, ""); code != http.StatusNotFound {
			t.Errorf("get another organization's route: %d, want 404", code)
		}

		code, body = e.do(as, http.MethodPost, "/api/v1/access/routes",
			`{"name":"created-`+f.suffix+`","from_url":"https://created-`+f.suffix+`.example.test","to_url":"http://127.0.0.1:2/"}`)
		if code != http.StatusCreated || routeCount("created-"+f.suffix) != 1 {
			t.Errorf("create route: %d %s", code, body)
		}

		if code, body := e.do(as, http.MethodPut, "/api/v1/access/routes/"+f.routeA, `{"to_url":"http://127.0.0.1:3/"}`); code != http.StatusOK {
			t.Errorf("update route: %d %s", code, body)
		}
		if got := route(f.routeA).toURL; got != "http://127.0.0.1:3/" {
			t.Errorf("an admitted update did not land: to_url=%q", got)
		}
		e.do(as, http.MethodPut, "/api/v1/access/routes/"+f.routeB, `{"to_url":"http://127.0.0.1:4/"}`)
		if got := route(f.routeB).toURL; got != f.upstreamB {
			t.Errorf("an admin changed another organization's route: to_url=%q", got)
		}

		code, body = e.do(as, http.MethodGet, "/api/v1/access/sessions", "")
		if code != http.StatusOK || !strings.Contains(body, f.userSessionA) || !strings.Contains(body, f.adminSessionA) {
			t.Fatalf("list sessions: %d %s", code, body)
		}
		if strings.Contains(body, f.sessionB) {
			t.Error("the session list carried another organization's session")
		}
		if code, body := e.do(as, http.MethodDelete, "/api/v1/access/sessions/"+f.userSessionA, ""); code != http.StatusOK || !revoked(f.userSessionA) {
			t.Errorf("revoke a user's session: %d %s, revoked=%v", code, body, revoked(f.userSessionA))
		}
		e.do(as, http.MethodDelete, "/api/v1/access/sessions/"+f.sessionB, "")
		if revoked(f.sessionB) {
			t.Error("an admin revoked another organization's session")
		}

		if code, _ := e.do(as, http.MethodDelete, "/api/v1/access/routes/"+f.routeB, ""); code != http.StatusNotFound {
			t.Errorf("delete another organization's route: %d, want 404", code)
		}
		if !route(f.routeB).exists {
			t.Error("an admin deleted another organization's route")
		}
		if code, body := e.do(as, http.MethodDelete, "/api/v1/access/routes/"+f.routeA, ""); code != http.StatusOK {
			t.Errorf("delete route: %d %s", code, body)
		}
		if route(f.routeA).exists {
			t.Error("an admitted delete left the route in place")
		}
	})
}

// The rest of the access surface that configures routes or reads their
// internals, and the kiosk and retention writes: each is refused to a caller
// without an admin role and admitted for admin and super_admin. What most
// admitted requests then do depends on components this fixture does not start
// (the feature manager, the Ziti controller), so for those the admitted half
// asserts that the gate let the request through; the writes this fixture can
// see -- the kiosk policy and the retention period -- are read back on both
// sides.
func TestRouteAdministrationNeedsTheAdminRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newAdminGateFixture(t)
	e := f.serve(t, f.db)

	var poolID string
	if err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO upstream_pools (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`,
		f.orgA, "pool-"+f.suffix).Scan(&poolID); err != nil {
		t.Fatalf("seed upstream pool: %v", err)
	}
	var kioskPolicy string
	if err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO kiosk_policies (name, mode, enabled, org_id) VALUES ($1, 'single_app', true, $2::uuid) RETURNING id::text`,
		"kiosk-"+f.suffix, f.orgA).Scan(&kioskPolicy); err != nil {
		t.Fatalf("seed kiosk policy: %v", err)
	}
	service := "/api/v1/access/services/" + f.routeA

	routes := []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/access/overview", ""},
		{http.MethodGet, "/api/v1/access/upstream-pools", ""},
		{http.MethodGet, "/api/v1/access/upstream-pools/" + poolID, ""},
		{http.MethodPost, "/api/v1/access/services/quick-create", `{"name":"qc-` + f.suffix + `","target_url":"http://127.0.0.1:5/","domain":"qc-` + f.suffix + `.example.test","require_auth":false}`},
		{http.MethodGet, "/api/v1/access/services/status", ""},
		{http.MethodGet, service + "/features", ""},
		{http.MethodGet, service + "/status", ""},
		{http.MethodGet, service + "/health", ""},
		{http.MethodPost, service + "/features/ziti/enable", "{}"},
		{http.MethodPost, service + "/features/ziti/disable", ""},
		{http.MethodPost, service + "/features/browzer/enable", "{}"},
		{http.MethodPost, service + "/features/browzer/disable", ""},
		{http.MethodPost, service + "/features/guacamole/enable", "{}"},
		{http.MethodPost, service + "/features/guacamole/disable", ""},
		{http.MethodPost, service + "/test-connection", "{}"},
		{http.MethodGet, service + "/test-history", ""},
		{http.MethodGet, "/api/v1/access/ziti/discover", ""},
		{http.MethodPost, "/api/v1/access/ziti/import", `{"ziti_id":"svc-` + f.suffix + `"}`},
		{http.MethodPost, "/api/v1/access/ziti/import/bulk", `{"ziti_ids":["svc-` + f.suffix + `"]}`},
		{http.MethodGet, "/api/v1/access/ziti/unmanaged/count", ""},
		{http.MethodPost, "/api/v1/access/audit/unified/sync", ""},
		{http.MethodPost, "/api/v1/access/kiosk/policies", `{"name":"kiosk-new-` + f.suffix + `","mode":"single_app"}`},
		{http.MethodPut, "/api/v1/access/kiosk/policies/" + kioskPolicy, `{"name":"kiosk-renamed-` + f.suffix + `","mode":"single_app"}`},
		{http.MethodPost, "/api/v1/access/kiosk/policies/" + kioskPolicy + "/assignments", `{"target_kind":"agent","target_id":"agent-` + f.suffix + `"}`},
		{http.MethodDelete, "/api/v1/access/kiosk/assignments/00000000-0000-0000-0000-00000000dead", ""},
		{http.MethodDelete, "/api/v1/access/kiosk/policies/" + kioskPolicy, ""},
		{http.MethodPut, "/api/v1/access/recording-retention-policy", `{"retention_days":1}`},
	}

	// What the writes can change, read back after each side.
	type written struct {
		policyName            string
		policyExists          bool
		assignments, created  int
		quickCreated, periods int
	}
	readBack := func() written {
		t.Helper()
		var w written
		var name *string
		if err := f.db.Pool.QueryRow(f.ctx, `
			SELECT (SELECT name FROM kiosk_policies WHERE id = $1::uuid),
			       (SELECT COUNT(*) FROM kiosk_policy_assignments WHERE target_id = $2),
			       (SELECT COUNT(*) FROM kiosk_policies WHERE name = $3),
			       (SELECT COUNT(*) FROM proxy_routes WHERE name = $4),
			       (SELECT COUNT(*) FROM recording_retention_policies WHERE org_id = $5::uuid)`,
			kioskPolicy, "agent-"+f.suffix, "kiosk-new-"+f.suffix, "qc-"+f.suffix, f.orgA,
		).Scan(&name, &w.assignments, &w.created, &w.quickCreated, &w.periods); err != nil {
			t.Fatalf("read back the writes: %v", err)
		}
		if name != nil {
			w.policyExists, w.policyName = true, *name
		}
		return w
	}

	for _, who := range []struct{ name, key string }{
		{"a plain user", e.caller(f.userA, f.orgA, "user")},
		{"an operator", e.caller(f.operatorA, f.orgA, "operator")},
	} {
		for _, rq := range routes {
			code, body := e.do(who.key, rq.method, rq.path, rq.body)
			if code != http.StatusForbidden || !strings.Contains(body, "admin access required") {
				t.Errorf("%s %s as %s: %d %s, want 403 admin access required", rq.method, rq.path, who.name, code, body)
			}
		}
	}
	if w := readBack(); w != (written{policyName: "kiosk-" + f.suffix, policyExists: true}) {
		t.Errorf("refused writes changed something: %+v", w)
	}

	for _, who := range []struct{ name, key string }{
		{"an admin", e.caller(f.adminA, f.orgA, "admin")},
		{"a super_admin", e.caller(f.superA, f.orgA, "super_admin")},
	} {
		for _, rq := range routes {
			code, body := e.do(who.key, rq.method, rq.path, rq.body)
			if code == http.StatusForbidden && strings.Contains(body, "admin access required") {
				t.Errorf("%s %s as %s was refused by the admin gate: %s", rq.method, rq.path, who.name, body)
			}
		}
	}
	// The kiosk writes ran in order -- create, rename, assign, delete -- and
	// the retention period was set.
	if w := readBack(); w.policyExists || w.created == 0 || w.periods != 1 {
		t.Errorf("admitted writes did not land: %+v", w)
	}

	// The kiosk and retention reads stay behind authentication alone, as
	// decided where those routes are registered: they grant nothing.
	for _, path := range []string{"/api/v1/access/kiosk/policies", "/api/v1/access/recording-retention-policy"} {
		if code, body := e.do(e.caller(f.userA, f.orgA, "user"), http.MethodGet, path, ""); code != http.StatusOK {
			t.Errorf("GET %s as a plain user: %d %s; this read is not gated", path, code, body)
		}
	}
}

// THE SAME ROUTES UNDER THE BELT THEY RUN BEHIND IN PRODUCTION.
//
// The tests above connect as the database's superuser, which ignores row-level
// security, so the organization scoping they see is the handlers' own
// predicates. This one serves the route table from a pool connected as an
// ordinary member of openidx_app -- the runtime role -- with the production
// checkout hook, so FORCE'd RLS applies as well: an admin of one organization
// lists, reads, changes, deletes and revokes nothing of another's.
func TestRouteAndSessionAPIsStayInsideTheOrganization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newAdminGateFixture(t)
	appDB := f.connectAsAppRole(t)

	// Vacuity: the belt must be on for this role, or everything below would
	// pass on the handlers' predicates alone.
	var visible int
	if err := appDB.Pool.QueryRow(orgctx.With(context.Background(), orgctx.Org{ID: f.orgA}),
		`SELECT COUNT(*) FROM proxy_routes WHERE id = $1::uuid`, f.routeB).Scan(&visible); err != nil {
		t.Fatalf("scoped read: %v", err)
	}
	if visible != 0 {
		t.Fatal("a read scoped to one organization saw another's route; RLS is not in force for this role, so this test would prove nothing")
	}

	e := f.serve(t, appDB)
	adminA := e.caller(f.adminA, f.orgA, "admin")
	adminB := e.caller(f.adminB, f.orgB, "admin")

	code, body := e.do(adminA, http.MethodGet, "/api/v1/access/routes", "")
	if code != http.StatusOK || !strings.Contains(body, f.routeA) || strings.Contains(body, f.routeB) {
		t.Fatalf("list routes as the first organization's admin: %d %s", code, body)
	}
	code, body = e.do(adminB, http.MethodGet, "/api/v1/access/routes", "")
	if code != http.StatusOK || !strings.Contains(body, f.routeB) || strings.Contains(body, f.routeA) {
		t.Fatalf("list routes as the second organization's admin: %d %s", code, body)
	}
	for _, rq := range []struct {
		method, path, body string
		want               int
	}{
		{http.MethodGet, "/api/v1/access/routes/" + f.routeB, "", http.StatusNotFound},
		{http.MethodPut, "/api/v1/access/routes/" + f.routeB, `{"to_url":"http://127.0.0.1:4/","require_auth":false}`, http.StatusNotFound},
		{http.MethodDelete, "/api/v1/access/routes/" + f.routeB, "", http.StatusNotFound},
	} {
		if code, body := e.do(adminA, rq.method, rq.path, rq.body); code != rq.want {
			t.Errorf("%s %s as another organization's admin: %d %s, want %d", rq.method, rq.path, code, body, rq.want)
		}
	}
	var toURL string
	var requireAuth bool
	if err := f.db.Pool.QueryRow(f.ctx, `SELECT to_url, require_auth FROM proxy_routes WHERE id = $1::uuid`, f.routeB).
		Scan(&toURL, &requireAuth); err != nil || toURL != f.upstreamB || !requireAuth {
		t.Errorf("another organization's route changed: to_url=%q require_auth=%v err=%v", toURL, requireAuth, err)
	}

	code, body = e.do(adminA, http.MethodGet, "/api/v1/access/sessions", "")
	if code != http.StatusOK || !strings.Contains(body, f.userSessionA) || strings.Contains(body, f.sessionB) {
		t.Fatalf("list sessions as the first organization's admin: %d %s", code, body)
	}
	e.do(adminA, http.MethodDelete, "/api/v1/access/sessions/"+f.sessionB, "")
	var revoked bool
	if err := f.db.Pool.QueryRow(f.ctx, `SELECT revoked FROM proxy_sessions WHERE id = $1::uuid`, f.sessionB).Scan(&revoked); err != nil || revoked {
		t.Errorf("another organization's session was revoked (revoked=%v err=%v)", revoked, err)
	}
}

// adminGateFixture is two organizations, each with a route and live proxy
// sessions, and the users who call the access service's real route table.
type adminGateFixture struct {
	ctx                                   context.Context
	db                                    *database.PostgresDB
	suffix                                string
	orgA, orgB                            string
	adminA, superA, operatorA, userA      string
	adminB                                string
	routeA, routeB                        string
	upstreamA, upstreamB                  string
	userSessionA, adminSessionA, sessionB string
}

func newAdminGateFixture(t *testing.T) *adminGateFixture {
	t.Helper()
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := orgctx.WithBypassRLS(context.Background())
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	f := &adminGateFixture{ctx: ctx, db: db, suffix: fmt.Sprintf("%d", time.Now().UnixNano()), orgA: middleware.DefaultOrgID}
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "tenant-"+f.suffix).Scan(&f.orgB); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	seedUser := func(org, name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+f.suffix, name+"-"+f.suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	f.adminA = seedUser(f.orgA, "admin-a")
	f.superA = seedUser(f.orgA, "super-a")
	f.operatorA = seedUser(f.orgA, "operator-a")
	f.userA = seedUser(f.orgA, "user-a")
	f.adminB = seedUser(f.orgB, "admin-b")

	seedRoute := func(org, name, upstream string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO proxy_routes (org_id, name, from_url, to_url, require_auth)
			VALUES ($1::uuid, $2, $3, $4, true) RETURNING id::text`,
			org, name+"-"+f.suffix, "https://"+name+"-"+f.suffix+".example.test", upstream).Scan(&id); err != nil {
			t.Fatalf("seed route %s: %v", name, err)
		}
		return id
	}
	// Closed loopback ports: the connection test and the health check an
	// admitted admin runs are refused at once instead of waiting out a dial
	// timeout.
	f.upstreamA, f.upstreamB = "http://127.0.0.1:9/", "http://127.0.0.1:19/"
	f.routeA = seedRoute(f.orgA, "route-a", f.upstreamA)
	f.routeB = seedRoute(f.orgB, "route-b", f.upstreamB)

	seedSession := func(org, user, route string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO proxy_sessions (org_id, user_id, route_id, session_token, ip_address, user_agent, expires_at)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4, '203.0.113.7', 'test', NOW() + INTERVAL '1 hour')
			RETURNING id::text`,
			org, user, route, "tok-"+user+"-"+f.suffix).Scan(&id); err != nil {
			t.Fatalf("seed session: %v", err)
		}
		return id
	}
	f.userSessionA = seedSession(f.orgA, f.userA, f.routeA)
	f.adminSessionA = seedSession(f.orgA, f.adminA, f.routeA)
	f.sessionB = seedSession(f.orgB, f.adminB, f.routeB)
	return f
}

// connectAsAppRole returns a pool connected as a fresh login role that is a
// member of openidx_app and nothing more. Roles are cluster-wide, so the name
// is unique to this run and the role is dropped afterwards.
func (f *adminGateFixture) connectAsAppRole(t *testing.T) *database.PostgresDB {
	t.Helper()
	role, password := "route_gate_"+f.suffix, "pw_"+f.suffix
	if _, err := f.db.Pool.Exec(f.ctx, fmt.Sprintf(
		`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOBYPASSRLS IN ROLE openidx_app`, role, password)); err != nil {
		t.Skipf("cannot create a non-superuser role to test RLS with (%v); the handlers' own scoping is covered by TestRouteAndSessionAPIsNeedTheAdminRole", err)
	}
	t.Cleanup(func() { _, _ = f.db.Pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+role) })

	appURL, err := url.Parse(f.db.Pool.Raw().Config().ConnString())
	if err != nil {
		t.Fatalf("parse test DSN: %v", err)
	}
	appURL.User = url.UserPassword(role, password)
	appDB, err := database.NewPostgres(appURL.String())
	if err != nil {
		t.Fatalf("connect as the non-superuser role: %v", err)
	}
	t.Cleanup(func() { _ = appDB.Close() })
	return appDB
}

// adminGateEngine is the access service's route table over one database, and
// the callers a request can be made as: the stand-in for the bearer auth reads
// the caller from a header only this test sets.
type adminGateEngine struct {
	r       *gin.Engine
	callers map[string]adminGateCaller
}

type adminGateCaller struct {
	user, org string
	roles     []string
}

func (f *adminGateFixture) serve(t *testing.T, db *database.PostgresDB) *adminGateEngine {
	t.Helper()
	mini := miniredis.RunT(t)
	rc := goredis.NewClient(&goredis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	svc := NewService(db, &database.RedisClient{Client: rc}, &config.Config{Environment: "production"}, zap.NewNop())

	e := &adminGateEngine{r: gin.New(), callers: map[string]adminGateCaller{}}
	RegisterRoutes(e.r, svc, func(c *gin.Context) {
		cl := e.callers[c.GetHeader("X-Test-Caller")]
		c.Set("user_id", cl.user)
		c.Set("org_id", cl.org)
		c.Set("roles", cl.roles)
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: cl.org}))
		c.Next()
	})
	return e
}

func (e *adminGateEngine) caller(user, org string, roles ...string) string {
	key := user + "/" + strings.Join(roles, ",")
	e.callers[key] = adminGateCaller{user: user, org: org, roles: roles}
	return key
}

func (e *adminGateEngine) do(callerKey, method, path, body string) (int, string) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Caller", callerKey)
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}
