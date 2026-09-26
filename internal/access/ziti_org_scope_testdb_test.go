package access

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
	"github.com/openidx/openidx/internal/organization"
)

// THE OPENZITI API, DRIVEN AS CMD/ACCESS-SERVICE SERVES IT.
//
// One controller serves every organization, and its objects carry no tenant.
// These tests put two organizations' objects on one fake controller -- and
// some that no organization owns -- and call the access service's real route
// table through the chain cmd/access-service mounts: the tenant resolver, then
// AuthWithAPIKey over a JWKS, with access tokens signed for each caller. The
// callers are a plain user, an operator and the administrator of the default
// organization (who administers the install), and an operator, an admin and
// a super_admin of a second organization, whose requests name it with
// X-Org-Slug as the console does.

// zitiScopeKey signs every token in these tests. Generating it is the slowest
// step, so it is made once.
var zitiScopeKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

// zitiScopeKid names the key in the JWKS. The verifier caches keys by kid for
// the whole process, so no other test signs under this one.
const zitiScopeKid = "access-ziti-org-scope"

// zitiScopeFixture is the install: two organizations, their users, their
// mirror rows, and the controller that holds both organizations' objects.
type zitiScopeFixture struct {
	t      *testing.T
	ctx    context.Context
	db     *database.PostgresDB
	sfx    string
	orgB   orgctx.Org
	users  map[string]string // caller name -> user id
	stub   *zitiStub
	svc    *Service
	router *gin.Engine
	jwks   string

	// What each organization owns, as the controller names it.
	svcA, svcB, svcInstall    string // service names
	zsA, zsB, zsInstall       string // service ids
	ziA, ziB                  string // identity ids
	zpA, zpB, zpInstall       string // policy ids
	hostA, hostB, hostInstall string // the internal addresses behind them
}

// zitiCaller is one signed-in caller: a token and the organization the request
// names, when it is not the default one.
type zitiCaller struct {
	name   string
	bearer string
	slug   string
}

func newZitiScopeFixture(t *testing.T) *zitiScopeFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := orgctx.WithBypassRLS(context.Background())
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	f := &zitiScopeFixture{
		t: t, ctx: ctx, db: db, sfx: sfx, users: map[string]string{},
		svcA: "svc-a-" + sfx, svcB: "svc-b-" + sfx, svcInstall: "infra-" + sfx,
		zsA: "zs-a-" + sfx, zsB: "zs-b-" + sfx, zsInstall: "zs-install-" + sfx,
		ziA: "zi-a-" + sfx, ziB: "zi-b-" + sfx,
		zpA: "zp-a-" + sfx, zpB: "zp-b-" + sfx, zpInstall: "zp-install-" + sfx,
		hostA: "192.0.2.10", hostB: "198.51.100.20", hostInstall: "203.0.113.30",
	}
	f.orgB = orgctx.Org{Slug: "zitiscope-b-" + sfx}
	if err := db.Pool.QueryRow(ctx, `INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`,
		f.orgB.Slug).Scan(&f.orgB.ID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	for name, org := range map[string]string{
		"userA": middleware.DefaultOrgID, "operatorA": middleware.DefaultOrgID, "adminA": middleware.DefaultOrgID,
		"userB": f.orgB.ID, "operatorB": f.orgB.ID, "adminB": f.orgB.ID, "superB": f.orgB.ID,
	} {
		var id string
		if err := db.Pool.QueryRow(ctx, `INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+sfx, name+"-"+sfx+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		f.users[name] = id
	}

	// The mirror: which organization owns which controller object.
	f.exec(`INSERT INTO ziti_services (ziti_id, name, host, port, org_id) VALUES
		($1, $2, $3, 8443, $7::uuid), ($4, $5, $6, 22, $8::uuid)`,
		f.zsA, f.svcA, f.hostA, f.zsB, f.svcB, f.hostB, middleware.DefaultOrgID, f.orgB.ID)
	f.exec(`INSERT INTO ziti_identities (ziti_id, name, user_id, org_id) VALUES
		($1, $2::text, $2::uuid, $5::uuid), ($3, $4::text, $4::uuid, $6::uuid)`,
		f.ziA, f.users["userA"], f.ziB, f.users["userB"], middleware.DefaultOrgID, f.orgB.ID)
	f.exec(`INSERT INTO ziti_service_policies (ziti_id, name, policy_type, org_id) VALUES
		($1, $2, 'Dial', $5::uuid), ($3, $4, 'Dial', $6::uuid)`,
		f.zpA, "pol-a-"+sfx, f.zpB, "pol-b-"+sfx, middleware.DefaultOrgID, f.orgB.ID)
	f.exec(`INSERT INTO posture_checks (ziti_id, name, check_type, remediation_hint, org_id) VALUES
		('pc-a-'||$5, $1, 'OS', '', $3::uuid), ('pc-b-'||$5, $2, 'OS', '', $4::uuid)`,
		"posture-a-"+sfx, "posture-b-"+sfx, middleware.DefaultOrgID, f.orgB.ID, sfx)
	f.exec(`INSERT INTO ziti_certificates (name, cert_type, subject, issuer, serial_number, fingerprint, not_after, org_id)
		VALUES ($1, 'identity', 'CN=a', 'CN=ca', '1', 'fp-a', NOW() + INTERVAL '5 days', $3::uuid),
		       ($2, 'identity', 'CN=b', 'CN=ca', '2', 'fp-b', NOW() + INTERVAL '5 days', $4::uuid)`,
		"cert-a-"+sfx, "cert-b-"+sfx, middleware.DefaultOrgID, f.orgB.ID)
	f.exec(`INSERT INTO policy_sync_state (governance_policy_id, ziti_policy_id, sync_type, status, last_error)
		VALUES (gen_random_uuid(), 'synced-'||$1, 'service_policy', 'error', 'refused')`, sfx)
	f.exec(`INSERT INTO ziti_user_sync (status, users_synced, users_failed, groups_synced) VALUES ('idle', 4242, 17, 99)`)
	f.exec(`INSERT INTO ziti_metrics (metric_type, source, value) VALUES ('health.services_count', 'metric-'||$1, 3)`, sfx)
	f.exec(`INSERT INTO ziti_ai_anomalies (identity_id, identity_name, anomaly_type) VALUES ($1, 'anomaly-'||$2, 'new_service')`, f.ziB, sfx)

	f.stub = newZitiStub(t)
	f.serveController()
	f.jwks = zitiScopeJWKS(t)

	mini := miniredis.RunT(t)
	rc := goredis.NewClient(&goredis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	redis := &database.RedisClient{Client: rc}
	cfg := &config.Config{Environment: "production"}
	f.svc = NewService(db, redis, cfg, zap.NewNop())
	f.svc.SetAuditService(NewUnifiedAuditService(db, zap.NewNop()))
	zm := zitiManagerAgainst(t, f.stub, db)
	// Discovery refuses a manager that never connected; this one stands for
	// a connected one.
	zm.initialized = true
	f.svc.SetZitiManager(zm)

	f.router = gin.New()
	f.router.Use(middleware.TenantResolver(
		organization.NewOrgLookup(organization.NewService(db, redis, cfg, zap.NewNop())),
		middleware.TenantResolverConfig{
			DefaultOrgFallback:     true,
			DefaultOrgID:           middleware.DefaultOrgID,
			PlatformAdminPredicate: auth.SuperAdminPredicate,
			Logger:                 zap.NewNop(),
		}))
	RegisterRoutes(f.router, f.svc, middleware.AuthWithAPIKey(f.jwks, nil))
	return f
}

func (f *zitiScopeFixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Pool.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("seed: %v\n%s", err, sql)
	}
}

// scalar reads one value as text.
func (f *zitiScopeFixture) scalar(sql string, args ...any) string {
	f.t.Helper()
	var v string
	if err := f.db.Pool.QueryRow(f.ctx, sql, args...).Scan(&v); err != nil {
		f.t.Fatalf("read back: %v\n%s", err, sql)
	}
	return v
}

// serveController puts both organizations' objects, and the install's own,
// on the fake controller.
func (f *zitiScopeFixture) serveController() {
	list := func(items ...string) string { return `{"data":[` + strings.Join(items, ",") + `]}` }
	f.stub.ok("GET /edge/management/v1/version", `{"data":{"version":"v1.1.15"}}`)
	router := `{"id":"er-` + f.sfx + `","name":"edge-` + f.sfx + `","hostname":"router-` + f.sfx + `.internal.example","isOnline":true}`
	f.stub.ok("GET /edge/management/v1/edge-routers", list(router))
	f.stub.ok("GET /edge/management/v1/edge-routers/er-"+f.sfx, `{"data":`+router+`}`)
	f.stub.ok("GET /edge/management/v1/services", list(
		`{"id":"`+f.zsA+`","name":"`+f.svcA+`","configs":["cfg-a-host-`+f.sfx+`","cfg-a-int-`+f.sfx+`"]}`,
		`{"id":"`+f.zsB+`","name":"`+f.svcB+`","configs":["cfg-b-host-`+f.sfx+`"]}`,
		`{"id":"`+f.zsInstall+`","name":"`+f.svcInstall+`","configs":["cfg-install-`+f.sfx+`"]}`))
	f.stub.ok("GET /edge/management/v1/identities", list(
		`{"id":"`+f.ziA+`","name":"`+f.users["userA"]+`","type":"User"}`,
		`{"id":"`+f.ziB+`","name":"`+f.users["userB"]+`","type":"User"}`))
	f.stub.ok("GET /edge/management/v1/service-policies", list(
		`{"id":"`+f.zpA+`","name":"pol-a-`+f.sfx+`","type":"Dial","serviceRoles":["#`+f.svcA+`"],"identityRoles":["#all"]}`,
		`{"id":"`+f.zpB+`","name":"pol-b-`+f.sfx+`","type":"Dial","serviceRoles":["#`+f.svcB+`"],"identityRoles":["#all"]}`,
		`{"id":"`+f.zpInstall+`","name":"pol-install-`+f.sfx+`","type":"Bind","serviceRoles":["#`+f.svcInstall+`"],"identityRoles":["#routers"]}`))
	f.stub.ok("GET /edge/management/v1/edge-router-policies", list(`{"id":"erp-1","name":"erp-`+f.sfx+`"}`))
	f.stub.ok("GET /edge/management/v1/config-types", list(`{"id":"host.v1","name":"host.v1"}`))
	f.stub.ok("GET /edge/management/v1/configs", list(
		`{"id":"cfg-a-host-`+f.sfx+`","name":"`+f.svcA+`-host","configTypeId":"host.v1","data":{"address":"`+f.hostA+`","port":8443}}`,
		`{"id":"cfg-a-int-`+f.sfx+`","name":"`+f.svcA+`-intercept","configTypeId":"intercept.v1","data":{"addresses":["a.ziti"]}}`,
		`{"id":"cfg-b-host-`+f.sfx+`","name":"`+f.svcB+`-host","configTypeId":"host.v1","data":{"address":"`+f.hostB+`","port":22}}`,
		`{"id":"cfg-install-`+f.sfx+`","name":"`+f.svcInstall+`-host","configTypeId":"host.v1","data":{"address":"`+f.hostInstall+`","port":443}}`))
	terminator := func(id, svcID, svcName, host string) string {
		return `{"id":"` + id + `","serviceId":"` + svcID + `","service":{"id":"` + svcID + `","name":"` + svcName +
			`"},"routerId":"er-` + f.sfx + `","binding":"transport","address":"tcp:` + host + `:443"}`
	}
	termA := terminator("term-a-"+f.sfx, f.zsA, f.svcA, f.hostA)
	termB := terminator("term-b-"+f.sfx, f.zsB, f.svcB, f.hostB)
	termInstall := terminator("term-install-"+f.sfx, f.zsInstall, f.svcInstall, f.hostInstall)
	f.stub.ok("GET /edge/management/v1/terminators", list(termA, termB, termInstall))
	// An id the controller does not know is its 404, as for a real one, rather
	// than the list above.
	notFound := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"NOT_FOUND"}}`))
	}
	f.stub.on("GET /edge/management/v1/terminators/", notFound)
	f.stub.on("GET /edge/management/v1/sessions/", notFound)
	f.stub.ok("GET /edge/management/v1/terminators/term-a-"+f.sfx, `{"data":`+termA+`}`)
	f.stub.ok("GET /edge/management/v1/terminators/term-b-"+f.sfx, `{"data":`+termB+`}`)
	f.stub.ok("GET /edge/management/v1/terminators/term-install-"+f.sfx, `{"data":`+termInstall+`}`)
	f.stub.ok("GET /edge/management/v1/sessions", list(
		// A's identity dialing A's service, with the ends embedded.
		`{"id":"sess-aa-`+f.sfx+`","type":"Dial","identity":{"id":"`+f.ziA+`","name":"a"},"service":{"id":"`+f.zsA+`","name":"`+f.svcA+`"}}`,
		// B's identity dialing B's service, with the ends as bare ids.
		`{"id":"sess-bb-`+f.sfx+`","type":"Dial","identityId":"`+f.ziB+`","serviceId":"`+f.zsB+`"}`,
		// A's identity dialing B's service: one end each.
		`{"id":"sess-ab-`+f.sfx+`","type":"Dial","apiSession":{"identity":{"id":"`+f.ziA+`"}},"service":{"id":"`+f.zsB+`","name":"`+f.svcB+`"}}`,
		// An identity no organization owns hosting A's service.
		`{"id":"sess-bind-`+f.sfx+`","type":"Bind","identity":{"id":"zi-proxy-`+f.sfx+`","name":"access-proxy"},"service":{"id":"`+f.zsA+`","name":"`+f.svcA+`"}}`))
	f.stub.ok("GET /edge/management/v1/auth-policies", list(`{"id":"ap-1","name":"auth-`+f.sfx+`"}`))
	f.stub.ok("GET /edge/management/v1/external-jwt-signers", list(`{"id":"js-1","name":"signer-`+f.sfx+`","issuer":"https://issuer.example.test"}`))
}

// zitiScopeJWKS serves the public half of zitiScopeKey.
func zitiScopeJWKS(t *testing.T) string {
	t.Helper()
	pub := &zitiScopeKey.PublicKey
	jwks := middleware.JWKS{Keys: []middleware.JWKSKey{{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: zitiScopeKid,
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// caller signs an access token for one of the fixture's users, minted in their
// own organization, as the console holds it.
func (f *zitiScopeFixture) caller(name string, roles ...string) zitiCaller {
	f.t.Helper()
	org, slug := middleware.DefaultOrgID, ""
	if strings.HasSuffix(name, "B") {
		org, slug = f.orgB.ID, f.orgB.Slug
	}
	rs := make([]interface{}, len(roles))
	for i, r := range roles {
		rs[i] = r
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": f.users[name], "client_id": "admin-console", "roles": rs,
		middleware.OrgIDClaim: org, middleware.APIAccessClaim: true,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = zitiScopeKid
	tok.Header["typ"] = middleware.AccessTokenType
	signed, err := tok.SignedString(zitiScopeKey)
	if err != nil {
		f.t.Fatalf("sign: %v", err)
	}
	return zitiCaller{name: name + " " + strings.Join(roles, "+"), bearer: signed, slug: slug}
}

func (f *zitiScopeFixture) do(cl zitiCaller, method, path, body string) (int, string) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+cl.bearer)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cl.slug != "" {
		req.Header.Set("X-Org-Slug", cl.slug)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// THE ORGANIZATION'S OWN PART OF THE FABRIC.
//
// Each read below relays the controller or describes the organization's
// fabric. A plain user of either organization is refused with 403. An
// operator sees their own organization's objects and nothing of the other's or
// of the install's own; the other organization's operator, admin and
// super_admin the same, the other way round. The administrator of the default
// organization administers the install and sees every organization's objects.
// A marker is the thing an answer carrying the object would show: a name, an
// id, or the internal address behind it.
func TestTheOpenZitiReadsShowAnOrganizationOnlyItsOwnFabric(t *testing.T) {
	f := newZitiScopeFixture(t)
	a, b, install := "A", "B", "install"
	type read struct {
		path string
		// relayed reads the controller, or install-wide state, and shows the
		// install administrator all of it. The others read the organization's
		// own rows, and the install administrator sees the organization the
		// request resolved to, as everyone does.
		relayed bool
		markers map[string][]string // owner -> what an answer carrying its objects shows
	}
	reads := []read{
		{"/api/v1/access/ziti/services", false, map[string][]string{a: {f.svcA, f.hostA}, b: {f.svcB, f.hostB}}},
		{"/api/v1/access/ziti/fabric/service-policies", true, map[string][]string{
			a: {"pol-a-" + f.sfx}, b: {"pol-b-" + f.sfx}, install: {"pol-install-" + f.sfx}}},
		{"/api/v1/access/ziti/configs", true, map[string][]string{
			a: {f.svcA + "-host", f.hostA, f.svcA + "-intercept"}, b: {f.svcB + "-host", f.hostB},
			install: {f.svcInstall + "-host", f.hostInstall}}},
		{"/api/v1/access/ziti/terminators", true, map[string][]string{
			a: {"term-a-" + f.sfx, f.hostA}, b: {"term-b-" + f.sfx, f.hostB}, install: {"term-install-" + f.sfx, f.hostInstall}}},
		{"/api/v1/access/ziti/sessions", true, map[string][]string{
			a: {"sess-aa-" + f.sfx}, b: {"sess-bb-" + f.sfx}, install: {"sess-ab-" + f.sfx, "sess-bind-" + f.sfx}}},
		{"/api/v1/access/ziti/posture/checks", false, map[string][]string{a: {"posture-a-" + f.sfx}, b: {"posture-b-" + f.sfx}}},
		{"/api/v1/access/ziti/certificates", false, map[string][]string{a: {"cert-a-" + f.sfx}, b: {"cert-b-" + f.sfx}}},
		{"/api/v1/access/ziti/certificates/expiry-alerts", false, map[string][]string{a: {"cert-a-" + f.sfx}, b: {"cert-b-" + f.sfx}}},
		// The routers name the hosts they run on and the metrics count every
		// organization's objects: in the overview, they are the install's.
		{"/api/v1/access/ziti/fabric/overview", true, map[string][]string{
			install: {"router-" + f.sfx + ".internal.example", "metric-" + f.sfx}}},
		{"/api/v1/access/ziti/fabric/health", true, nil},
		{"/api/v1/access/ziti/sync/status", true, map[string][]string{install: {"4242"}}},
		{"/api/v1/access/ziti/posture/summary", true, map[string][]string{install: {"total_policy_syncs"}}},
	}

	userA, userB := f.caller("userA", "user"), f.caller("userB", "user")
	for _, cl := range []zitiCaller{userA, userB} {
		for _, rd := range reads {
			if code, body := f.do(cl, http.MethodGet, rd.path, ""); code != http.StatusForbidden || !strings.Contains(body, "operator access required") {
				t.Errorf("GET %s as %s: %d %s, want 403 operator access required", rd.path, cl.name, code, body)
			}
		}
	}

	for _, v := range []struct {
		cl   zitiCaller
		sees map[string]bool
		all  bool // the install administrator: every owner on a relayed read
	}{
		{f.caller("operatorA", "operator"), map[string]bool{a: true}, false},
		{f.caller("operatorB", "operator"), map[string]bool{b: true}, false},
		{f.caller("adminB", "admin"), map[string]bool{b: true}, false},
		{f.caller("superB", "admin", "super_admin"), map[string]bool{b: true}, false},
		{f.caller("adminA", "admin"), map[string]bool{a: true}, true},
	} {
		for _, rd := range reads {
			code, body := f.do(v.cl, http.MethodGet, rd.path, "")
			if code != http.StatusOK {
				t.Errorf("GET %s as %s: %d %s, want 200", rd.path, v.cl.name, code, body)
				continue
			}
			for owner, markers := range rd.markers {
				want := v.sees[owner] || (v.all && rd.relayed)
				for _, m := range markers {
					if shows := strings.Contains(body, m); shows != want {
						t.Errorf("GET %s as %s: showing %s's %q = %v, want %v\n%s", rd.path, v.cl.name, owner, m, shows, want, body)
					}
				}
			}
		}
	}

	// The counts in the organization's view of the fabric are its own. B owns
	// one service, one identity and one policy; the controller holds three
	// services, two identities and three policies.
	for _, path := range []string{"/api/v1/access/ziti/fabric/overview", "/api/v1/access/ziti/fabric/health"} {
		_, body := f.do(f.caller("operatorB", "operator"), http.MethodGet, path, "")
		for _, want := range []string{`"services_count":1`, `"identities_count":1`, `"policies_count":1`, `"routers_online":1`} {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s as B's operator: want %s in %s", path, want, body)
			}
		}
		if _, body := f.do(f.caller("adminA", "admin"), http.MethodGet, path, ""); !strings.Contains(body, `"services_count":3`) {
			t.Errorf("GET %s as the install administrator: want the controller's 3 services in %s", path, body)
		}
	}
	// B has four enabled users, one of them with an identity.
	_, body := f.do(f.caller("operatorB", "operator"), http.MethodGet, "/api/v1/access/ziti/sync/status", "")
	for _, want := range []string{`"total_users":4`, `"total_identities":1`, `"unsynced_users":3`} {
		if !strings.Contains(body, want) {
			t.Errorf("sync status as B's operator: want %s in %s", want, body)
		}
	}
	for _, gone := range []string{"users_synced", "users_failed", "groups_synced"} {
		if strings.Contains(body, gone) {
			t.Errorf("sync status as B's operator carries the install's run counter %s: %s", gone, body)
		}
	}

	// One terminator by id: an organization's own, or the 404 an unknown id
	// gets, word for word, so the answer does not say which ids exist.
	for _, tc := range []struct {
		cl   zitiCaller
		term string
		want int
	}{
		{f.caller("operatorA", "operator"), "term-a-" + f.sfx, http.StatusOK},
		{f.caller("operatorA", "operator"), "term-b-" + f.sfx, http.StatusNotFound},
		{f.caller("operatorA", "operator"), "term-install-" + f.sfx, http.StatusNotFound},
		{f.caller("operatorA", "operator"), "term-none-" + f.sfx, http.StatusNotFound},
		{f.caller("adminB", "admin"), "term-a-" + f.sfx, http.StatusNotFound},
		{f.caller("adminB", "admin"), "term-b-" + f.sfx, http.StatusOK},
		{f.caller("adminA", "admin"), "term-b-" + f.sfx, http.StatusOK},
		{f.caller("adminA", "admin"), "term-install-" + f.sfx, http.StatusOK},
	} {
		code, body := f.do(tc.cl, http.MethodGet, "/api/v1/access/ziti/terminators/"+tc.term, "")
		if code != tc.want {
			t.Errorf("GET terminator %s as %s: %d %s, want %d", tc.term, tc.cl.name, code, body, tc.want)
		}
		if code == http.StatusNotFound && body != `{"error":"terminator not found"}` {
			t.Errorf("GET terminator %s as %s: the 404 says %s, want the unknown id's answer", tc.term, tc.cl.name, body)
		}
	}

	// Explaining a service walks the whole controller by its name, so an
	// organization's admin explains its own services only.
	for _, tc := range []struct {
		cl   zitiCaller
		name string
		want int
	}{
		{f.caller("adminB", "admin"), f.svcB, http.StatusOK},
		{f.caller("adminB", "admin"), f.svcA, http.StatusNotFound},
		{f.caller("adminB", "admin"), f.svcInstall, http.StatusNotFound},
		{f.caller("adminA", "admin"), f.svcB, http.StatusOK},
	} {
		code, body := f.do(tc.cl, http.MethodGet, "/api/v1/access/ziti/services/by-name/"+tc.name+"/explain", "")
		if code != tc.want {
			t.Errorf("explain %s as %s: %d %s, want %d", tc.name, tc.cl.name, code, body, tc.want)
		}
	}
}

// Testing a service's connectivity dials its upstream and answers with the
// dial errors, which name the address, so it is gated like the route
// connection test: a plain user and an operator are refused, and an admin
// tests their own organization's services only.
func TestTestingAZitiServiceNeedsAnAdmin(t *testing.T) {
	f := newZitiScopeFixture(t)
	// A closed local port: the dial fails at once.
	f.exec(`UPDATE ziti_services SET host = '127.0.0.1', port = 1 WHERE ziti_id = $1`, f.zsB)
	idA := f.scalar(`SELECT id::text FROM ziti_services WHERE ziti_id = $1`, f.zsA)
	idB := f.scalar(`SELECT id::text FROM ziti_services WHERE ziti_id = $1`, f.zsB)
	test := func(id string) string { return "/api/v1/access/ziti/services/" + id + "/test" }
	for _, cl := range []zitiCaller{f.caller("userB", "user"), f.caller("operatorB", "operator")} {
		if code, body := f.do(cl, http.MethodPost, test(idB), ""); code != http.StatusForbidden || !strings.Contains(body, "admin access required") {
			t.Errorf("test B's service as %s: %d %s, want 403 admin access required", cl.name, code, body)
		}
	}
	adminB := f.caller("adminB", "admin")
	if code, body := f.do(adminB, http.MethodPost, test(idA), ""); code != http.StatusNotFound {
		t.Errorf("test A's service as B's admin: %d %s, want 404", code, body)
	}
	if code, body := f.do(adminB, http.MethodPost, test(idB), ""); code != http.StatusOK || !strings.Contains(body, f.svcB) {
		t.Errorf("test B's service as B's admin: %d %s, want 200 with its result", code, body)
	}
}

// THE CONTROLLER'S OWN OBJECTS.
//
// The edge routers, their policies, the authentication policies and JWT
// signers, the config types, the controller's version, the reconciler's
// state, the metrics, the governance-policy syncs, the BrowZer bootstrapper,
// the AI ledger, the network setup, discovery and the PAM broker's bindings
// belong to no organization. Every caller but the administrator of the
// default organization is refused: a plain user and an operator by the admin
// gate, the other organization's admin and super_admin with "platform
// administrator required". The refused reads reach nothing on the controller.
func TestTheControllersOwnObjectsNeedAnInstallAdministrator(t *testing.T) {
	f := newZitiScopeFixture(t)
	routes := []struct {
		path       string
		controller string // what a relayed read would ask the controller for
		marker     string
	}{
		{"/api/v1/access/ziti/fabric/routers", "GET /edge/management/v1/edge-routers", "router-" + f.sfx + ".internal.example"},
		{"/api/v1/access/ziti/fabric/routers/er-" + f.sfx, "GET /edge/management/v1/edge-routers/", ""},
		{"/api/v1/access/ziti/fabric/metrics?type=health.services_count", "", "metric-" + f.sfx},
		{"/api/v1/access/ziti/edge-router-policies", "GET /edge/management/v1/edge-router-policies", "erp-" + f.sfx},
		{"/api/v1/access/ziti/config-types", "GET /edge/management/v1/config-types", "host.v1"},
		{"/api/v1/access/ziti/auth-policies", "GET /edge/management/v1/auth-policies", "auth-" + f.sfx},
		{"/api/v1/access/ziti/jwt-signers", "GET /edge/management/v1/external-jwt-signers", "signer-" + f.sfx},
		{"/api/v1/access/ziti/controller/features", "GET /edge/management/v1/version", "v1.1.15"},
		{"/api/v1/access/ziti/reconciler/status", "", ""},
		{"/api/v1/access/ziti/policy-sync", "", "synced-" + f.sfx},
		{"/api/v1/access/ziti/browzer/management", "", ""},
		{"/api/v1/access/ziti/ai/insights", "GET /edge/management/v1/identities", ""},
		{"/api/v1/access/ziti/ai/anomalies", "", "anomaly-" + f.sfx},
		{"/api/v1/access/ziti/ai/identity-risk", "GET /edge/management/v1/identities", f.ziB},
		{"/api/v1/access/ziti/ai/recommendations", "GET /edge/management/v1/service-policies", ""},
		{"/api/v1/access/ziti/setup/status", "GET /edge/management/v1/edge-routers", "router-" + f.sfx + ".internal.example"},
		{"/api/v1/access/ziti/discover", "GET /edge/management/v1/services", f.svcInstall},
		{"/api/v1/access/ziti/unmanaged/count", "GET /edge/management/v1/services", ""},
		{"/api/v1/access/pam/broker/ziti-bindings", "", ""},
	}

	for _, rq := range routes {
		f.stub.mu.Lock()
		f.stub.calls = nil
		f.stub.mu.Unlock()
		for _, refused := range []struct {
			cl   zitiCaller
			want string
		}{
			{f.caller("userA", "user"), "admin access required"},
			{f.caller("operatorA", "operator"), "admin access required"},
			{f.caller("operatorB", "operator"), "admin access required"},
			{f.caller("adminB", "admin"), middleware.PlatformAdminRequired},
			{f.caller("superB", "admin", "super_admin"), middleware.PlatformAdminRequired},
		} {
			code, body := f.do(refused.cl, http.MethodGet, rq.path, "")
			if code != http.StatusForbidden || !strings.Contains(body, refused.want) {
				t.Errorf("GET %s as %s: %d %s, want 403 %s", rq.path, refused.cl.name, code, body, refused.want)
			}
		}
		if rq.controller != "" && f.stub.saw(rq.controller) {
			t.Errorf("GET %s: a refused caller's request reached the controller: %v", rq.path, f.stub.received())
		}

		code, body := f.do(f.caller("adminA", "admin"), http.MethodGet, rq.path, "")
		if code == http.StatusForbidden || code >= http.StatusInternalServerError {
			t.Errorf("GET %s as the install administrator: %d %s", rq.path, code, body)
		}
		if rq.marker != "" && !strings.Contains(body, rq.marker) {
			t.Errorf("GET %s as the install administrator: want %q in %s", rq.path, rq.marker, body)
		}
	}

	// Discovery offers the install administrator the one service no
	// organization manages. B's service is B's, not one to import into the
	// organization the request resolved to.
	if _, body := f.do(f.caller("adminA", "admin"), http.MethodGet, "/api/v1/access/ziti/unmanaged/count", ""); !strings.Contains(body, `"count":1`) || !strings.Contains(body, `"managed":2`) {
		t.Errorf("unmanaged services as the install administrator: want 1 unmanaged and 2 managed in %s", body)
	}
}

// THE STATUS PROBES.
//
// Whether the overlay is up stays open to any signed-in user; what it says
// is the organization's: its own counts, and none of the install's addresses
// -- the controller's management endpoint and console, which the fake
// controller's own URL stands for here -- or the ids of the controller
// objects BrowZer's bootstrap created. The install administrator still gets
// them.
func TestTheZitiStatusProbesNameNothingOfTheInstall(t *testing.T) {
	f := newZitiScopeFixture(t)
	f.exec(`INSERT INTO ziti_browzer_config (enabled, external_jwt_signer_id, auth_policy_id, dial_policy_id)
		VALUES (true, $1, $2, $3)`, "signer-id-"+f.sfx, "auth-id-"+f.sfx, "dial-id-"+f.sfx)
	controller := strings.TrimPrefix(f.stub.URL, "http://")

	probes := []string{
		"/api/v1/access/ziti/status",
		"/api/v1/access/health/ziti",
		"/api/v1/access/health/integrations",
		"/api/v1/access/ziti/browzer/status",
	}
	for _, cl := range []zitiCaller{f.caller("userB", "user"), f.caller("adminB", "admin")} {
		for _, path := range probes {
			code, body := f.do(cl, http.MethodGet, path, "")
			if code != http.StatusOK {
				t.Errorf("GET %s as %s: %d %s, want 200", path, cl.name, code, body)
				continue
			}
			for _, leak := range []string{controller, "signer-id-" + f.sfx, "auth-id-" + f.sfx, `"services_count":3`} {
				if strings.Contains(body, leak) {
					t.Errorf("GET %s as %s carries %q: %s", path, cl.name, leak, body)
				}
			}
		}
		if _, body := f.do(cl, http.MethodGet, "/api/v1/access/ziti/status", ""); !strings.Contains(body, `"services_count":1`) ||
			!strings.Contains(body, `"controller_reachable":true`) {
			t.Errorf("ziti status as %s: want B's one service and a reachable controller: %s", cl.name, body)
		}
	}
	admin := f.caller("adminA", "admin")
	if _, body := f.do(admin, http.MethodGet, "/api/v1/access/ziti/status", ""); !strings.Contains(body, controller) {
		t.Errorf("ziti status as the install administrator: want the controller endpoints (%s) in %s", controller, body)
	}
	if _, body := f.do(admin, http.MethodGet, "/api/v1/access/ziti/browzer/status", ""); !strings.Contains(body, "signer-id-"+f.sfx) {
		t.Errorf("BrowZer status as the install administrator: want the signer id in %s", body)
	}

	// A controller that does not answer: its error names its address, which
	// only the install administrator is told.
	f.stub.Close()
	for _, path := range []string{"/api/v1/access/health/ziti", "/api/v1/access/ziti/status"} {
		if _, body := f.do(f.caller("userB", "user"), http.MethodGet, path, ""); strings.Contains(body, controller) {
			t.Errorf("GET %s as B's user with the controller down carries its address: %s", path, body)
		}
		if _, body := f.do(admin, http.MethodGet, path, ""); !strings.Contains(body, controller) {
			t.Errorf("GET %s as the install administrator with the controller down: want its address in %s", path, body)
		}
	}
}
