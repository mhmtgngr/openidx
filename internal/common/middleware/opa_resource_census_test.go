package middleware_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/admin"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/opa"
	"github.com/openidx/openidx/internal/governance"
	"github.com/openidx/openidx/internal/notifications"
	"github.com/openidx/openidx/internal/organization"
	"github.com/openidx/openidx/internal/provisioning"
)

// WHAT OPA IS ACTUALLY ASKED, FOR EVERY ROUTE IT GUARDS.
//
// deployments/docker/opa/policies/authz.rego keys five rules on
// input.resource.type -- role_permissions[input.resource.type][input.method] and
// the user / session / event-report-review-statistic / report rules. The
// middleware derived that type from the request path's LAST SEGMENT, so
// /api/v1/identity/users/<uuid> asked OPA about a resource of type
// "3f2a...-...", which matches nothing. Every endpoint naming a specific object
// -- every read, update and delete of one thing -- fell outside the policy's
// role map without a word in any log.
//
// A unit test over hand-written paths could not see that, and did not: every
// case in opa_infer_test.go was a collection path. So this drives the REAL
// middleware over the REAL route tables of the three services that wire it
// (governance, provisioning, admin-api), with a stub OPA that records what it
// was asked, and checks the question rather than the answer.
//
// This is an external test package because those services import this one.

// regoResourceTypes are the resource types authz.rego keys a rule on. Each must
// be produced by at least one route the middleware guards, or the rule is a
// decision about a resource nobody can ask for. Read from the policy file:
//
//	authz.rego:118  input.resource.type == "user"
//	authz.rego:125  input.resource.type == "session"
//	authz.rego:133  input.resource.type in {"event", "report", "review", "statistic"}
//	authz.rego:140  input.resource.type == "report"
var regoResourceTypes = []string{"user", "session", "event", "report", "review", "statistic"}

// knownUnreachableRegoTypes are the rego resource types no guarded route can
// produce, with the reason. An entry is a recorded finding, not a waiver: the
// rule it names cannot fire today, and the test fails if a type here becomes
// reachable, so the entry cannot outlive the problem.
var knownUnreachableRegoTypes = map[string]string{
	"report": "the only /reports routes in the product are audit-service's " +
		"(internal/audit/service.go and reports.go), and audit-service does not wire " +
		"OPAAuthz -- only governance, provisioning and admin-api do. So authz.rego's two " +
		"auditor rules (\"Auditors can read audit events, reviews, and reports\" and " +
		"\"Auditors can create reports\") describe a service OPA never sees. Guard " +
		"audit-service or drop the rules; either way the policy should not read as though " +
		"reports are covered.",
}

func censusConfig() *config.Config {
	return &config.Config{Environment: "production"}
}

// opaGuardedTemplates returns every route template the three services put behind
// OPAAuthz, exactly where their main.go puts it.
func opaGuardedTemplates(t *testing.T) []gin.RouteInfo {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := &database.PostgresDB{}
	redis := &database.RedisClient{}
	cfg := censusConfig()
	log := zap.NewNop()
	noop := func(c *gin.Context) { c.Next() }

	// cmd/governance-service/main.go: RegisterRoutes(router, svc, opaMiddleware...)
	gov := gin.New()
	governance.RegisterRoutes(gov, governance.NewService(db, redis, cfg, log), noop)

	// cmd/provisioning-service/main.go: RegisterRoutes(router, svc, opaMiddleware...)
	prov := gin.New()
	provisioning.RegisterRoutes(prov, provisioning.NewService(db, redis, cfg, log), noop)

	// cmd/admin-api/main.go: v1 := router.Group("/api/v1"); v1.Use(OPAAuthz); then
	// admin, organization and notifications register on v1.
	adminAPI := gin.New()
	v1 := adminAPI.Group("/api/v1")
	v1.Use(noop)
	admin.RegisterRoutes(v1, admin.NewService(db, redis, cfg, log))
	organization.RegisterRoutes(v1, organization.NewService(db, redis, cfg, log))
	notifications.RegisterRoutes(v1, notifications.NewService(db, log))

	var all []gin.RouteInfo
	for _, e := range []*gin.Engine{gov, prov, adminAPI} {
		all = append(all, e.Routes()...)
	}
	return all
}

// censusRouter puts the REAL OPA middleware in front of the REAL templates with
// inert handlers. Each service's own auth middleware sits ABOVE OPAAuthz in
// production and would refuse every unauthenticated probe before OPA was
// consulted; what is under test here is the question OPA is asked for a route,
// so the route table is what this reproduces, not the credential chain.
func censusRouter(routes []gin.RouteInfo, mw gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(mw)
	registered := map[string]bool{}
	for _, ri := range routes {
		if registered[ri.Method+" "+ri.Path] {
			continue
		}
		registered[ri.Method+" "+ri.Path] = true
		r.Handle(ri.Method, ri.Path, func(c *gin.Context) { c.Status(http.StatusOK) })
	}
	return r
}

func TestOPAIsAskedAboutARealResourceTypeOnEveryGuardedRoute(t *testing.T) {
	// A stub OPA that records the input and allows everything, so the middleware
	// runs to completion and the census sees every route.
	var asked []opa.Input
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Input opa.Input `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		asked = append(asked, body.Input)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":{"allow":true}}`))
	}))
	defer stub.Close()

	mw := middleware.OPAAuthz(opa.NewClient(stub.URL, zap.NewNop()), zap.NewNop(), false)

	routes := opaGuardedTemplates(t)
	engine := censusRouter(routes, mw)

	type asking struct{ template, resourceType string }
	var askings []asking
	for _, ri := range routes {
		asked = asked[:0]
		w := httptest.NewRecorder()
		req := httptest.NewRequest(ri.Method, concreteFor(ri.Path), strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		engine.ServeHTTP(w, req)
		if len(asked) == 0 {
			t.Fatalf("OPA was not consulted for %s %s; the middleware is no longer being "+
				"reached, so this census would pass over silence", ri.Method, ri.Path)
		}
		askings = append(askings, asking{ri.Path, asked[len(asked)-1].Resource.Type})
	}

	if len(askings) < 100 {
		t.Fatalf("OPA was consulted for only %d route(s); the census is checking almost "+
			"nothing -- the middleware is probably no longer wired the way this test builds it",
			len(askings))
	}

	var bad []string
	produced := map[string]bool{}
	for _, a := range askings {
		produced[a.resourceType] = true
		switch {
		case a.resourceType == "":
			bad = append(bad, a.template+"  ->  (empty)")
		case strings.HasPrefix(a.resourceType, ":"), strings.HasPrefix(a.resourceType, "*"):
			bad = append(bad, a.template+"  ->  "+a.resourceType+" (a parameter NAME)")
		case looksLikeAnID(a.resourceType):
			bad = append(bad, a.template+"  ->  "+a.resourceType+" (a request VALUE)")
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		found := len(bad)
		if len(bad) > 25 {
			bad = append(bad[:25:25], fmt.Sprintf("... and %d more", found-25))
		}
		t.Errorf("OPA was asked about %d resource type(s) that no policy can match:\n  %s\n\n"+
			"input.resource.type must be a word authz.rego is written in. A value taken from "+
			"the request -- an id, a name, a parameter -- matches no rule, so every rule keyed "+
			"on resource type silently does not apply to that route.",
			found, strings.Join(bad, "\n  "))
	}

	var unreachable, recovered []string
	for _, want := range regoResourceTypes {
		_, known := knownUnreachableRegoTypes[want]
		switch {
		case !produced[want] && !known:
			unreachable = append(unreachable, want)
		case produced[want] && known:
			recovered = append(recovered, want)
		}
	}
	if len(unreachable) > 0 {
		t.Errorf("authz.rego keys a rule on resource type(s) that NO guarded route produces: "+
			"%s\n\nEither the rule is dead -- a decision about a resource nobody can ask for -- "+
			"or the middleware stopped producing that spelling. Both are worth knowing; neither "+
			"shows up as a denial. Fix it, or record it in knownUnreachableRegoTypes with the "+
			"reason.", strings.Join(unreachable, ", "))
	}
	if len(recovered) > 0 {
		sort.Strings(recovered)
		t.Errorf("knownUnreachableRegoTypes records %s as unreachable, but a guarded route now "+
			"produces it -- delete the entry so the register keeps meaning what it says",
			strings.Join(recovered, ", "))
	}
	for typ, why := range knownUnreachableRegoTypes {
		if len(strings.TrimSpace(why)) < 40 {
			t.Errorf("knownUnreachableRegoTypes[%q] has no real reason; an unreachable policy "+
				"rule recorded without one is a waiver, which is what this register exists not "+
				"to be", typ)
		}
	}

	t.Logf("OPA resource-type census: %d guarded route(s), %d distinct resource type(s), "+
		"%d of the %d types authz.rego keys on are reachable",
		len(askings), len(produced), len(regoResourceTypes)-len(unreachable), len(regoResourceTypes))
}

func concreteFor(template string) string {
	segs := strings.Split(template, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") || strings.HasPrefix(s, "*") {
			segs[i] = "11111111-1111-1111-1111-111111111111"
		}
	}
	return strings.Join(segs, "/")
}

// looksLikeAnID reports whether a resource type is really a value out of the
// request rather than a word. A kebab-case action segment ("mark-all-read") is
// a poor resource type but it IS part of the route; a UUID or a bare number can
// only have come from the caller.
func looksLikeAnID(s string) bool {
	if s == "" {
		return false
	}
	if isAllDigits(s) {
		return true
	}
	// 8-4-4-4-12 hex, which is every id this product mints.
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return false
	}
	for _, want := range []int{8, 4, 4, 4, 12} {
		if len(parts[0]) != want {
			return false
		}
		if strings.Trim(strings.ToLower(parts[0]), "0123456789abcdef") != "" {
			return false
		}
		parts = parts[1:]
	}
	return true
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
