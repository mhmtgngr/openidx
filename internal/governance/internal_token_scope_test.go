package governance

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// WHAT THE INTERNAL SERVICE TOKEN CAN REACH, DERIVED FROM THE ROUTE TABLE.
//
// openIDXAuthMiddleware accepts a shared secret instead of a user JWT for the
// access-proxy's policy call, and its own comment states the bound: "Scoped to
// the evaluate endpoints ... so a leaked token can't drive user-facing
// governance operations." The scoping test was written against a router holding
// two hand-registered routes, so it could only ever check the two paths somebody
// thought of.
//
// This drives the SERVICE'S REAL ROUTE TABLE, and it crafts the paths rather
// than listing them: every static segment the table uses is tried in every
// parameter slot, and a request the token gets past the middleware must be
// served by a route that actually ends in /evaluate. That is the difference
// between "the paths I wrote end in /evaluate" and "nothing else does".
const internalTokenSecret = "s3cr3t-internal-token-for-the-scope-census"

func governanceRouteTable(t *testing.T) []gin.RouteInfo {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterRoutes(r, NewService(&database.PostgresDB{}, &database.RedisClient{},
		&config.Config{InternalServiceToken: internalTokenSecret}, zap.NewNop()))
	routes := r.Routes()
	if len(routes) < 40 {
		t.Fatalf("governance registered only %d routes; this census is checking almost "+
			"nothing", len(routes))
	}
	return routes
}

// internalTokenRouter puts the REAL middleware in front of the REAL route table
// with inert handlers, so what is measured is the middleware's decision and not
// a handler's behaviour against a nil database.
func internalTokenRouter(t *testing.T, routes []gin.RouteInfo) *gin.Engine {
	t.Helper()
	svc := NewService(&database.PostgresDB{}, &database.RedisClient{},
		&config.Config{InternalServiceToken: internalTokenSecret}, zap.NewNop())
	r := gin.New()
	g := r.Group("/api/v1/governance")
	g.Use(svc.openIDXAuthMiddleware())
	for _, ri := range routes {
		rest := strings.TrimPrefix(ri.Path, "/api/v1/governance")
		if rest == ri.Path {
			continue // registered outside the governance group
		}
		g.Handle(ri.Method, rest, func(c *gin.Context) { c.String(http.StatusOK, c.FullPath()) })
	}
	return r
}

func TestInternalTokenReachesOnlyEvaluateRoutes(t *testing.T) {
	routes := governanceRouteTable(t)
	router := internalTokenRouter(t, routes)

	vocabulary := map[string]bool{}
	for _, ri := range routes {
		for _, s := range strings.Split(ri.Path, "/") {
			if s == "" || strings.HasPrefix(s, ":") || strings.HasPrefix(s, "*") {
				continue
			}
			vocabulary[s] = true
		}
	}

	// Every concrete path worth trying: each route's own shape with a UUID in
	// every parameter slot, plus every static segment the table uses tried in
	// each slot -- which is how a caller reaches one route by writing another.
	type probe struct{ method, path string }
	var probes []probe
	seen := map[string]bool{}
	add := func(method, path string) {
		if !seen[method+path] {
			seen[method+path] = true
			probes = append(probes, probe{method, path})
		}
	}
	fill := func(segs []string) string {
		out := append([]string{}, segs...)
		for i, s := range out {
			if strings.HasPrefix(s, ":") || strings.HasPrefix(s, "*") {
				out[i] = "11111111-1111-1111-1111-111111111111"
			}
		}
		return strings.Join(out, "/")
	}
	for _, ri := range routes {
		segs := strings.Split(ri.Path, "/")
		add(ri.Method, fill(segs))
		for i, s := range segs {
			if !strings.HasPrefix(s, ":") && !strings.HasPrefix(s, "*") {
				continue
			}
			for candidate := range vocabulary {
				trial := append([]string{}, segs...)
				trial[i] = candidate
				add(ri.Method, fill(trial))
			}
		}
	}

	var escaped []string
	for _, p := range probes {
		req := httptest.NewRequest(p.method, p.path, nil)
		req.Header.Set("X-Internal-Token", internalTokenSecret)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code == http.StatusUnauthorized || w.Code == http.StatusNotFound {
			continue // refused, or nothing serves it
		}
		served := w.Body.String() // the handler echoes the matched template
		if !strings.HasSuffix(served, "/evaluate") {
			escaped = append(escaped, p.method+" "+p.path+"  ->  served by "+served)
		}
	}

	if len(escaped) > 0 {
		sort.Strings(escaped)
		t.Errorf("the internal service token authenticated %d request(s) that are NOT served "+
			"by an /evaluate route:\n  %s\n\nThe middleware's own comment scopes this "+
			"credential to the evaluate endpoints so a leaked token cannot drive user-facing "+
			"governance operations. It tests the suffix of c.Request.URL.Path -- the string "+
			"the caller wrote -- and gin backtracks from a static segment to a parameter, so "+
			"a path ending in \"/evaluate\" can be served by a route that does not. Test "+
			"c.FullPath() instead.", len(escaped), strings.Join(escaped, "\n  "))
	}

	// Vacuity guard: the census is worthless if the token opened nothing at all.
	opened := 0
	for _, ri := range routes {
		if strings.HasSuffix(ri.Path, "/evaluate") {
			opened++
		}
	}
	if opened == 0 {
		t.Fatal("no route ends in /evaluate, so this census proved nothing; the internal-token " +
			"branch is either dead or scoped to something else now")
	}
	t.Logf("internal token census: %d probes, %d /evaluate route(s) it may reach", len(probes), opened)
}
