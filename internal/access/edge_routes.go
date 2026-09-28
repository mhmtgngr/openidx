package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// Rendering ordinary (non-BrowZer) routes into the edge, with pool support.
//
// The BrowZer reconciler renders its own routes because they all terminate at
// the bootstrapper. Everything else is a plain "this hostname goes to that
// backend" route, and that is where an upstream pool becomes meaningful: the
// single to_url grows into a weighted, health-checked set.
//
// Routes without a pool keep rendering exactly as before, from to_url. That is
// what makes pools opt-in and this change safe to run against a live edge.

// edgeRoute is one row of desired edge state.
type edgeRoute struct {
	id   string
	name string
	// host is the route's host as migration v211 stores it: from_url's host,
	// normalized by proxy_route_host(), and held by this route alone among
	// the enabled routes.
	host     string
	toURL    string
	poolID   string // empty when the route uses to_url
	priority int
	// requireAuth is the route's require_auth: its requests reach the pool
	// only through forward-auth.
	requireAuth bool
}

// upstreamFromToURL renders the pre-pool behaviour: a single node taken from
// to_url. Kept as its own function so the fallback path is explicit rather than
// an accident of an empty pool.
func upstreamFromToURL(raw string) (map[string]interface{}, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("route target %q is not a usable URL", raw)
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("route target %q has a bad port", raw)
	}
	return map[string]interface{}{
		"type":   "roundrobin",
		"scheme": scheme,
		"nodes":  map[string]interface{}{fmt.Sprintf("%s:%d", u.Hostname(), p): 1},
	}, nil
}

// buildEdgeRoute renders one route, using its pool when it has a usable one.
//
// A route that names a pool which cannot serve traffic (every member drained or
// disabled) falls back to to_url rather than rendering an empty upstream. The
// alternative would silently black-hole the route, which is a worse outcome
// than "the pool is not in effect yet".
//
// A pool-backed route is served by APISIX straight from the pool, not through
// the access proxy, so the edge is the only place its sign-in can be enforced.
// It was rendered with no plugin at all: linking a pool to a route that
// required sign-in made it public, together with its roles, groups, device
// trust and assignments. A route that requires sign-in now carries the
// forward-auth plugin every protected edge route carries, asking the access
// service's decide endpoint (forwardAuthURI) about each request, plus a route
// for /access/.auth/* on its host to the access service, where decide sends a
// browser to sign in. With no forward-auth endpoint configured such a route is
// not rendered at all: its host is then left to whatever else serves it.
// Every route, public or not, has every identity header removed from the
// caller's request before anything else runs; forward-auth then writes the
// ones decide answers.
func buildEdgeRoute(r edgeRoute, pools map[string]*UpstreamPool, forwardAuthURI string, logger *zap.Logger) ([]apisixRoute, error) {
	host := r.host
	if host == "" {
		return nil, fmt.Errorf("route %q has no host", r.name)
	}
	var auth *url.URL
	if r.requireAuth {
		u, err := forwardAuthEndpoint(forwardAuthURI)
		if err != nil {
			return nil, fmt.Errorf("route %q requires sign-in and %w", r.name, err)
		}
		auth = u
	}

	var upstream map[string]interface{}
	var err error
	if r.poolID != "" {
		if pool, ok := pools[r.poolID]; ok {
			scheme := "http"
			if u, perr := url.Parse(r.toURL); perr == nil && u.Scheme != "" {
				scheme = u.Scheme
			}
			upstream, err = pool.BuildUpstream(scheme, "", "")
			if err != nil && logger != nil {
				logger.Warn("upstream pool unusable; falling back to the route's single target",
					zap.String("route", r.name), zap.String("pool", pool.Name), zap.Error(err))
			}
		} else if logger != nil {
			logger.Warn("route names an unknown upstream pool; falling back to its single target",
				zap.String("route", r.name), zap.String("pool_id", r.poolID))
		}
	}
	if upstream == nil {
		upstream, err = upstreamFromToURL(r.toURL)
		if err != nil {
			return nil, err
		}
	}

	stripIdentity := map[string]interface{}{
		"headers": map[string]interface{}{"remove": namedIdentityHeaders()},
	}
	plugins := map[string]interface{}{"proxy-rewrite": stripIdentity}
	if auth != nil {
		plugins["forward-auth"] = map[string]interface{}{
			"uri":             auth.String(),
			"request_method":  "GET",
			"request_headers": []string{"Authorization", "Cookie"},
			// Each header listed here is taken from decide's answer and
			// replaces the caller's copy (see writeForwardAuthHeaders).
			"upstream_headers": []string{
				"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Name", "X-Forwarded-Roles",
				"X-Forwarded-Route", "X-Risk-Score", "Cookie", "Authorization",
			},
			"client_headers": []string{"Location", "Set-Cookie"},
		}
	}
	name := edgeRouteName(r.id)
	obj := map[string]interface{}{
		"name":             name,
		"hosts":            []string{host},
		"uri":              "/*",
		"priority":         r.priority,
		"enable_websocket": true,
		"plugins":          plugins,
		"upstream":         upstream,
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	out := []apisixRoute{{name: name, body: b}}
	if auth == nil {
		return out, nil
	}

	// The sign-in flow on the application's host reaches the access
	// service without forward-auth, which would otherwise answer every one
	// of its requests with a redirect back to itself.
	port := auth.Port()
	if port == "" {
		port = "80"
		if strings.EqualFold(auth.Scheme, "https") {
			port = "443"
		}
	}
	flow := map[string]interface{}{
		"name":     name + "-auth",
		"hosts":    []string{host},
		"uri":      "/access/.auth/*",
		"priority": r.priority + 1,
		"plugins":  map[string]interface{}{"proxy-rewrite": stripIdentity},
		"upstream": map[string]interface{}{
			"type":      "roundrobin",
			"scheme":    strings.ToLower(auth.Scheme),
			"pass_host": "pass",
			"nodes":     map[string]interface{}{net.JoinHostPort(auth.Hostname(), port): 1},
		},
	}
	fb, err := json.Marshal(flow)
	if err != nil {
		return nil, err
	}
	return append(out, apisixRoute{name: name + "-auth", body: fb}), nil
}

// forwardAuthEndpoint is the access service's decide endpoint as the edge
// reaches it (APISIX_FORWARD_AUTH_URI), or why there is none.
func forwardAuthEndpoint(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("no forward-auth endpoint is configured (APISIX_FORWARD_AUTH_URI)")
	}
	u, err := url.Parse(raw)
	if err != nil || (!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) || u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("the forward-auth endpoint APISIX_FORWARD_AUTH_URI is not an http(s) URL")
	}
	return u, nil
}

// edgeRouteName namespaces generated routes so a reconcile pass can tell its
// own objects apart from hand-made ones and never prune somebody else's. It is
// keyed by the route's id: route names are chosen per organization, and two
// organizations' routes of one name overwrote each other at the edge.
func edgeRouteName(routeID string) string {
	slug := apisixSlug(routeID)
	if slug == "" {
		slug = "unnamed"
	}
	return "oidx-route-" + slug
}

// queryEdgeRoutes reads the routes that should exist at the edge.
//
// BrowZer-enabled routes are excluded: they are rendered by the BrowZer
// reconciler, which points them at the bootstrapper instead of the backend.
func queryEdgeRoutes(ctx context.Context, db *database.PostgresDB) ([]edgeRoute, error) {
	rows, err := db.Pool.Query(ctx,
		//orgscope:ignore install-wide reconciler pass: renders desired edge state for every org into the shared data plane, mirroring queryBrowZerRoutes
		`SELECT id::text, name, host, to_url, COALESCE(upstream_pool_id::text, ''), COALESCE(priority, 0),
		        COALESCE(require_auth, true)
		 FROM proxy_routes
		 WHERE enabled = true
		   AND COALESCE(browzer_enabled, false) = false
		   AND host IS NOT NULL
		 ORDER BY priority DESC, name`)
	if err != nil {
		return nil, fmt.Errorf("query edge routes: %w", err)
	}
	defer rows.Close()

	// A route whose from_url names no host cannot be served by host, and has
	// none (host IS NULL): it is left out rather than failing the whole pass.
	var out []edgeRoute
	for rows.Next() {
		var r edgeRoute
		if err := rows.Scan(&r.id, &r.name, &r.host, &r.toURL, &r.poolID, &r.priority, &r.requireAuth); err != nil {
			return nil, fmt.Errorf("scan edge route: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// BuildEdgeRoutesForPools renders every pool-backed route.
//
// Only routes that actually name a pool are rendered here. Routes still on
// to_url are left to whatever already serves them, so enabling this path cannot
// disturb the existing edge configuration -- and since a route can only name a
// pool once an operator has created one and linked it, an install that has
// never used pools renders nothing here and sees no change at all.
//
// forwardAuthURI is the decide endpoint a route that requires sign-in is
// rendered with; a route that requires sign-in is not rendered without one.
func BuildEdgeRoutesForPools(ctx context.Context, db *database.PostgresDB, logger *zap.Logger, forwardAuthURI string) ([]apisixRoute, error) {
	pools, err := loadUpstreamPools(ctx, db)
	if err != nil {
		return nil, err
	}
	if len(pools) == 0 {
		return nil, nil
	}

	routes, err := queryEdgeRoutes(ctx, db)
	if err != nil {
		return nil, err
	}

	var out []apisixRoute
	for _, r := range routes {
		if r.poolID == "" {
			continue
		}
		objs, err := buildEdgeRoute(r, pools, forwardAuthURI, logger)
		if err != nil {
			if logger != nil {
				logger.Warn("skipping route that cannot be rendered",
					zap.String("route", r.name), zap.Error(err))
			}
			continue
		}
		out = append(out, objs...)
	}
	return out, nil
}
