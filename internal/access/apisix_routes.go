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

// apisixRoute is a single Admin API route object: PUT .../routes/<name> with body.
type apisixRoute struct {
	name string
	body []byte
}

// APISIXRouteOpts builds the route options from exported inputs (main.go wiring).
func APISIXRouteOpts(bootstrapperNode string, hopBasePort int, oidcCallbacks []string) apisixRouteOpts {
	return apisixRouteOpts{bootstrapperNode: bootstrapperNode, hopBasePort: hopBasePort, oidcCallbacks: oidcCallbacks}
}

var apisixSlugNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// apisixSlug turns a hostname into a stable, name-safe route slug.
func apisixSlug(host string) string {
	s := apisixSlugNonAlnum.ReplaceAllString(strings.ToLower(host), "-")
	return strings.Trim(s, "-")
}

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

// buildBrowZerAPISIXRoutes renders the Admin API route objects for the
// BrowZer-enabled routes: an overlay route -> bootstrapper for each, plus an OIDC
// form_post bypass route -> the hop for hop-mode routes. The overlay upstream sets
// the TLS SNI to the app vhost via pass_host=rewrite + upstream_host (the §3.1
// spike proved upstream.tls.sni is a no-op on APISIX 3.15.0).
func buildBrowZerAPISIXRoutes(routes []browzerRouteInfo, opts apisixRouteOpts) []apisixRoute {
	if opts.bootstrapperNode == "" {
		opts.bootstrapperNode = "127.0.0.1:8445"
	}
	if opts.hopBasePort == 0 {
		opts.hopBasePort = 8095
	}
	var hopNames []string
	for _, r := range routes {
		if r.hostingMode == HostingModeHop {
			hopNames = append(hopNames, r.serviceName)
		}
	}
	ports := assignHopPorts(hopNames, opts.hopBasePort)

	var out []apisixRoute
	seenHost := make(map[string]bool, len(routes))
	for _, r := range routes {
		if r.hostname == "" {
			continue
		}
		// One APISIX route per host: the route name is browzer-<host-slug>, so
		// same-host routes would otherwise overwrite each other on PUT (last
		// wins). queryBrowZerRoutes already dedups by host; this is a defensive
		// guard so the pure builder is collision-proof in isolation.
		if seenHost[r.hostname] {
			continue
		}
		seenHost[r.hostname] = true
		slug := apisixSlug(r.hostname)
		name := "browzer-" + slug

		overlay := map[string]interface{}{
			"name":             name,
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
		out = append(out, apisixRoute{name: name, body: body})

		if r.hostingMode == HostingModeHop && len(opts.oidcCallbacks) > 0 {
			oidcName := name + "-oidc"
			suffix := strings.Join(opts.oidcCallbacks, "|")
			oidc := map[string]interface{}{
				"name":     oidcName,
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
			out = append(out, apisixRoute{name: oidcName, body: body})
		}
	}
	return out
}
