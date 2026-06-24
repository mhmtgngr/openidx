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
// BrowZer-enabled routes: an overlay route -> bootstrapper for each, plus an OIDC
// form_post bypass route -> the hop for hop-mode routes. The overlay upstream sets
// the TLS SNI to the app vhost via pass_host=rewrite + upstream_host (the §3.1
// spike proved upstream.tls.sni is a no-op on APISIX 3.15.0).
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
