package main

import (
	"fmt"
	"sort"
	"strings"
)

// The deployed edge router (APISIX) is what the admin console actually talks
// to: nginx sends /api/v1/ to it (deployments/docker/nginx/conf.d/openidx.tdv.org.conf)
// and it forwards each prefix to one service. CI has no edge router — the
// services are started directly on their ports — so probing a single base URL
// there answers 404 for every prefix that base does not happen to own, and the
// probe reports a wall of false negatives rather than shape mismatches.
//
// edgePrefixes mirrors deployments/apisix-edge/seed-edge-routes.sh. Longest
// prefix wins; "/api/" is the catch-all that sends everything else to admin-api,
// which is why the console can call /api/v1/ispm/... and /api/v1/privacy/...
// without a rule of their own. edge_test.go pins this against the seed script,
// so a route added there and not here fails a test instead of silently
// re-creating the wall of 404s.
var edgePrefixes = []struct {
	Prefix  string
	Service string
}{
	{"/api/v1/identity/", "identity"},
	{"/api/v1/governance/", "governance"},
	{"/api/v1/provisioning/", "provisioning"},
	{"/api/v1/audit/", "audit"},
	{"/api/v1/access/", "access"},
	{"/api/v1/oauth/", "oauth"},
	{"/api/v1/saml/", "oauth"},
	{"/api/", "admin"},
}

// localPorts are the ports each service listens on in the documented local
// stack (deployments/docker/docker-compose.yml and the CI smoke job).
var localPorts = map[string]int{
	"identity":     8001,
	"governance":   8002,
	"provisioning": 8003,
	"audit":        8004,
	"admin":        8005,
	"oauth":        8006,
	"access":       8007,
}

// serviceForPath returns the service key the edge router would forward path to,
// or "" when no rule matches (the console should not be calling it at all).
func serviceForPath(path string) string {
	best, bestLen := "", -1
	for _, r := range edgePrefixes {
		if strings.HasPrefix(path, r.Prefix) && len(r.Prefix) > bestLen {
			best, bestLen = r.Service, len(r.Prefix)
		}
	}
	return best
}

// localBases builds service key -> base URL for the documented local ports.
func localBases(host string) map[string]string {
	out := make(map[string]string, len(localPorts))
	for svc, port := range localPorts {
		out[svc] = fmt.Sprintf("http://%s:%d", host, port)
	}
	return out
}

// serviceKeys returns the service keys in a stable order, for reporting.
func serviceKeys() []string {
	keys := make([]string, 0, len(localPorts))
	for k := range localPorts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
