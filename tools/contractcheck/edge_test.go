package main

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

func TestServiceForPath(t *testing.T) {
	cases := map[string]string{
		"/api/v1/identity/users":       "identity",
		"/api/v1/governance/reviews":   "governance",
		"/api/v1/provisioning/targets": "provisioning",
		"/api/v1/audit/events":         "audit",
		"/api/v1/access/pam/sessions":  "access",
		"/api/v1/access/enroll":        "access",
		"/api/v1/oauth/clients":        "oauth",
		"/api/v1/saml/providers":       "oauth",
		// No rule of their own: the /api/ catch-all sends them to admin-api,
		// which is how the console reaches ISPM, privacy, analytics and the
		// rest without an edge route each.
		"/api/v1/ispm/findings":    "admin",
		"/api/v1/privacy/dsars":    "admin",
		"/api/v1/analytics/usage":  "admin",
		"/api/v1/social-providers": "admin",
		"/api/v1/vault/secrets":    "admin",
		// Not under /api at all.
		"/oauth/authorize":               "",
		"/downloads/agent-manifest.json": "",
	}
	for path, want := range cases {
		if got := serviceForPath(path); got != want {
			t.Errorf("serviceForPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestEveryServiceHasALocalPort(t *testing.T) {
	for _, r := range edgePrefixes {
		if _, ok := localPorts[r.Service]; !ok {
			t.Errorf("edge prefix %q names service %q, which has no local port", r.Prefix, r.Service)
		}
	}
	if len(serviceKeys()) != len(localPorts) {
		t.Fatalf("serviceKeys() lost entries: %v", serviceKeys())
	}
}

// seedRouteRe pulls (uri, upstream port) out of the APISIX seed script's
// `put <name> "{...\"uri\":\"/api/...\",...\"127.0.0.1:PORT\":1...}"` lines.
var seedRouteRe = regexp.MustCompile(`\\"uri\\":\\"(/api[^\\]*)\\".*?127\.0\.0\.1:(\d+)`)

// unmappedEdgeRoutes returns a message per /api route in the seed script whose
// (prefix -> service -> port) does not agree with edgePrefixes + localPorts.
func unmappedEdgeRoutes(script string) []string {
	byPort := map[int]string{}
	for svc, port := range localPorts {
		byPort[port] = svc
	}
	var problems []string
	for _, m := range seedRouteRe.FindAllStringSubmatch(script, -1) {
		uri, portStr := m[1], m[2]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		wantSvc, known := byPort[port]
		if !known {
			continue // an upstream this tool does not probe (Ziti, BrowZer, the SPA)
		}
		sample := uri
		if len(sample) > 0 && sample[len(sample)-1] == '*' {
			sample += "probe"
		}
		got := serviceForPath(sample)
		if got != wantSvc {
			problems = append(problems, uri+" -> "+got+" (edge sends it to "+wantSvc+" on :"+portStr+")")
		}
	}
	return problems
}

// The route map is a copy of something deployed elsewhere, so it can rot. This
// reads the seed script the edge router is actually configured from and fails
// when the two disagree — a new /api route there and not here would put the
// probe back to answering 404 and calling it "unverified".
func TestEdgeMapMatchesTheDeployedSeedScript(t *testing.T) {
	const seed = "../../deployments/apisix-edge/seed-edge-routes.sh"
	b, err := os.ReadFile(seed)
	if err != nil {
		t.Fatalf("cannot read %s: %v", seed, err)
	}
	script := string(b)
	if !seedRouteRe.MatchString(script) {
		t.Fatalf("%s parsed to zero /api routes; the seed format changed and this guard stopped guarding", seed)
	}
	if problems := unmappedEdgeRoutes(script); len(problems) > 0 {
		for _, p := range problems {
			t.Errorf("edge route not reflected in edge.go: %s", p)
		}
	}
}

// Red case: the guard above passes today, so prove it can still fail. A seed
// line routing /api/v1/billing/* to the identity port must be reported, because
// edge.go's catch-all would send it to admin-api instead.
func TestEdgeMapGuardGoesRedOnDrift(t *testing.T) {
	fixture := `put openidx-api-billing "{$H,\"uri\":\"/api/v1/billing/*\",\"priority\":30,\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1:8001\":1}}}"`
	problems := unmappedEdgeRoutes(fixture)
	if len(problems) != 1 {
		t.Fatalf("expected exactly one drift report, got %d: %v", len(problems), problems)
	}
}
