package access

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildBrowZerAPISIXRoutes(t *testing.T) {
	routes := []browzerRouteInfo{
		{hostname: "psm.tdv.org", serviceName: "psm-zt", hostingMode: "hop"},
		{hostname: "netgraph.tdv.org", serviceName: "openidx-Netgraph", hostingMode: "direct"},
	}
	opts := apisixRouteOpts{
		bootstrapperNode: "127.0.0.1:8445",
		hopBasePort:      8095,
		oidcCallbacks:    []string{"signin-oidc", "signout-callback-oidc"},
	}
	got := buildBrowZerAPISIXRoutes(routes, opts)
	byName := map[string]map[string]interface{}{}
	names := []string{}
	for _, r := range got {
		var m map[string]interface{}
		if err := json.Unmarshal(r.body, &m); err != nil {
			t.Fatalf("route %s body is not valid JSON: %v", r.name, err)
		}
		byName[r.name] = m
		names = append(names, r.name)
	}
	for _, want := range []string{"browzer-psm-tdv-org", "browzer-psm-tdv-org-oidc", "browzer-netgraph-tdv-org"} {
		if byName[want] == nil {
			t.Fatalf("missing route %s; got %v", want, names)
		}
	}
	if byName["browzer-netgraph-tdv-org-oidc"] != nil {
		t.Fatal("direct-mode route must NOT get an OIDC bypass route")
	}
	ov := byName["browzer-psm-tdv-org"]
	up := ov["upstream"].(map[string]interface{})
	if hosts := ov["hosts"].([]interface{}); hosts[0] != "psm.tdv.org" {
		t.Fatalf("overlay host wrong: %v", hosts)
	}
	if up["scheme"] != "https" || up["pass_host"] != "rewrite" || up["upstream_host"] != "psm.tdv.org" {
		t.Fatalf("overlay upstream must set SNI via pass_host=rewrite+upstream_host: %v", up)
	}
	if _, ok := up["nodes"].(map[string]interface{})["127.0.0.1:8445"]; !ok {
		t.Fatalf("overlay must target the bootstrapper node: %v", up["nodes"])
	}
	if ov["enable_websocket"] != true {
		t.Fatal("overlay route must enable websocket")
	}
	oidc := byName["browzer-psm-tdv-org-oidc"]
	if oidc["priority"].(float64) <= ov["priority"].(float64) {
		t.Fatal("OIDC route must outrank the overlay route")
	}
	varsJSON, _ := json.Marshal(oidc["vars"])
	if !strings.Contains(string(varsJSON), "signin-oidc|signout-callback-oidc") {
		t.Fatalf("OIDC route must match the callback suffixes: %s", varsJSON)
	}
	oup := oidc["upstream"].(map[string]interface{})
	// sorted hop names: only psm-zt is hop (openidx-Netgraph is direct, excluded), so it lands on base port 8095.
	if _, ok := oup["nodes"].(map[string]interface{})["127.0.0.1:8095"]; !ok {
		t.Fatalf("OIDC route must target the hop port 8095: %v", oup["nodes"])
	}
}

func TestBuildBrowZerAPISIXRoutesSkipsEmptyHost(t *testing.T) {
	got := buildBrowZerAPISIXRoutes(
		[]browzerRouteInfo{{hostname: "", serviceName: "x", hostingMode: "hop"}},
		apisixRouteOpts{bootstrapperNode: "127.0.0.1:8445", hopBasePort: 8095})
	if len(got) != 0 {
		t.Fatalf("a route with no hostname must be skipped: %v", got)
	}
}

func TestStaleBrowZerRouteNames(t *testing.T) {
	existing := []string{"browzer-a", "browzer-b", "browzer-b-oidc", "identity-service", "other"}
	desired := []string{"browzer-a"}
	stale := staleBrowZerRouteNames(existing, desired)
	// Only browzer-* routes not in desired are stale; non-browzer routes are left alone.
	want := map[string]bool{"browzer-b": true, "browzer-b-oidc": true}
	if len(stale) != 2 {
		t.Fatalf("got %v", stale)
	}
	for _, s := range stale {
		if !want[s] {
			t.Fatalf("unexpected stale name %s (got %v)", s, stale)
		}
	}
}

// TestStaleBrowZerRouteNames_DesiredOnlyNoPanic verifies that a desired name that
// does not appear in existing causes no panic and is simply ignored.
func TestStaleBrowZerRouteNames_DesiredOnlyNoPanic(t *testing.T) {
	stale := staleBrowZerRouteNames(
		[]string{"browzer-a", "identity-service"},
		[]string{"browzer-a", "browzer-ghost"}, // browzer-ghost not in existing
	)
	// browzer-a is desired+present → not stale; identity-service non-browzer → not stale
	if len(stale) != 0 {
		t.Fatalf("expected no stale routes, got %v", stale)
	}
}

func TestAPISIXSlug(t *testing.T) {
	cases := map[string]string{
		"psm.tdv.org":     "psm-tdv-org",
		"UPPER.Case.org":  "upper-case-org",
		"host..double":    "host-double",
		".leading.trail.": "leading-trail",
	}
	for in, want := range cases {
		if got := apisixSlug(in); got != want {
			t.Errorf("apisixSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildBrowZerAPISIXRoutesNoSameHostCollision(t *testing.T) {
	// Several routes on the SAME host (e.g. an app published per-path) must collapse
	// to exactly ONE browzer-<slug> APISIX route — names key by host slug, so without
	// the guard each PUT would overwrite the previous (last wins, the rest lost).
	routes := []browzerRouteInfo{
		{hostname: "kibana-dev.tdv.org", serviceName: "openidx-kibana-dev", hostingMode: "hop", pathPrefix: "/"},
		{hostname: "kibana-dev.tdv.org", serviceName: "openidx-kibana-devadmin", hostingMode: "hop", pathPrefix: "/admin"},
		{hostname: "kibana-dev.tdv.org", serviceName: "openidx-kibana-devapi", hostingMode: "hop", pathPrefix: "/api"},
	}
	got := buildBrowZerAPISIXRoutes(routes, apisixRouteOpts{bootstrapperNode: "127.0.0.1:8445", hopBasePort: 8095})
	n := 0
	for _, r := range got {
		if r.name == "browzer-kibana-dev-tdv-org" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 browzer-kibana-dev-tdv-org route, got %d (same-host collision)", n)
	}
}
