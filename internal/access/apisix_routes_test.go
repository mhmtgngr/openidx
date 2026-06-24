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
		if err := json.Unmarshal(r.Body, &m); err != nil {
			t.Fatalf("route %s body is not valid JSON: %v", r.Name, err)
		}
		byName[r.Name] = m
		names = append(names, r.Name)
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

func TestAPISIXSlug(t *testing.T) {
	if got := apisixSlug("psm.tdv.org"); got != "psm-tdv-org" {
		t.Fatalf("apisixSlug: got %q", got)
	}
}
