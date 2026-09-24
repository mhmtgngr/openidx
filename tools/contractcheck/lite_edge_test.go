package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The lite install has no APISIX: the console's own nginx is the edge
// (deployments/docker/nginx/admin-console.lite.conf). Its location blocks are
// one more copy of the edge route table, and a copy that misses a prefix sends
// the console's calls for it to admin-api's catch-all, which answers 404 with a
// 200-shaped silence around it. So it is held to edgePrefixes the way the seed
// script is.

const liteEdgeConf = "../../deployments/docker/nginx/admin-console.lite.conf"

// liteLocationRe pulls (prefix, upstream host, upstream port) out of blocks
// shaped `location ^~ /prefix/ { set $upstream http://host:port; ... }`.
var liteLocationRe = regexp.MustCompile(`location \^~ (\S+) \{\s*set \$upstream http://([a-z-]+):(\d+);`)

// liteEdgeProblems returns one message per way the lite config's proxied
// routes disagree with edgePrefixes and localPorts.
func liteEdgeProblems(conf string) []string {
	routes := map[string]int{} // location prefix -> upstream port
	for _, m := range liteLocationRe.FindAllStringSubmatch(conf, -1) {
		port, err := strconv.Atoi(m[3])
		if err != nil {
			continue
		}
		routes[m[1]] = port
	}

	var problems []string
	// Every prefix the edge routes is routed here, to the same service.
	for _, r := range edgePrefixes {
		port, ok := routes[r.Prefix]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s has no location; the edge sends it to %s", r.Prefix, r.Service))
			continue
		}
		if want := localPorts[r.Service]; port != want {
			problems = append(problems, fmt.Sprintf("%s goes to :%d; the edge sends it to %s on :%d", r.Prefix, port, r.Service, want))
		}
	}
	// No /api location sends a prefix anywhere the edge would not.
	for prefix, port := range routes {
		if !strings.HasPrefix(prefix, "/api/") {
			continue
		}
		svc := serviceForPath(prefix + "probe")
		if want, ok := localPorts[svc]; !ok || want != port {
			problems = append(problems, fmt.Sprintf("%s goes to :%d; the edge sends it to %q", prefix, port, svc))
		}
	}
	// The sign-in and discovery endpoints the console calls on its own origin.
	for _, prefix := range []string{"/oauth/", "/.well-known/"} {
		if port, ok := routes[prefix]; !ok || port != localPorts["oauth"] {
			problems = append(problems, fmt.Sprintf("%s must go to oauth on :%d", prefix, localPorts["oauth"]))
		}
	}
	sort.Strings(problems)
	return problems
}

func TestLiteConsoleEdgeMatchesTheRouteTable(t *testing.T) {
	b, err := os.ReadFile(liteEdgeConf)
	if err != nil {
		t.Fatalf("cannot read %s: %v", liteEdgeConf, err)
	}
	conf := string(b)
	if n := len(liteLocationRe.FindAllStringSubmatch(conf, -1)); n < len(edgePrefixes) {
		t.Fatalf("%s parsed to %d proxied locations, fewer than the %d edge prefixes; the config's shape changed and this guard stopped guarding", liteEdgeConf, n, len(edgePrefixes))
	}
	for _, p := range liteEdgeProblems(conf) {
		t.Errorf("%s: %s", liteEdgeConf, p)
	}
}

// Red cases: the guard above passes today, so prove each half can still fail.
func TestLiteConsoleEdgeGuardGoesRed(t *testing.T) {
	var b strings.Builder
	for _, r := range edgePrefixes {
		port := localPorts[r.Service]
		switch r.Prefix {
		case "/api/v1/access/":
			continue // missing: the console's PAM and Ziti pages would 404
		case "/api/v1/audit/":
			port = localPorts["identity"] // misrouted
		}
		fmt.Fprintf(&b, "location ^~ %s {\n    set $upstream http://svc:%d;\n}\n", r.Prefix, port)
	}
	b.WriteString("location ^~ /oauth/ {\n    set $upstream http://oauth-service:8006;\n}\n")
	// /.well-known/ is missing too.

	got := liteEdgeProblems(b.String())
	want := []string{"/.well-known/", "/api/v1/access/ has no location", "/api/v1/audit/ goes to :8001"}
	if len(got) != 4 {
		t.Fatalf("expected 4 reports (missing access, misrouted audit twice, missing /.well-known/), got %d: %v", len(got), got)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if strings.HasPrefix(g, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("no report starting %q in %v", w, got)
		}
	}
}
