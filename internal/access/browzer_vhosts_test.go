package access

import (
	"strings"
	"testing"
)

func TestBuildBrowZerVHostConfig(t *testing.T) {
	routes := []browzerRouteInfo{
		{hostname: "psm.tdv.org", toURL: "https://psm.tdv.org", serviceName: "psm-zt", hostingMode: "hop"},
		{hostname: "netgraph.tdv.org", toURL: "http://127.0.0.1:8088", serviceName: "openidx-Netgraph", hostingMode: "direct"},
	}
	opts := browzerVHostOpts{
		bootstrapperPass: "https://127.0.0.1:8445",
		sslCert:          "/etc/nginx/tdv-fullchain.pem",
		sslKey:           "/etc/nginx/tdv-key.pem",
		hopBasePort:      8095,
		oidcCallbacks:    []string{"signin-oidc", "signout-callback-oidc"},
	}
	cfg := buildBrowZerVHostConfig(routes, opts)

	psm := vhostBlockFor(cfg, "psm.tdv.org")
	ng := vhostBlockFor(cfg, "netgraph.tdv.org")
	if psm == "" || ng == "" {
		t.Fatalf("missing a server block:\n%s", cfg)
	}

	// Every app block: TLS-terminate + forward to the bootstrapper by Host.
	for host, block := range map[string]string{"psm.tdv.org": psm, "netgraph.tdv.org": ng} {
		if !strings.Contains(block, "listen 443 ssl;") ||
			!strings.Contains(block, "server_name "+host+";") ||
			!strings.Contains(block, "ssl_certificate /etc/nginx/tdv-fullchain.pem;") ||
			!strings.Contains(block, "ssl_certificate_key /etc/nginx/tdv-key.pem;") {
			t.Fatalf("%s block missing tls/server_name:\n%s", host, block)
		}
		if !strings.Contains(block, "proxy_pass https://127.0.0.1:8445;") ||
			!strings.Contains(block, "proxy_ssl_name $host;") {
			t.Fatalf("%s block must forward to the bootstrapper:\n%s", host, block)
		}
	}

	// Hop-mode (psm) gets the OIDC form_post callback bypass to ITS hop port.
	// sorted hop names: openidx-Netgraph(direct, excluded from hop ports) — only
	// psm-zt is hop, so it lands on the base port 8095.
	if !strings.Contains(psm, "location ~ /(signin-oidc|signout-callback-oidc)$ {") {
		t.Fatalf("psm (hop) must emit the OIDC callback bypass:\n%s", psm)
	}
	if !strings.Contains(psm, "proxy_pass http://127.0.0.1:8095;") {
		t.Fatalf("psm OIDC bypass must target its hop port 8095:\n%s", psm)
	}
	// Direct-mode (netgraph) has no hop upstream → no callback bypass.
	if strings.Contains(ng, "signin-oidc") {
		t.Fatalf("direct-mode netgraph must NOT emit an OIDC callback bypass:\n%s", ng)
	}
}

func TestBuildBrowZerVHostConfigSkipsEmptyHost(t *testing.T) {
	routes := []browzerRouteInfo{{hostname: "", toURL: "http://127.0.0.1:9000", serviceName: "x-zt", hostingMode: "hop"}}
	cfg := buildBrowZerVHostConfig(routes, browzerVHostOpts{bootstrapperPass: "https://127.0.0.1:8445", hopBasePort: 8095})
	if strings.Contains(cfg, "server_name ;") || strings.Contains(cfg, "server {") {
		t.Fatalf("a route with no hostname must be skipped:\n%s", cfg)
	}
}

func TestSplitCSV(t *testing.T) {
	got := SplitCSV(" signin-oidc , ,signout-callback-oidc ,")
	if len(got) != 2 || got[0] != "signin-oidc" || got[1] != "signout-callback-oidc" {
		t.Fatalf("SplitCSV trim/drop-empty failed: %#v", got)
	}
	if len(SplitCSV("")) != 0 {
		t.Fatal("SplitCSV(\"\") must be empty")
	}
}

// vhostBlockFor returns the server{} block whose server_name is host.
func vhostBlockFor(cfg, host string) string {
	marker := "server_name " + host + ";"
	i := strings.Index(cfg, marker)
	if i < 0 {
		return ""
	}
	start := strings.LastIndex(cfg[:i], "server {")
	if start < 0 {
		start = 0
	}
	rest := cfg[start:]
	// The block ends at the first line that is just "}" at column 0.
	if end := strings.Index(rest, "\n}\n"); end >= 0 {
		return rest[:end+3]
	}
	return rest
}
