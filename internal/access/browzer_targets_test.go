package access

import (
	"strings"
	"testing"
)

func TestBrowZerTargetUsesPerAppServiceAndScheme(t *testing.T) {
	routes := []browzerRouteInfo{
		{hostname: "psm.tdv.org", toURL: "https://192.168.152.112:443", serviceName: "psm-zt", hostingMode: "direct", pathPrefix: "/"},
		{hostname: "netgraph.tdv.org", toURL: "http://127.0.0.1:8088", serviceName: "openidx-Netgraph", hostingMode: "direct", pathPrefix: "/"},
	}
	got := buildBrowZerTargets(routes, "browzer.localtest.me", "https://openidx.tdv.org", "browzer-client")
	byVHost := map[string]BrowZerTarget{}
	for _, tt := range got {
		byVHost[tt.VHost] = tt
	}
	if byVHost["psm.tdv.org"].Service != "psm-zt" || byVHost["psm.tdv.org"].Scheme != "https" {
		t.Fatalf("psm target wrong: %+v", byVHost["psm.tdv.org"])
	}
	if byVHost["netgraph.tdv.org"].Service != "openidx-Netgraph" || byVHost["netgraph.tdv.org"].Scheme != "http" {
		t.Fatalf("netgraph target wrong: %+v", byVHost["netgraph.tdv.org"])
	}
	if byVHost["psm.tdv.org"].IDPIssuerURL != "https://openidx.tdv.org" || byVHost["psm.tdv.org"].IDPClientID != "browzer-client" {
		t.Fatalf("idp fields not propagated: %+v", byVHost["psm.tdv.org"])
	}
}

func TestGenerateHopConfigPerVhost(t *testing.T) {
	routes := []browzerRouteInfo{
		{hostname: "psm.tdv.org", toURL: "https://psm.tdv.org", serviceName: "psm-zt", hostingMode: "hop"},
		{hostname: "netgraph.tdv.org", toURL: "http://127.0.0.1:8088", serviceName: "openidx-Netgraph", hostingMode: "direct"},
	}
	cfg := buildBrowZerHopConfig(routes, "/certs/tdv-fullchain.pem", "/certs/tdv-key.pem", 8095)
	for _, want := range []string{
		"listen 8095 ssl;",
		"server_name psm.tdv.org;",
		"ssl_certificate /certs/tdv-fullchain.pem;",
		"ssl_certificate_key /certs/tdv-key.pem;",
		"proxy_pass https://psm.tdv.org;",
		"proxy_ssl_server_name on;",
		"proxy_ssl_name psm.tdv.org;",
		"proxy_set_header Host psm.tdv.org;",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("hop config missing %q\n---\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "netgraph.tdv.org") {
		t.Fatalf("non-hop (direct) route must be excluded from hop config:\n%s", cfg)
	}
}
