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
	// A hop route yields scheme "http": the runtime→hop leg is plain HTTP,
	// demuxed by port (the runtime sends no SNI and Host:unknown).
	hop := buildBrowZerTargets([]browzerRouteInfo{
		{hostname: "hop.tdv.org", toURL: "https://hop.tdv.org", serviceName: "hop-zt", hostingMode: "hop", pathPrefix: "/"},
	}, "browzer.localtest.me", "https://openidx.tdv.org", "browzer-client")
	if len(hop) != 1 || hop[0].Scheme != "http" {
		t.Fatalf("hop route must yield scheme http, got %+v", hop)
	}
}

func TestHopConfigPerAppPorts(t *testing.T) {
	routes := []browzerRouteInfo{
		{hostname: "psm.tdv.org", toURL: "https://psm.tdv.org", serviceName: "psm-zt", hostingMode: "hop"},
		{hostname: "netgraph.tdv.org", toURL: "http://127.0.0.1:8088", serviceName: "openidx-Netgraph", hostingMode: "hop"},
		{hostname: "x.tdv.org", toURL: "http://127.0.0.1:9000", serviceName: "x-zt", hostingMode: "direct"}, // not hop -> excluded
	}
	cfg := buildBrowZerHopConfig(routes, 8095)
	// sorted by service name: openidx-Netgraph -> 8095, psm-zt -> 8096
	if !strings.Contains(cfg, "listen 8095;") || !strings.Contains(cfg, "listen 8096;") {
		t.Fatalf("expected per-app ports 8095/8096:\n%s", cfg)
	}
	if strings.Contains(cfg, "listen 8095 ssl;") {
		t.Fatal("hop must be plain HTTP, no ssl listen")
	}
	if !strings.Contains(cfg, "proxy_set_header Host netgraph.tdv.org;") {
		t.Fatal("netgraph Host rewrite missing")
	}
	if !strings.Contains(cfg, "proxy_set_header Host psm.tdv.org;") {
		t.Fatal("psm Host rewrite missing")
	}
	if strings.Contains(cfg, "x.tdv.org") {
		t.Fatal("non-hop route must be excluded")
	}
	// https upstream (psm) gets proxy_ssl; http upstream (netgraph) does not — check per block
	psmBlock := blockFor(cfg, "psm.tdv.org")
	ngBlock := blockFor(cfg, "netgraph.tdv.org")
	if !strings.Contains(psmBlock, "proxy_ssl_server_name on;") {
		t.Fatal("https upstream needs proxy_ssl")
	}
	if strings.Contains(ngBlock, "proxy_ssl_server_name on;") {
		t.Fatal("http upstream must NOT have proxy_ssl")
	}
}

// blockFor returns the substring of cfg for the server block whose
// proxy_set_header Host is host.
func blockFor(cfg, host string) string {
	marker := "proxy_set_header Host " + host + ";"
	i := strings.Index(cfg, marker)
	if i < 0 {
		return ""
	}
	start := strings.LastIndex(cfg[:i], "server {")
	end := strings.Index(cfg[i:], "}")
	if start < 0 {
		start = 0
	}
	if end < 0 {
		return cfg[start:]
	}
	return cfg[start : i+end]
}

func TestAssignHopPortsDeterministic(t *testing.T) {
	m := assignHopPorts([]string{"psm-zt", "openidx-Netgraph"}, 8095)
	if m["openidx-Netgraph"] != 8095 || m["psm-zt"] != 8096 {
		t.Fatalf("got %v", m)
	}
}
