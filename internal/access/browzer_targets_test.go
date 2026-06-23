package access

import "testing"

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
