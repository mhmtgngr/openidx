package access

import "testing"

// These tests lock the invariants that BrowZer error 1010 (and the silent
// hop-port cross-wiring) violated: the Ziti reconciler and the bootstrapper/hop
// config generators MUST resolve a route's hosting mode identically, and a hop
// route's bootstrapper target MUST advertise the http scheme (so the runtime
// never runs TLS against the plain-HTTP hop port).

// TestEffectiveHostingModeResolver pins the single resolver used by both the
// reconciler (DesiredRoute.EffectiveMode) and the generators (queryBrowZerRoutes).
func TestEffectiveHostingModeResolver(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		browzer bool
		toURL   string
		want    string
	}{
		{"browzer identity + external https -> hop", "identity", true, "https://es-dev.tdv.org", HostingModeHop},
		{"browzer empty + external https -> hop", "", true, "https://app.tdv.org", HostingModeHop},
		{"browzer identity + local http -> direct", "identity", true, "http://127.0.0.1:9000", HostingModeDirect},
		{"browzer identity + loopback https -> direct", "identity", true, "https://localhost:8443", HostingModeDirect},
		{"explicit hop wins", "hop", true, "http://127.0.0.1:9000", HostingModeHop},
		{"explicit direct honored on external https", "direct", true, "https://app.tdv.org", HostingModeDirect},
		{"non-browzer identity stays identity", "identity", false, "https://app.tdv.org", HostingModeIdentity},
		{"non-browzer explicit direct", "direct", false, "https://app.tdv.org", HostingModeDirect},
	}
	for _, c := range cases {
		// The resolver and DesiredRoute.EffectiveMode must never disagree — that
		// disagreement (reconciler vs generators) is exactly what caused 1010.
		got := effectiveHostingMode(c.raw, c.browzer, c.toURL)
		viaDesired := DesiredRoute{HostingMode: c.raw, BrowZerEnabled: c.browzer, ToURL: c.toURL}.EffectiveMode()
		if got != c.want {
			t.Errorf("%s: effectiveHostingMode=%q want %q", c.name, got, c.want)
		}
		if got != viaDesired {
			t.Errorf("%s: resolver (%q) and DesiredRoute.EffectiveMode (%q) disagree", c.name, got, viaDesired)
		}
	}
}

// TestBuildBrowZerTargetsHopSchemeIsHTTP is the direct 1010 guard: a hop route's
// target scheme must be http (the runtime→hop leg is plain HTTP/port-demux), no
// matter how the upstream is addressed. A https scheme here makes the WASM do a
// TLS handshake against the plain-HTTP hop port → 1010.
func TestBuildBrowZerTargetsHopSchemeIsHTTP(t *testing.T) {
	routes := []browzerRouteInfo{
		{hostname: "https://hop-https.tdv.org", toURL: "https://hop-https.tdv.org", serviceName: "openidx-HopHttps", hostingMode: HostingModeHop},
		{hostname: "https://direct-https.tdv.org", toURL: "https://10.0.0.5", serviceName: "openidx-DirectHttps", hostingMode: HostingModeDirect},
		{hostname: "https://direct-http.tdv.org", toURL: "http://127.0.0.1:9000", serviceName: "openidx-DirectHttp", hostingMode: HostingModeDirect},
	}
	want := map[string]string{
		"openidx-HopHttps":    "http",  // hop ALWAYS http, even with an https upstream (1010 guard)
		"openidx-DirectHttps": "https", // direct → end-to-end WASM TLS to the upstream
		"openidx-DirectHttp":  "http",
	}
	for _, tg := range buildBrowZerTargets(routes, "tdv.org", "https://issuer", "browzer-client") {
		if w, ok := want[tg.Service]; ok && tg.Scheme != w {
			t.Errorf("%s: target scheme=%q want %q", tg.Service, tg.Scheme, w)
		}
	}
}

// TestReconcilerGeneratorHopSetAgreement guards against the cross-wiring bug:
// for the same routes, the reconciler's effective-hop set (used for host.v1 +
// assignHopPorts) and the generator's (browzerRouteInfo.hostingMode, set from
// the same resolver) must be identical, so assignHopPorts yields one port map.
func TestReconcilerGeneratorHopSetAgreement(t *testing.T) {
	type route struct {
		svc, raw, toURL string
	}
	routes := []route{
		{"openidx-Es-Dev", "identity", "https://es-dev.tdv.org"}, // auto-promoted -> hop
		{"openidx-Netgraph", "hop", "http://127.0.0.1:8088"},     // explicit hop
		{"openidx-PSM", "hop", "https://psm.tdv.org"},            // explicit hop
		{"openidx-Local", "identity", "http://127.0.0.1:9000"},   // -> direct (not hop)
	}
	var reconcilerHop, generatorHop []string
	for _, r := range routes {
		// Reconciler's view.
		if (DesiredRoute{ServiceName: r.svc, HostingMode: r.raw, BrowZerEnabled: true, ToURL: r.toURL}).EffectiveMode() == HostingModeHop {
			reconcilerHop = append(reconcilerHop, r.svc)
		}
		// Generator's view (queryBrowZerRoutes stores effectiveHostingMode in
		// browzerRouteInfo.hostingMode; the hop config filters == hop).
		if effectiveHostingMode(r.raw, true, r.toURL) == HostingModeHop {
			generatorHop = append(generatorHop, r.svc)
		}
	}
	rp := assignHopPorts(reconcilerHop, 8095)
	gp := assignHopPorts(generatorHop, 8095)
	if len(rp) != len(gp) {
		t.Fatalf("hop set size differs: reconciler=%v generator=%v", reconcilerHop, generatorHop)
	}
	for svc, port := range rp {
		if gp[svc] != port {
			t.Errorf("hop port for %s differs: reconciler=%d generator=%d (port cross-wiring)", svc, port, gp[svc])
		}
	}
	// es-dev (stored identity) MUST be a hop route in both views — the original bug
	// had it hop in the reconciler but not the generator.
	if rp["openidx-Es-Dev"] == 0 || gp["openidx-Es-Dev"] == 0 {
		t.Errorf("auto-promoted es-dev must be a hop route in both views: reconciler=%v generator=%v", rp, gp)
	}
}
