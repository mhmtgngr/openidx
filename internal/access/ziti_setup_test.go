package access

import (
	"strings"
	"testing"
)

// The advice helpers must mirror effectiveHostingMode semantics — the UI
// explains exactly what the reconciler will do.

func TestRouteNextHop(t *testing.T) {
	cases := []struct {
		mode, toURL, hopHost string
		hopPort              int
		wantContains         []string
	}{
		{HostingModeIdentity, "http://app:8080", "", 0,
			[]string{"access-proxy", "identity headers", "http://app:8080"}},
		{HostingModeDirect, "http://app:8080", "", 0,
			[]string{"edge router", "host.v1", "http://app:8080"}},
		{HostingModeHop, "https://ext.example.com", "127.0.0.1", 8103,
			[]string{"hop nginx 127.0.0.1:8103", "Host rewrite", "https://ext.example.com"}},
	}
	for _, tc := range cases {
		got := routeNextHop(tc.mode, tc.toURL, tc.hopHost, tc.hopPort)
		for _, want := range tc.wantContains {
			if !strings.Contains(got, want) {
				t.Errorf("routeNextHop(%s): %q missing %q", tc.mode, got, want)
			}
		}
	}
}

func TestRouteClientSide(t *testing.T) {
	if got := routeClientSide(HostingModeDirect, true); !strings.Contains(got, "Nothing to install") {
		t.Errorf("browzer route should be clientless, got %q", got)
	}
	if got := routeClientSide(HostingModeIdentity, false); !strings.Contains(got, "tunneler") ||
		!strings.Contains(got, "#access-proxy-clients") {
		t.Errorf("identity route should require a tunneler as #access-proxy-clients, got %q", got)
	}
}

func TestRouteRequirements(t *testing.T) {
	// Router-hosted modes require a tunneler-enabled router tagged #ziti-routers.
	for _, mode := range []string{HostingModeDirect, HostingModeHop} {
		reqs := strings.Join(routeRequirements(mode, false), "\n")
		if !strings.Contains(reqs, "#ziti-routers") || !strings.Contains(reqs, "tunneler-enabled") {
			t.Errorf("%s requirements missing router advice: %q", mode, reqs)
		}
	}
	// Hop needs the hop nginx; direct needs upstream reachability from the router.
	if reqs := strings.Join(routeRequirements(HostingModeHop, false), "\n"); !strings.Contains(reqs, "hop nginx") {
		t.Errorf("hop requirements missing hop nginx: %q", reqs)
	}
	if reqs := strings.Join(routeRequirements(HostingModeDirect, false), "\n"); !strings.Contains(reqs, "reach the upstream") {
		t.Errorf("direct requirements missing upstream reachability: %q", reqs)
	}
	// Identity mode relies on the auto-managed access-proxy identity.
	if reqs := strings.Join(routeRequirements(HostingModeIdentity, false), "\n"); !strings.Contains(reqs, "access-proxy") {
		t.Errorf("identity requirements missing access-proxy: %q", reqs)
	}
	// BrowZer adds the bootstrapper requirement on top of the mode's own.
	if reqs := strings.Join(routeRequirements(HostingModeDirect, true), "\n"); !strings.Contains(reqs, "BrowZer bootstrapper") {
		t.Errorf("browzer requirements missing bootstrapper: %q", reqs)
	}
}

func TestRouteWarnings(t *testing.T) {
	// BrowZer route stored as identity → auto-correct warning (mirrors reconciler log).
	w := routeWarnings(HostingModeIdentity, HostingModeDirect, true, "http://app:8080")
	if len(w) != 1 || !strings.Contains(w[0], "auto-corrected") {
		t.Errorf("expected auto-correct warning, got %v", w)
	}
	// Hop with a non-https upstream is misconfigured (generator skips it).
	w = routeWarnings(HostingModeHop, HostingModeHop, true, "http://plain:80")
	if len(w) != 1 || !strings.Contains(w[0], "https upstream") {
		t.Errorf("expected non-https hop warning, got %v", w)
	}
	// Clean config → no warnings.
	if w = routeWarnings(HostingModeHop, HostingModeHop, true, "https://ext.example.com"); len(w) != 0 {
		t.Errorf("expected no warnings, got %v", w)
	}
}

func TestBuildSetupComponents(t *testing.T) {
	comps := buildSetupComponents(true, true, 2, 1, 1, false, 3, 1, "127.0.0.1", 8095)
	byID := map[string]ZitiSetupComponent{}
	for _, c := range comps {
		byID[c.ID] = c
	}
	if byID["controller"].Status != setupComplete {
		t.Errorf("reachable controller should be complete, got %s", byID["controller"].Status)
	}
	if byID["edge-router"].Status != setupComplete || byID["edge-router"].Detail != "1/2 online" {
		t.Errorf("router component wrong: %+v", byID["edge-router"])
	}
	// 1 BrowZer route but BrowZer not bootstrapped → action needed, conditional.
	if bz := byID["browzer"]; bz.Status != setupAction || bz.Required != "conditional" {
		t.Errorf("browzer component wrong: %+v", bz)
	}
	if hop := byID["hop"]; hop.Required != "conditional" {
		t.Errorf("hop with 1 hop route should be conditional, got %+v", hop)
	}

	// No routers online → action needed on the required router component.
	comps = buildSetupComponents(true, true, 0, 0, 0, false, 0, 0, "127.0.0.1", 8095)
	for _, c := range comps {
		if c.ID == "edge-router" && c.Status != setupAction {
			t.Errorf("no routers should be action_needed, got %s", c.Status)
		}
		if c.ID == "browzer" && c.Required != "optional" {
			t.Errorf("browzer with no browzer routes should be optional, got %s", c.Required)
		}
	}
}

func TestValidateZitiConnSettings(t *testing.T) {
	ok := ZitiConnSettingsView{ControllerURL: "https://ziti-controller:1280", AdminUser: "admin"}
	if msg := validateZitiConnSettings(ok); msg != "" {
		t.Errorf("valid settings rejected: %s", msg)
	}
	cases := map[string]ZitiConnSettingsView{
		"empty url":  {AdminUser: "admin"},
		"no host":    {ControllerURL: "https://", AdminUser: "admin"},
		"bad scheme": {ControllerURL: "ftp://ctrl:1280", AdminUser: "admin"},
		"no admin":   {ControllerURL: "https://ctrl:1280"},
		"not a url":  {ControllerURL: "://nope", AdminUser: "admin"},
	}
	for name, in := range cases {
		if msg := validateZitiConnSettings(in); msg == "" {
			t.Errorf("%s: expected rejection, got none", name)
		}
	}
}
