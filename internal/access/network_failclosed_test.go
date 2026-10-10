package access

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// The network reconciler fails closed: what it cannot vouch for this pass is
// not left dialable with what an earlier pass wrote.

func resetRouterHosts(t *testing.T, known bool, hosts ...string) {
	t.Helper()
	routerHostsMu.Lock()
	saved, savedKnown := routerHosts, routerHostsKnown
	routerHosts, routerHostsKnown = hosts, known
	routerHostsMu.Unlock()
	t.Cleanup(func() {
		routerHostsMu.Lock()
		routerHosts, routerHostsKnown = saved, savedKnown
		routerHostsMu.Unlock()
	})
}

func failClosedFixture(t *testing.T) (*fakeNetCtrl, *ZitiManager, *ZitiReconciler, DesiredNetworkService) {
	t.Helper()
	pinTargetGuard(t)
	f := newFakeNetCtrl()
	f.routers = []interface{}{map[string]interface{}{
		"id": "er-1", "hostname": "edge1.corp.example", "roleAttributes": []string{"ziti-routers"},
		"supportedProtocols": map[string]string{"tls": "tls://10.30.77.7:3022"},
	}}
	zm := newNetTestManager(t, f)
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}, assignmentEnforce: true}
	tgt, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.20.0.0/16"}, PortRanges: []PortRange{{445, 445}}})
	if err != nil {
		t.Fatal(err)
	}
	const app = "33333333-3333-3333-3333-333333333333"
	d := DesiredNetworkService{ApplicationID: app, OrgID: "org-1", ServiceName: networkServiceName(app), Target: tgt, RequireDeviceTrust: true}
	return f, zm, rec, d
}

func (f *fakeNetCtrl) has(kind, name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	var m map[string]map[string]interface{}
	switch kind {
	case "service":
		m = f.services
	case "policy":
		m = f.policies
	case "config":
		m = f.configs
	}
	for _, v := range m {
		if v["name"] == name {
			return true
		}
	}
	return false
}

func TestNetworkPassConvergesWhenEverythingLoads(t *testing.T) {
	f, zm, rec, d := failClosedFixture(t)
	resetRouterHosts(t, false)
	rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) { return []DesiredNetworkService{d}, nil }
	rec.reconcileNetworkServices(context.Background(), zm)
	if !f.has("service", d.ServiceName) || !f.has("policy", "openidx-dial-"+d.ServiceName) {
		t.Fatalf("a good pass did not converge the service; status %q", rec.StatusSnapshot()[d.ServiceName])
	}
	if !routerHostsAreKnown() {
		t.Error("the router hosts were not recorded")
	}
}

// A target refused at emit time (here: the denylist now covers it) has its
// service, configs and Dial policy removed, not left as an earlier pass wrote.
func TestARefusedTargetIsRemovedNotLeftLive(t *testing.T) {
	f, zm, rec, d := failClosedFixture(t)
	resetRouterHosts(t, false)
	rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) { return []DesiredNetworkService{d}, nil }
	rec.reconcileNetworkServices(context.Background(), zm)
	if !f.has("policy", "openidx-dial-"+d.ServiceName) {
		t.Fatal("setup: the service did not converge")
	}

	t.Setenv("NETWORK_TARGET_DENY_CIDRS", "10.20.0.0/16")
	rec.reconcileNetworkServices(context.Background(), zm)
	if f.has("service", d.ServiceName) {
		t.Error("the service survived a refused target")
	}
	for _, p := range []string{"openidx-dial-" + d.ServiceName, "openidx-bind-" + d.ServiceName} {
		if f.has("policy", p) {
			t.Errorf("policy %s survived a refused target", p)
		}
	}
	if f.has("config", d.ServiceName+"-intercept") || f.has("config", d.ServiceName+"-host") {
		t.Error("the refused target's configs survived")
	}
	if st := rec.StatusSnapshot()[d.ServiceName]; !strings.HasPrefix(st, "error:") {
		t.Errorf("status %q, want the refusal", st)
	}
}

// A controller failure part-way through convergence removes the service too.
func TestAFailedConvergenceRemovesTheService(t *testing.T) {
	f, zm, rec, d := failClosedFixture(t)
	resetRouterHosts(t, false)
	rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) { return []DesiredNetworkService{d}, nil }
	rec.reconcileNetworkServices(context.Background(), zm)

	// The Dial policy now has to change (device trust dropped) and the
	// controller refuses the update.
	d.RequireDeviceTrust = false
	f.mu.Lock()
	f.failPolicyWrites = true
	f.mu.Unlock()
	rec.reconcileNetworkServices(context.Background(), zm)
	if f.has("policy", "openidx-dial-"+d.ServiceName) {
		t.Error("the Dial policy an earlier pass wrote is still live after a failed convergence")
	}
	if f.has("service", d.ServiceName) {
		t.Error("the service is still live after a failed convergence")
	}
}

// A failure to load the network resources (targets or their conditions)
// removes every network service's Dial policy instead of leaving it as is.
func TestALoadFailureRevokesEveryNetworkDial(t *testing.T) {
	f, zm, rec, d := failClosedFixture(t)
	resetRouterHosts(t, false)
	rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) { return []DesiredNetworkService{d}, nil }
	rec.reconcileNetworkServices(context.Background(), zm)

	f.mu.Lock()
	f.services["other"] = map[string]interface{}{"id": "other", "name": "someone-elses-service"}
	f.policies["sp-other"] = map[string]interface{}{"id": "sp-other", "name": "openidx-dial-someone-elses-service"}
	f.mu.Unlock()
	rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) {
		return nil, errors.New("resource_conditions: connection reset")
	}
	rec.reconcileNetworkServices(context.Background(), zm)
	if f.has("policy", "openidx-dial-"+d.ServiceName) {
		t.Error("a network service stayed dialable while the resources could not be loaded")
	}
	if !f.has("policy", "openidx-dial-someone-elses-service") {
		t.Error("a service the reconciler does not own lost its Dial policy")
	}
	if st := rec.StatusSnapshot()[d.ServiceName]; !strings.HasPrefix(st, "error:") {
		t.Errorf("status %q, want the revoke", st)
	}

	// The next good pass restores it.
	rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) { return []DesiredNetworkService{d}, nil }
	rec.reconcileNetworkServices(context.Background(), zm)
	if !f.has("policy", "openidx-dial-"+d.ServiceName) {
		t.Error("a good pass did not restore the Dial policy")
	}
}

// With no router-host list ever read, the pass writes nothing; a later failed
// or empty refresh keeps the last good list.
func TestNoRouterListMeansNoWrites(t *testing.T) {
	f, zm, rec, d := failClosedFixture(t)
	resetRouterHosts(t, false)
	f.routers = []interface{}{} // the controller lists no routers
	loads := 0
	rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) {
		loads++
		return []DesiredNetworkService{d}, nil
	}
	rec.reconcileNetworkServices(context.Background(), zm)
	if n := f.writeCount(); n != 0 || loads != 0 {
		t.Errorf("with no router list the pass wrote %d time(s) and loaded %d time(s)", n, loads)
	}

	// A good list, then a failed refresh: the good list stays.
	f.routers = []interface{}{map[string]interface{}{"hostname": "edge1.corp.example", "roleAttributes": []string{"ziti-routers"}}}
	if err := refreshRouterHosts(context.Background(), zm); err != nil {
		t.Fatal(err)
	}
	f.routers = []interface{}{}
	if err := refreshRouterHosts(context.Background(), zm); err == nil {
		t.Error("an empty router list was taken as a good one")
	}
	if _, err := normalizeNetworkTarget(NetworkTarget{Hosts: []string{"edge1.corp.example"}}); err == nil {
		t.Error("an empty refresh dropped the last good router list")
	}
}

// A host interface discovery that fails with no earlier result makes the
// guard refuse every target, and the pass write nothing; with an earlier
// result, that result is used.
func TestInterfaceDiscoveryFailureFailsClosed(t *testing.T) {
	f, zm, rec, d := failClosedFixture(t)
	resetRouterHosts(t, true, "edge1.corp.example")
	lastIfaceMu.Lock()
	lastIfaceDeny = nil
	lastIfaceMu.Unlock()
	hostInterfaces = func() ([]ifaceAddr, error) { return nil, errors.New("netlink: permission denied") }

	if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.20.0.0/16"}}); err == nil ||
		!strings.Contains(err.Error(), "incomplete") {
		t.Errorf("a target was accepted with an incomplete denylist: %v", err)
	}
	loads := 0
	rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) {
		loads++
		return []DesiredNetworkService{d}, nil
	}
	rec.reconcileNetworkServices(context.Background(), zm)
	if loads != 0 || f.has("service", d.ServiceName) {
		t.Error("the pass wrote network services with an incomplete denylist")
	}

	// An empty answer is a failure too.
	hostInterfaces = func() ([]ifaceAddr, error) { return nil, nil }
	if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.20.0.0/16"}}); err == nil {
		t.Error("an empty interface list was taken as a good one")
	}

	// A good discovery, then a failed one: the good result is kept.
	hostInterfaces = func() ([]ifaceAddr, error) {
		return []ifaceAddr{{name: "podman1", prefix: netip.MustParsePrefix("10.90.0.1/24")}}, nil
	}
	if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.20.0.0/16"}}); err != nil {
		t.Fatalf("a good discovery still refuses: %v", err)
	}
	hostInterfaces = func() ([]ifaceAddr, error) { return nil, errors.New("gone") }
	if _, err := normalizeNetworkTarget(NetworkTarget{Hosts: []string{"10.90.0.50"}}); err == nil {
		t.Error("after a failed discovery the last good bridge network is no longer refused")
	}
	if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.20.0.0/16"}}); err != nil {
		t.Errorf("the last good discovery was not used: %v", err)
	}
}

// A row whose conditions cannot be read is not given looser roles: the load
// fails as a whole (it is one query) and the Dial policies are revoked, as
// above. A resource the loader leaves out (a row that does not scan, a target
// that is refused) is pruned with everything else not desired.
func TestAResourceLeftOutOfTheLoadIsRemoved(t *testing.T) {
	f, zm, rec, d := failClosedFixture(t)
	resetRouterHosts(t, false)
	rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) { return []DesiredNetworkService{d}, nil }
	rec.reconcileNetworkServices(context.Background(), zm)
	rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) { return nil, nil }
	rec.reconcileNetworkServices(context.Background(), zm)
	if f.has("service", d.ServiceName) || f.has("policy", "openidx-dial-"+d.ServiceName) {
		t.Error("a resource left out of the load is still live")
	}
}
