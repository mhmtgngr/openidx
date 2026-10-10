package access

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func moveGuardClock(t *testing.T, by time.Duration) {
	t.Helper()
	orig := guardNow
	guardNow = func() time.Time { return orig().Add(by) }
	t.Cleanup(func() { guardNow = orig })
}

// (a) The last good router list expires: after denylistMaxFailures failed
// refreshes, or denylistMaxAge since the last good one, the guard is
// incomplete, targets are refused, and the reconciler revokes every
// network Dial policy and writes nothing.
func TestTheLastGoodRouterListExpires(t *testing.T) {
	for name, expire := range map[string]func(*testing.T, *fakeNetCtrl, *ZitiManager){
		"after repeated failures": func(t *testing.T, f *fakeNetCtrl, zm *ZitiManager) {
			f.routers = []interface{}{}
			for i := 0; i < denylistMaxFailures; i++ {
				_ = refreshRouterHosts(context.Background(), zm)
			}
		},
		"after the age bound": func(t *testing.T, f *fakeNetCtrl, zm *ZitiManager) {
			f.routers = []interface{}{}
			moveGuardClock(t, denylistMaxAge+time.Minute)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, zm, rec, d := failClosedFixture(t)
			resetRouterHosts(t, false)
			rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) { return []DesiredNetworkService{d}, nil }
			rec.reconcileNetworkServices(context.Background(), zm)
			if !f.has("policy", "openidx-dial-"+d.ServiceName) {
				t.Fatal("setup: the service did not converge")
			}
			// One failed refresh is tolerated: the last good list stays.
			f.routers = []interface{}{}
			_ = refreshRouterHosts(context.Background(), zm)
			if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.20.0.0/16"}}); err != nil {
				t.Fatalf("one failed refresh already refuses: %v", err)
			}

			expire(t, f, zm)
			if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.20.0.0/16"}}); err == nil ||
				!strings.Contains(err.Error(), "incomplete") {
				t.Errorf("a target was judged against an expired router list: %v", err)
			}
			loads := 0
			rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) {
				loads++
				return []DesiredNetworkService{d}, nil
			}
			rec.reconcileNetworkServices(context.Background(), zm)
			if loads != 0 {
				t.Error("the pass loaded and converged under an expired router list")
			}
			if f.has("policy", "openidx-dial-"+d.ServiceName) {
				t.Error("a network service stayed dialable under an expired router list")
			}
		})
	}
}

// The interface half expires the same way.
func TestTheLastGoodInterfaceDiscoveryExpires(t *testing.T) {
	pinTargetGuard(t)
	if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.20.0.0/16"}}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	hostInterfaces = func() ([]ifaceAddr, error) { return nil, errors.New("gone") }
	for i := 0; i < denylistMaxFailures-1; i++ {
		if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.20.0.0/16"}}); err != nil {
			t.Fatalf("failure %d already refuses: %v", i+1, err)
		}
	}
	if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.20.0.0/16"}}); err == nil {
		t.Error("the last good interface discovery outlived its failure bound")
	}

	// And by age, with the discovery still failing.
	pinTargetGuard(t)
	_, _ = normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.20.0.0/16"}})
	hostInterfaces = func() ([]ifaceAddr, error) { return nil, errors.New("gone") }
	moveGuardClock(t, denylistMaxAge+time.Minute)
	if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.20.0.0/16"}}); err == nil {
		t.Error("the last good interface discovery outlived its age bound")
	}
}

// A partial interface answer is a failed discovery, not a smaller good one.
func TestAPartialInterfaceAnswerIsAFailure(t *testing.T) {
	pinTargetGuard(t)
	lastIfaceMu.Lock()
	lastIfaceDeny, lastIfaceState = nil, discovered{}
	lastIfaceMu.Unlock()
	hostInterfaces = func() ([]ifaceAddr, error) {
		return []ifaceAddr{{name: "lo", prefix: netip.MustParsePrefix("127.0.0.1/8")}}, errors.New("addresses of podman1: busy")
	}
	if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.20.0.0/16"}}); err == nil {
		t.Error("a partial interface answer was taken as complete")
	}
}

// (c) The API judges a write only against a complete denylist in its own
// process: an instance whose router list is not fresh reads it first, and
// answers 503 when it cannot.
func TestTheAPIRefusesWritesWithAnIncompleteDenylist(t *testing.T) {
	pinTargetGuard(t)
	resetRouterHosts(t, false)
	gin.SetMode(gin.TestMode)
	svc := &Service{logger: zap.NewNop()} // no Ziti controller connection
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("PUT", "/x", nil)
	if svc.networkGuardReady(c) {
		t.Fatal("a write was let through with no router list")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("answered %d, want 503", w.Code)
	}

	// With a controller, a stale instance reads the routers and proceeds.
	f := newFakeNetCtrl()
	f.routers = []interface{}{map[string]interface{}{"hostname": "edge9.corp.example"}}
	zm := newNetTestManager(t, f)
	svc.zitiProvider = &ZitiProvider{}
	svc.zitiProvider.Store(zm)
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("PUT", "/x", nil)
	if !svc.networkGuardReady(c) {
		t.Fatalf("a write was refused after the routers were readable: %s", w.Body.String())
	}
	if _, err := normalizeNetworkTarget(NetworkTarget{Hosts: []string{"edge9.corp.example"}}); err == nil {
		t.Error("the router the API just read is not in its denylist")
	}
}

// (b) Drift on the controller is repaired on every good pass: the service's
// configs, attributes and encryption; a config's data or type; the Dial and
// Bind policies; the service-edge-router policy; a per-org Dial policy left
// behind. A policy the reconciler did not write that applies to the service
// removes the service.
func TestDriftOnTheControllerIsRepaired(t *testing.T) {
	f, zm, rec, d := failClosedFixture(t)
	resetRouterHosts(t, true, "edge1.corp.example")
	rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) { return []DesiredNetworkService{d}, nil }
	pass := func() { rec.reconcileNetworkServices(context.Background(), zm) }
	pass()

	find := func(m map[string]map[string]interface{}, name string) map[string]interface{} {
		for _, v := range m {
			if v["name"] == name {
				return v
			}
		}
		return nil
	}
	f.mu.Lock()
	svc := find(f.services, d.ServiceName)
	f.configs["cfg-foreign"] = map[string]interface{}{"id": "cfg-foreign", "name": "someone-elses", "data": map[string]interface{}{}}
	svc["configs"] = append(svc["configs"].([]interface{}), "cfg-foreign")
	svc["roleAttributes"] = []interface{}{d.ServiceName, "openidx-managed", "browzer-enabled"}
	svc["encryptionRequired"] = false
	find(f.configs, d.ServiceName+"-intercept")["data"] = map[string]interface{}{
		"protocols": []interface{}{"tcp"}, "addresses": []interface{}{"127.0.0.1"},
		"portRanges": []interface{}{map[string]interface{}{"low": 5432, "high": 5432}}}
	find(f.policies, "openidx-dial-"+d.ServiceName)["identityRoles"] = []interface{}{"#all"}
	find(f.policies, "openidx-dial-"+d.ServiceName)["semantic"] = "AnyOf"
	find(f.policies, "openidx-bind-"+d.ServiceName)["identityRoles"] = []interface{}{"#all"}
	f.serps["openidx-serp-"+d.ServiceName]["edgeRouterRoles"] = []interface{}{"#rogue"}
	f.policies["sp-org"] = map[string]interface{}{"id": "sp-org", "name": "openidx-orgdial-" + d.ServiceName, "type": "Dial",
		"serviceRoles": []interface{}{"#" + d.ServiceName}, "identityRoles": []interface{}{"#org-org-1"}}
	f.mu.Unlock()

	pass()
	if st := rec.StatusSnapshot()[d.ServiceName]; st != "synced" {
		t.Fatalf("status after repair = %q", st)
	}
	f.mu.Lock()
	svc = find(f.services, d.ServiceName)
	if cfgs := svc["configs"]; len(asStrings(cfgs)) != 2 || strings.Contains(strings.Join(asStrings(cfgs), ","), "cfg-foreign") {
		t.Errorf("service configs after repair = %v", cfgs)
	}
	if attrs := asStrings(svc["roleAttributes"]); !sameRoleSet(attrs, []string{d.ServiceName, "openidx-managed"}) {
		t.Errorf("service attributes after repair = %v", attrs)
	}
	if svc["encryptionRequired"] != true {
		t.Errorf("encryptionRequired after repair = %v", svc["encryptionRequired"])
	}
	if addrs := asStrings(find(f.configs, d.ServiceName+"-intercept")["data"].(map[string]interface{})["addresses"]); strings.Join(addrs, ",") != "10.20.0.0/16" {
		t.Errorf("intercept addresses after repair = %v", addrs)
	}
	dial := find(f.policies, "openidx-dial-"+d.ServiceName)
	if dial["semantic"] != "AllOf" || !sameRoleSet(asStrings(dial["identityRoles"]), []string{"#app-" + d.ApplicationID, "#device-trusted", "#openidx-agent"}) {
		t.Errorf("dial policy after repair = %v", dial)
	}
	if bind := find(f.policies, "openidx-bind-"+d.ServiceName); !sameRoleSet(asStrings(bind["identityRoles"]), []string{"#ziti-routers"}) {
		t.Errorf("bind policy after repair = %v", bind)
	}
	if serp := f.serps["openidx-serp-"+d.ServiceName]; serp == nil || !sameRoleSet(asStrings(serp["edgeRouterRoles"]), []string{"#all"}) {
		t.Errorf("serp after repair = %v", serp)
	}
	if find(f.policies, "openidx-orgdial-"+d.ServiceName) != nil {
		t.Error("the per-org Dial policy left behind was not removed")
	}
	f.mu.Unlock()

	// A config of the right name but another type is replaced.
	f.mu.Lock()
	find(f.configs, d.ServiceName+"-host")["configTypeId"] = "some-other-type"
	f.mu.Unlock()
	pass()
	f.mu.Lock()
	if ct := find(f.configs, d.ServiceName+"-host")["configTypeId"]; ct != "host-type" {
		t.Errorf("host config type after repair = %v", ct)
	}
	f.mu.Unlock()

	// A policy the reconciler did not write that reaches the service.
	f.mu.Lock()
	f.policies["sp-wild"] = map[string]interface{}{"id": "sp-wild", "name": "openidx-gov-everything", "type": "Dial",
		"serviceRoles": []interface{}{"#all"}, "identityRoles": []interface{}{"#all"}}
	f.mu.Unlock()
	pass()
	if f.has("service", d.ServiceName) || f.has("policy", "openidx-dial-"+d.ServiceName) {
		t.Error("the service stayed live while a foreign policy applied to it")
	}
	if st := rec.StatusSnapshot()[d.ServiceName]; !strings.Contains(st, "openidx-gov-everything") {
		t.Errorf("status %q does not name the foreign policy", st)
	}
}

func asStrings(v interface{}) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, _ := e.(string)
			out = append(out, s)
		}
		return out
	}
	return nil
}
