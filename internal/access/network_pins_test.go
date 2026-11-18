package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestPinnableMeansExactlyOneNonWildcardName(t *testing.T) {
	cases := []struct {
		name string
		t    NetworkTarget
		want bool
	}{
		{"one name", NetworkTarget{DNSNames: []string{"wiki.corp.example"}}, true},
		{"two names", NetworkTarget{DNSNames: []string{"a.corp.example", "b.corp.example"}}, false},
		{"a name and a host", NetworkTarget{DNSNames: []string{"a.corp.example"}, Hosts: []string{"10.0.0.5"}}, false},
		{"a name and a range", NetworkTarget{DNSNames: []string{"a.corp.example"}, CIDRs: []string{"10.0.0.0/24"}}, false},
		{"a wildcard", NetworkTarget{DNSNames: []string{"*.corp.example"}}, false},
		{"no name", NetworkTarget{Hosts: []string{"10.0.0.5"}}, false},
		{"nothing", NetworkTarget{}, false},
	}
	for _, c := range cases {
		if got := c.t.pinnable(); got != c.want {
			t.Errorf("%s: pinnable = %v, want %v", c.name, got, c.want)
		}
	}
}

// The service must keep working for a device that knows nothing about pins:
// the name stays in the intercept addresses, the pin is added beside it, and
// a dial to the pin is forwarded to the one name the resource has.
func TestPinnedServiceConfigs(t *testing.T) {
	base := NetworkTarget{DNSNames: []string{"wiki.corp.example"}, PortRanges: []PortRange{{Low: 443, High: 443}}, Protocols: []string{"tcp"}}

	in, host := interceptV1Data(base), hostV1Data(base)
	if got := in["addresses"].([]string); !reflect.DeepEqual(got, []string{"wiki.corp.example"}) {
		t.Errorf("unpinned intercept addresses = %v", got)
	}
	if host["forwardAddress"] != true || host["address"] != nil {
		t.Errorf("unpinned host.v1 must still forward what was dialed: %v", host)
	}

	pinned := base
	pinned.PinIP = "100.127.0.10"
	in, host = interceptV1Data(pinned), hostV1Data(pinned)
	if got := in["addresses"].([]string); !reflect.DeepEqual(got, []string{"wiki.corp.example", "100.127.0.10"}) {
		t.Errorf("pinned intercept addresses = %v, want the name and the pin", got)
	}
	if host["address"] != "wiki.corp.example" || host["forwardAddress"] == true || host["allowedAddresses"] != nil {
		t.Errorf("a dial to the pin must be forwarded to the name, not to the pin: %v", host)
	}
	if host["forwardPort"] != true || host["allowedPortRanges"] == nil {
		t.Errorf("the port still follows the dial, bounded by the resource's ranges: %v", host)
	}

	pinned.ForwardAddress, pinned.ForwardPort = "10.9.9.9", 8443
	host = hostV1Data(pinned)
	if host["address"] != "10.9.9.9" || host["port"] != 8443 {
		t.Errorf("an explicit forward address and port win over the name: %v", host)
	}
}

func TestOnlyAServerPinMayLieInsideTheTunnelersRange(t *testing.T) {
	pinTargetGuard(t)
	target := NetworkTarget{DNSNames: []string{"wiki.corp.example"}, PortRanges: []PortRange{{Low: 443, High: 443}}, Protocols: []string{"tcp"}}
	build := func(pin string) (map[string]interface{}, map[string]interface{}) {
		tt := target
		tt.PinIP = pin
		return interceptV1Data(tt), hostV1Data(tt)
	}

	in, host := build("100.127.0.10")
	if errs := guardEmittedConfigsPinned(in, host, "100.127.0.10"); len(errs) != 0 {
		t.Errorf("a pin from the pool was refused: %v", errs)
	}
	// Without the pinned path the same addresses are refused: the exception is
	// only for what the server allocated.
	if errs := guardEmittedConfigs(in, host); len(errs) == 0 || !strings.Contains(strings.Join(errs, " "), "100.64.0.0/10") {
		t.Errorf("the general guard must still refuse the tunneler's range, got %v", errs)
	}
	for _, bad := range []string{"100.64.0.5", "100.126.255.1", "10.0.0.9", "127.0.0.1", "100.127.000.010", "100.127.0.10/32", "not-an-ip", "::1"} {
		in, host := build(bad)
		if errs := guardEmittedConfigsPinned(in, host, bad); len(errs) == 0 {
			t.Errorf("pin %q was accepted", bad)
		}
	}
	// A pin the configs do not carry is a mistake, not an allowance.
	in, host = build("")
	if errs := guardEmittedConfigsPinned(in, host, "100.127.0.10"); len(errs) == 0 {
		t.Error("a pin that is not among the intercept addresses was accepted")
	}
	// The rest of the target is still judged: a pin does not excuse a platform name.
	bad := target
	bad.DNSNames = []string{"localhost"}
	bad.PinIP = "100.127.0.10"
	if errs := guardEmittedConfigsPinned(interceptV1Data(bad), hostV1Data(bad), bad.PinIP); len(errs) == 0 {
		t.Error("a pinned target naming the platform was accepted")
	}
}

func TestARequestCannotChooseAPin(t *testing.T) {
	pinTargetGuard(t)
	got, err := normalizeNetworkTarget(NetworkTarget{
		DNSNames: []string{"wiki.corp.example"}, PortRanges: []PortRange{{Low: 443, High: 443}},
		Protocols: []string{"tcp"}, PinIP: "100.127.0.99",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.PinIP != "" {
		t.Errorf("a pin supplied by the request survived normalization: %q", got.PinIP)
	}
}

// Every organization that has not turned the setting on must keep the version
// its devices already report: the digest has not changed for them.
func TestPolicyVersionIsUnchangedUntilNameResolutionIsOn(t *testing.T) {
	old := func(p agentNetworkPolicy) string {
		h := sha256.New()
		fmt.Fprintf(h, "v1|%t|%t|%t|%s", p.AlwaysOn, p.SplitTunnel, p.BlockDirectCorporateCIDRs, strings.Join(p.CorporateCIDRs, ","))
		return hex.EncodeToString(h.Sum(nil))[:16]
	}
	p := agentNetworkPolicy{AlwaysOn: true, SplitTunnel: true, CorporateCIDRs: []string{"10.0.0.0/16"}}
	if got, want := policyVersion(p), old(p); got != want {
		t.Fatalf("version moved for an organization that did nothing: %s, was %s", got, want)
	}
	on := p
	on.NameResolution = nameResolutionAgent
	if policyVersion(on) == policyVersion(p) {
		t.Error("turning name resolution on did not move the version")
	}
	// Pins are per device and stay out of the version the console compares.
	withPins := on
	withPins.NamePins = []namePin{{Name: "wiki.corp.example", IP: "100.127.0.10"}}
	withPins.NamePinsVersion = "x"
	if policyVersion(withPins) != policyVersion(on) {
		t.Error("the pins moved the organization's policy version")
	}
}

func TestNamePinsVersion(t *testing.T) {
	if namePinsVersion(nil) != "" || namePinsVersion([]namePin{}) != "" {
		t.Error("no pins must have no version")
	}
	a := []namePin{{Name: "a.example", IP: "100.127.0.10"}, {Name: "b.example", IP: "100.127.0.11"}}
	v := namePinsVersion(a)
	if len(v) != 16 || v != namePinsVersion(append([]namePin(nil), a...)) {
		t.Errorf("version %q is not a stable 16-character digest", v)
	}
	changed := []namePin{{Name: "a.example", IP: "100.127.0.10"}, {Name: "b.example", IP: "100.127.0.12"}}
	if namePinsVersion(changed) == v {
		t.Error("a different address gave the same version")
	}
	moved := []namePin{{Name: "a.example", IP: "100.127.0.10", Service: "openidx-net-1"}, {Name: "b.example", IP: "100.127.0.11"}}
	if namePinsVersion(moved) == v {
		t.Error("a different service gave the same version")
	}
}

// configData is the data the controller holds for the named config, as JSON
// decoded (the fake keeps what was posted).
func (f *fakeNetCtrl) configData(name string) map[string]interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.configs {
		if c["name"] == name {
			m, _ := c["data"].(map[string]interface{})
			return m
		}
	}
	return nil
}

func pinnedDesired(t *testing.T, pin string) DesiredNetworkService {
	t.Helper()
	tgt, err := normalizeNetworkTarget(NetworkTarget{
		DNSNames: []string{"wiki.corp.example"}, PortRanges: []PortRange{{Low: 443, High: 443}}, Protocols: []string{"tcp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tgt.PinIP = pin
	const app = "44444444-4444-4444-4444-444444444444"
	return DesiredNetworkService{ApplicationID: app, OrgID: "org-1", ServiceName: networkServiceName(app), Target: tgt}
}

// What the controller ends up holding for a pinned resource: both addresses to
// intercept, and a router that forwards a dial of either to the one name.
func TestAPinnedResourceReachesTheControllerWithBothAddresses(t *testing.T) {
	f, zm, rec, _ := failClosedFixture(t)
	d := pinnedDesired(t, "100.127.0.10") // normalizes through the guard: before the router hosts are forgotten
	resetRouterHosts(t, false)
	rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) { return []DesiredNetworkService{d}, nil }
	rec.reconcileNetworkServices(context.Background(), zm)

	if !f.has("service", d.ServiceName) {
		t.Fatalf("the pinned service did not converge: %q", rec.StatusSnapshot()[d.ServiceName])
	}
	in := f.configData(d.ServiceName + "-intercept")
	addrs := toStrings(in["addresses"])
	if !reflect.DeepEqual(addrs, []string{"wiki.corp.example", "100.127.0.10"}) {
		t.Errorf("intercept addresses = %v", addrs)
	}
	host := f.configData(d.ServiceName + "-host")
	if host["address"] != "wiki.corp.example" || host["forwardAddress"] == true {
		t.Errorf("host.v1 = %v, want a fixed forward to the name", host)
	}

	// The setting going back to 'tunnel' drops the pin from the service, and
	// nothing else about it.
	d.Target.PinIP = ""
	rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) { return []DesiredNetworkService{d}, nil }
	rec.reconcileNetworkServices(context.Background(), zm)
	in = f.configData(d.ServiceName + "-intercept")
	if got := toStrings(in["addresses"]); !reflect.DeepEqual(got, []string{"wiki.corp.example"}) {
		t.Errorf("intercept addresses after the setting went back = %v", got)
	}
	if f.configData(d.ServiceName + "-host")["forwardAddress"] != true {
		t.Error("host.v1 did not go back to forwarding what was dialed")
	}
}

// A pin the guard does not recognize as the server's is not written: the
// service is taken off the overlay and the status says why.
func TestAPinOutsideThePoolIsNeverWritten(t *testing.T) {
	f, zm, rec, _ := failClosedFixture(t)
	var desired []DesiredNetworkService
	for _, bad := range []string{"100.64.0.5", "10.0.0.9"} {
		desired = append(desired, pinnedDesired(t, bad))
	}
	resetRouterHosts(t, false)
	for i, bad := range []string{"100.64.0.5", "10.0.0.9"} {
		d := desired[i]
		rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) { return []DesiredNetworkService{d}, nil }
		rec.reconcileNetworkServices(context.Background(), zm)
		if f.has("service", d.ServiceName) {
			t.Errorf("a service with the pin %s was created", bad)
		}
		if st := rec.StatusSnapshot()[d.ServiceName]; !strings.HasPrefix(st, "error:") || !strings.Contains(st, bad) {
			t.Errorf("pin %s: status %q, want an error naming it", bad, st)
		}
	}
}

func toStrings(v interface{}) []string {
	var out []string
	switch x := v.(type) {
	case []string:
		return x
	case []interface{}:
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
	}
	return out
}
