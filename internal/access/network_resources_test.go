package access

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

func TestNetworkTargetNormalization(t *testing.T) {
	pinTargetGuard(t)
	got, err := normalizeNetworkTarget(NetworkTarget{
		Hosts:      []string{" fs1.corp.example ", "10.0.0.5", "fs1.corp.example"},
		CIDRs:      []string{"10.20.3.4/16"},
		DNSNames:   []string{"*.Corp.Example"},
		PortRanges: []PortRange{{Low: 8000, High: 8100}, {Low: 445}},
		Protocols:  []string{"TCP"},
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	want := NetworkTarget{
		Hosts:      []string{"fs1.corp.example", "10.0.0.5"},
		CIDRs:      []string{"10.20.0.0/16"},
		DNSNames:   []string{"*.corp.example"},
		PortRanges: []PortRange{{Low: 445, High: 445}, {Low: 8000, High: 8100}},
		Protocols:  []string{"tcp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized to %+v\nwant %+v", got, want)
	}

	defaults, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"192.168.1.0/24"}})
	if err != nil {
		t.Fatalf("normalize defaults: %v", err)
	}
	if !reflect.DeepEqual(defaults.Protocols, []string{"tcp", "udp"}) {
		t.Errorf("protocols default to %v, want tcp+udp", defaults.Protocols)
	}
	if !reflect.DeepEqual(defaults.PortRanges, []PortRange{{1, 65535}}) {
		t.Errorf("ports default to %v, want every port", defaults.PortRanges)
	}
}

func TestNetworkTargetValidationRefuses(t *testing.T) {
	pinTargetGuard(t)
	for name, tgt := range map[string]NetworkTarget{
		"no address":         {},
		"bad CIDR":           {CIDRs: []string{"10.0.0.0/33"}},
		"default route":      {CIDRs: []string{"0.0.0.0/0"}},
		"bad host":           {Hosts: []string{"bad host!"}},
		"bare DNS label":     {DNSNames: []string{"intranet"}},
		"port 0":             {Hosts: []string{"a.example"}, PortRanges: []PortRange{{Low: 0, High: 10}}},
		"port above 65535":   {Hosts: []string{"a.example"}, PortRanges: []PortRange{{Low: 1, High: 70000}}},
		"inverted range":     {Hosts: []string{"a.example"}, PortRanges: []PortRange{{Low: 90, High: 80}}},
		"protocol icmp":      {Hosts: []string{"a.example"}, Protocols: []string{"icmp"}},
		"forward port 70000": {Hosts: []string{"a.example"}, ForwardPort: 70000},
		"forward address ws": {Hosts: []string{"a.example"}, ForwardAddress: "no such host"},
	} {
		if _, err := normalizeNetworkTarget(tgt); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNetworkConfigData(t *testing.T) {
	pinTargetGuard(t)
	tgt, _ := normalizeNetworkTarget(NetworkTarget{
		Hosts: []string{"fs1.corp.example"}, CIDRs: []string{"10.20.0.0/16"},
		PortRanges: []PortRange{{Low: 445, High: 445}},
	})
	icpt := interceptV1Data(tgt)
	if !reflect.DeepEqual(icpt["addresses"], []string{"fs1.corp.example", "10.20.0.0/16"}) {
		t.Errorf("intercept addresses = %v", icpt["addresses"])
	}
	if !reflect.DeepEqual(icpt["protocols"], []string{"tcp", "udp"}) {
		t.Errorf("intercept protocols = %v", icpt["protocols"])
	}

	// No forward address: the router forwards what was dialed, within the
	// resource's own addresses, ports and protocols.
	host := hostV1Data(tgt)
	for _, k := range []string{"forwardAddress", "forwardPort", "forwardProtocol"} {
		if host[k] != true {
			t.Errorf("host.v1 %s = %v, want true", k, host[k])
		}
	}
	if !reflect.DeepEqual(host["allowedAddresses"], icpt["addresses"]) {
		t.Errorf("allowedAddresses %v differ from the intercepted addresses %v", host["allowedAddresses"], icpt["addresses"])
	}
	if _, ok := host["address"]; ok {
		t.Error("host.v1 carries a fixed address beside forwardAddress")
	}

	// A fixed forward target and a single protocol pin all three.
	tgt.ForwardAddress, tgt.ForwardPort, tgt.Protocols = "10.20.0.10", 3389, []string{"tcp"}
	host = hostV1Data(tgt)
	if host["address"] != "10.20.0.10" || host["port"] != 3389 || host["protocol"] != "tcp" {
		t.Errorf("fixed host.v1 = %v", host)
	}
	for _, k := range []string{"forwardAddress", "forwardPort", "forwardProtocol"} {
		if _, ok := host[k]; ok {
			t.Errorf("fixed host.v1 still sets %s", k)
		}
	}
}

func TestNetworkDialPolicyNamesDevices(t *testing.T) {
	const app = "11111111-1111-1111-1111-111111111111"
	cases := []struct {
		name           string
		enforce, trust bool
		roles          []string
		semantic       string
	}{
		{"observe", false, false, []string{"#openidx-agent", "#app-" + app}, "AnyOf"},
		{"observe, trusted device", false, true, []string{"#openidx-agent", "#app-" + app}, "AnyOf"},
		{"enforce", true, false, []string{"#app-" + app, "#openidx-agent"}, "AllOf"},
		{"enforce, trusted device", true, true, []string{"#app-" + app, "#device-trusted", "#openidx-agent"}, "AllOf"},
	}
	for _, c := range cases {
		roles, sem := networkDialPolicy(app, c.enforce, c.trust)
		if !sameRoleSet(roles, c.roles) || sem != c.semantic {
			t.Errorf("%s: got %v %s, want %v %s", c.name, roles, sem, c.roles, c.semantic)
		}
	}
}

func TestNetworkServiceNameIsReserved(t *testing.T) {
	if !reservedZitiServiceName(networkServiceName("abc")) {
		t.Error("a network resource's service name can be claimed by a route or a free-form service")
	}
}

func TestParseNetworkImportCSV(t *testing.T) {
	pinTargetGuard(t)
	in := "Name,Hosts,CIDRs,DNS_Names,Ports,Protocols,Group\n" +
		"# a comment line\n" +
		"File servers,fs1.corp.example;fs2.corp.example,,,445,tcp,Finance\n" +
		"Lab,,10.50.0.0/16,,22;8000-8100,,\n" +
		"Broken,,10.0.0.0/40,,,,\n" +
		",,10.1.0.0/16,,,,\n"
	rows, err := parseNetworkImportCSV(strings.NewReader(in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("%d rows, want 4", len(rows))
	}
	if rows[0].Error != "" || rows[0].Group != "Finance" || len(rows[0].Target.Hosts) != 2 ||
		!reflect.DeepEqual(rows[0].Target.PortRanges, []PortRange{{445, 445}}) {
		t.Errorf("row 1 = %+v", rows[0])
	}
	if rows[1].Error != "" || !reflect.DeepEqual(rows[1].Target.PortRanges, []PortRange{{22, 22}, {8000, 8100}}) {
		t.Errorf("row 2 = %+v", rows[1])
	}
	if rows[2].Error == "" {
		t.Error("a row with a bad CIDR carries no error")
	}
	if rows[3].Error == "" {
		t.Error("a row with no name carries no error")
	}
	if _, err := parseNetworkImportCSV(strings.NewReader("hosts\nx\n")); err == nil {
		t.Error("a header without a name column was accepted")
	}
}

func TestTunnelStatusNormalize(t *testing.T) {
	ts := &agentTunnelStatus{
		State: "UP", Version: "v1.2.3", LastSeen: "not a time", DialFailures: 2,
		Services: []agentTunnelService{{Name: "a", DialFailures: 3}, {Name: "b", DialFailures: -4}},
	}
	if n := ts.normalize(); n != 5 {
		t.Errorf("dial failures counted = %d, want 5", n)
	}
	if ts.State != "up" || ts.LastSeen != "" || ts.Services[1].DialFailures != 0 {
		t.Errorf("normalized to %+v", ts)
	}
	odd := &agentTunnelStatus{State: "<script>"}
	odd.normalize()
	if odd.State != "unknown" {
		t.Errorf("an unknown state was stored as %q", odd.State)
	}
}

// fakeNetCtrl is a stateful Ziti management API: enough of configs, services,
// service policies and service-edge-router policies for the network reconciler
// to converge against, and a record of every write.
type fakeNetCtrl struct {
	mu       sync.Mutex
	next     int
	configs  map[string]map[string]interface{} // id -> {id,name,data}
	services map[string]map[string]interface{} // id -> {id,name,roleAttributes,configs}
	policies map[string]map[string]interface{} // id -> policy
	serps    map[string]string                 // name -> id
	writes   []string
}

func newFakeNetCtrl() *fakeNetCtrl {
	return &fakeNetCtrl{
		configs: map[string]map[string]interface{}{}, services: map[string]map[string]interface{}{},
		policies: map[string]map[string]interface{}{}, serps: map[string]string{},
	}
}

func (f *fakeNetCtrl) id(prefix string) string { f.next++; return fmt.Sprintf("%s-%d", prefix, f.next) }

func netFilterName(r *http.Request) string {
	fv := r.URL.Query().Get("filter")
	_, v, ok := strings.Cut(fv, "=")
	if !ok {
		return ""
	}
	if s, err := strconv.Unquote(strings.TrimSpace(v)); err == nil {
		return s
	}
	return ""
}

func (f *fakeNetCtrl) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

func (f *fakeNetCtrl) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	body, _ := io.ReadAll(r.Body)
	var in map[string]interface{}
	_ = json.Unmarshal(body, &in)
	if r.Method != http.MethodGet {
		f.writes = append(f.writes, r.Method+" "+r.URL.Path)
	}
	reply := func(status int, v interface{}) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": v})
	}
	listByName := func(m map[string]map[string]interface{}) {
		name := netFilterName(r)
		out := []interface{}{}
		for _, v := range m {
			if name == "" || v["name"] == name {
				out = append(out, v)
			}
		}
		reply(http.StatusOK, out)
	}
	const base = "/edge/management/v1/"
	path := strings.TrimPrefix(r.URL.Path, base)
	coll, id, _ := strings.Cut(path, "/")
	switch {
	case coll == "configs" && r.Method == http.MethodGet:
		listByName(f.configs)
	case coll == "configs" && r.Method == http.MethodPost:
		nid := f.id("cfg")
		f.configs[nid] = map[string]interface{}{"id": nid, "name": in["name"], "data": in["data"]}
		reply(http.StatusCreated, map[string]string{"id": nid})
	case coll == "configs" && r.Method == http.MethodPatch:
		f.configs[id]["data"] = in["data"]
		reply(http.StatusOK, map[string]string{})
	case coll == "configs" && r.Method == http.MethodDelete:
		delete(f.configs, id)
		reply(http.StatusOK, map[string]string{})
	case coll == "services" && id == "" && r.Method == http.MethodGet:
		listByName(f.services)
	case coll == "services" && r.Method == http.MethodPost:
		nid := f.id("svc")
		f.services[nid] = map[string]interface{}{"id": nid, "name": in["name"], "roleAttributes": in["roleAttributes"], "configs": in["configs"]}
		reply(http.StatusCreated, map[string]string{"id": nid})
	case coll == "services" && r.Method == http.MethodGet:
		reply(http.StatusOK, f.services[id])
	case coll == "services" && r.Method == http.MethodPatch:
		for k, v := range in {
			f.services[id][k] = v
		}
		reply(http.StatusOK, map[string]string{})
	case coll == "services" && r.Method == http.MethodDelete:
		delete(f.services, id)
		reply(http.StatusOK, map[string]string{})
	case coll == "service-policies" && r.Method == http.MethodGet:
		listByName(f.policies)
	case coll == "service-policies" && r.Method == http.MethodPost:
		nid := f.id("sp")
		in["id"] = nid
		f.policies[nid] = in
		reply(http.StatusCreated, map[string]string{"id": nid})
	case coll == "service-policies" && r.Method == http.MethodPut:
		in["id"] = id
		f.policies[id] = in
		reply(http.StatusOK, map[string]string{})
	case coll == "service-policies" && r.Method == http.MethodDelete:
		delete(f.policies, id)
		reply(http.StatusOK, map[string]string{})
	case coll == "service-edge-router-policies" && r.Method == http.MethodGet:
		out := []interface{}{}
		if sid, ok := f.serps[netFilterName(r)]; ok {
			out = append(out, map[string]string{"id": sid, "name": netFilterName(r)})
		}
		reply(http.StatusOK, out)
	case coll == "service-edge-router-policies" && r.Method == http.MethodPost:
		name, _ := in["name"].(string)
		if _, ok := f.serps[name]; ok {
			reply(http.StatusBadRequest, map[string]string{})
			return
		}
		f.serps[name] = f.id("serp")
		reply(http.StatusCreated, map[string]string{"id": f.serps[name]})
	case coll == "service-edge-router-policies" && r.Method == http.MethodDelete:
		for n, v := range f.serps {
			if v == id {
				delete(f.serps, n)
			}
		}
		reply(http.StatusOK, map[string]string{})
	case coll == "edge-routers" && r.Method == http.MethodGet:
		reply(http.StatusOK, []interface{}{})
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"NOT_FOUND"}}`))
	}
}

func newNetTestManager(t *testing.T, f *fakeNetCtrl) *ZitiManager {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &ZitiManager{
		cfg:             &config.Config{ZitiEnabled: true, ZitiCtrlURL: srv.URL},
		logger:          zap.NewNop(),
		mgmtClient:      &http.Client{Timeout: 5 * time.Second},
		mgmtToken:       "fake",
		hostedServices:  make(map[string]*hostedService),
		configTypeCache: map[string]string{"host.v1": "host-type", "intercept.v1": "intercept-type"},
		initialized:     true,
	}
}

func TestEnsureNetworkServiceConvergesAndIsIdempotent(t *testing.T) {
	pinTargetGuard(t)
	f := newFakeNetCtrl()
	zm := newNetTestManager(t, f)
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}, assignmentEnforce: true}
	const app = "22222222-2222-2222-2222-222222222222"
	tgt, _ := normalizeNetworkTarget(NetworkTarget{
		CIDRs: []string{"10.20.0.0/16"}, DNSNames: []string{"*.corp.example"},
		PortRanges: []PortRange{{Low: 445, High: 445}},
	})
	d := DesiredNetworkService{ApplicationID: app, OrgID: "org-1", ServiceName: networkServiceName(app), Target: tgt, RequireDeviceTrust: true}

	if err := rec.ensureNetworkService(context.Background(), zm, d); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	if len(f.services) != 1 {
		t.Fatalf("%d services, want 1", len(f.services))
	}
	var svc map[string]interface{}
	for _, s := range f.services {
		svc = s
	}
	if svc["name"] != d.ServiceName {
		t.Errorf("service named %v, want %s", svc["name"], d.ServiceName)
	}
	cfgs, _ := svc["configs"].([]interface{})
	if len(cfgs) != 2 {
		t.Errorf("service carries %d configs, want host.v1 and intercept.v1", len(cfgs))
	}
	var intercept map[string]interface{}
	for _, c := range f.configs {
		if c["name"] == d.ServiceName+"-intercept" {
			intercept, _ = c["data"].(map[string]interface{})
		}
	}
	if intercept == nil || !reflect.DeepEqual(intercept["addresses"], []interface{}{"10.20.0.0/16", "*.corp.example"}) {
		t.Errorf("intercept.v1 data = %v", intercept)
	}
	var dial, bind map[string]interface{}
	for _, p := range f.policies {
		switch p["name"] {
		case "openidx-dial-" + d.ServiceName:
			dial = p
		case "openidx-bind-" + d.ServiceName:
			bind = p
		}
	}
	if dial == nil || dial["semantic"] != "AllOf" {
		t.Fatalf("dial policy = %v, want AllOf", dial)
	}
	gotRoles := []string{}
	for _, r := range dial["identityRoles"].([]interface{}) {
		gotRoles = append(gotRoles, r.(string))
	}
	if !sameRoleSet(gotRoles, []string{"#app-" + app, "#device-trusted", "#openidx-agent"}) {
		t.Errorf("dial roles = %v", gotRoles)
	}
	if bind == nil || !reflect.DeepEqual(bind["identityRoles"], []interface{}{"#ziti-routers"}) {
		t.Errorf("bind policy = %v", bind)
	}

	// A second pass over the converged controller writes nothing.
	before := f.writeCount()
	if err := rec.ensureNetworkService(context.Background(), zm, d); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	f.mu.Lock()
	extra := f.writes[before:]
	f.mu.Unlock()
	if len(extra) != 0 {
		t.Errorf("a pass over a converged controller wrote %v", extra)
	}

	// A changed target patches the config in place: same id, new data.
	d.Target.PortRanges = []PortRange{{Low: 445, High: 445}, {Low: 3389, High: 3389}}
	if err := rec.ensureNetworkService(context.Background(), zm, d); err != nil {
		t.Fatalf("third pass: %v", err)
	}
	if len(f.configs) != 2 || len(f.services) != 1 {
		t.Errorf("a target change created objects: %d configs, %d services", len(f.configs), len(f.services))
	}
	for _, c := range f.configs {
		if c["name"] == d.ServiceName+"-intercept" {
			pr := c["data"].(map[string]interface{})["portRanges"].([]interface{})
			if len(pr) != 2 {
				t.Errorf("intercept port ranges after the change = %v", pr)
			}
		}
	}
}

func TestPruneNetworkServicesRemovesOnlyUndesired(t *testing.T) {
	pinTargetGuard(t)
	f := newFakeNetCtrl()
	zm := newNetTestManager(t, f)
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}}
	mk := func(app string) DesiredNetworkService {
		tgt, _ := normalizeNetworkTarget(NetworkTarget{Hosts: []string{"10.0.0.1"}})
		return DesiredNetworkService{ApplicationID: app, OrgID: "org-1", ServiceName: networkServiceName(app), Target: tgt}
	}
	keep, gone := mk("keep"), mk("gone")
	for _, d := range []DesiredNetworkService{keep, gone} {
		if err := rec.ensureNetworkService(context.Background(), zm, d); err != nil {
			t.Fatalf("ensure %s: %v", d.ServiceName, err)
		}
	}
	// A service the reconciler does not own is never touched.
	f.mu.Lock()
	f.services["other"] = map[string]interface{}{"id": "other", "name": "someone-elses-service"}
	f.mu.Unlock()

	rec.pruneNetworkServices(context.Background(), zm, []DesiredNetworkService{keep})

	names := map[string]bool{}
	for _, s := range f.services {
		names[s["name"].(string)] = true
	}
	if !names[keep.ServiceName] || names[gone.ServiceName] || !names["someone-elses-service"] {
		t.Errorf("services after prune: %v", names)
	}
	for _, p := range f.policies {
		if strings.HasSuffix(p["name"].(string), gone.ServiceName) {
			t.Errorf("policy %v of the pruned service remains", p["name"])
		}
	}
	for _, c := range f.configs {
		if strings.HasPrefix(c["name"].(string), gone.ServiceName) {
			t.Errorf("config %v of the pruned service remains", c["name"])
		}
	}
	if _, ok := f.serps["openidx-serp-"+gone.ServiceName]; ok {
		t.Error("the pruned service's service-edge-router policy remains")
	}
}
