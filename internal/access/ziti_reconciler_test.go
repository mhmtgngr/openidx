package access

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

func TestEffectiveModeHop(t *testing.T) {
	if (DesiredRoute{HostingMode: "hop", BrowZerEnabled: true}).EffectiveMode() != HostingModeHop {
		t.Fatalf("explicit hop must win over browzer->direct, got %q", (DesiredRoute{HostingMode: "hop", BrowZerEnabled: true}).EffectiveMode())
	}
	if (DesiredRoute{HostingMode: "hop"}).EffectiveMode() != HostingModeHop {
		t.Fatalf("hop must be honored")
	}
	// regression: existing modes unchanged
	if (DesiredRoute{BrowZerEnabled: true}).EffectiveMode() != HostingModeDirect {
		t.Fatalf("browzer must still map to direct")
	}
	if (DesiredRoute{}).EffectiveMode() != HostingModeIdentity {
		t.Fatalf("default must still be identity")
	}
}

func TestParseHopAddr(t *testing.T) {
	cases := []struct {
		in, host string
		port     int
	}{
		{"127.0.0.1:8095", "127.0.0.1", 8095},
		{"127.0.0.1", "127.0.0.1", 8095}, // portless → default 8095 (no drift)
		{"hop.internal:9000", "hop.internal", 9000},
		{"", "", 8095},
	}
	for _, c := range cases {
		h, p := ParseHopAddr(c.in)
		if h != c.host || p != c.port {
			t.Fatalf("ParseHopAddr(%q)=(%q,%d) want (%q,%d)", c.in, h, p, c.host, c.port)
		}
	}
}

func TestDesiredRouteHostingModeNormalization(t *testing.T) {
	if got := (DesiredRoute{HostingMode: "identity", BrowZerEnabled: true}).EffectiveMode(); got != "direct" {
		t.Fatalf("browzer route should be direct, got %q", got)
	}
	if got := (DesiredRoute{HostingMode: "identity"}).EffectiveMode(); got != "identity" {
		t.Fatalf("expected identity, got %q", got)
	}
	if got := (DesiredRoute{}).EffectiveMode(); got != "identity" {
		t.Fatalf("expected identity default, got %q", got)
	}
	if got := (DesiredRoute{HostingMode: "direct"}).EffectiveMode(); got != "direct" {
		t.Fatalf("expected direct, got %q", got)
	}
}

func TestReconcilerCoalescesAndSerializes(t *testing.T) {
	var runs int32
	rec := newTestReconciler(func() { atomic.AddInt32(&runs, 1); time.Sleep(20 * time.Millisecond) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec.Start(ctx)
	for i := 0; i < 50; i++ {
		rec.Enqueue()
	}
	time.Sleep(150 * time.Millisecond)
	if n := atomic.LoadInt32(&runs); n == 0 || n > 8 {
		t.Fatalf("expected a small coalesced number of runs, got %d", n)
	}
}

func newTestReconciler(run func()) *ZitiReconciler {
	rec := &ZitiReconciler{
		logger:  zap.NewNop(),
		period:  time.Hour, // disable periodic in this test
		trigger: make(chan struct{}, 1),
		status:  make(map[string]string),
	}
	rec.runOnce = func(context.Context) { run() }
	return rec
}

func TestEnsureServiceCreatesWhenMissing(t *testing.T) {
	var created bool
	// After creation the GET must return the newly-created service so the
	// follow-up GetServiceByName (to fetch role attributes) succeeds.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/edge/management/v1/services":
			if !created {
				json.NewEncoder(w).Encode(map[string]interface{}{"data": []interface{}{}})
			} else {
				json.NewEncoder(w).Encode(map[string]interface{}{"data": []map[string]interface{}{
					{"id": "svc-id-1", "name": "openidx-Test", "roleAttributes": []string{"openidx-Test"}},
				}})
			}
		case r.Method == "POST" && r.URL.Path == "/edge/management/v1/services":
			created = true
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]string{"id": "svc-id-1"}})
		default:
			// GET /services/svc-id-1 for GetServiceRoleAttributes
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"roleAttributes": []string{"openidx-Test"},
			}})
		}
	}))
	defer srv.Close()
	zm := &ZitiManager{logger: zap.NewNop(), mgmtToken: "fake", mgmtClient: srv.Client(),
		cfg: &config.Config{ZitiCtrlURL: srv.URL}, initialized: true}
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}}
	if err := rec.ensureService(context.Background(), zm, DesiredRoute{ServiceName: "openidx-Test", ToURL: "http://10.0.0.9:80"}); err != nil {
		t.Fatalf("ensureService: %v", err)
	}
	if !created {
		t.Fatalf("expected service to be created")
	}
}

func TestEnsureHostingIdentityCallsHostService(t *testing.T) {
	zm := &ZitiManager{logger: zap.NewNop(), initialized: false}
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}}
	if err := rec.ensureHosting(context.Background(), zm,
		DesiredRoute{ServiceName: "openidx-Test", ToURL: "http://10.0.0.9:80", HostingMode: "identity"}); err == nil {
		t.Fatalf("expected error from HostService on uninitialized SDK")
	}
}

func TestEnsureHostingDirectIsNoop(t *testing.T) {
	// Phase 2: direct mode hosting is handled by the edge router via host.v1
	// (created in ensureService) + the router Bind (ensurePolicies), so the
	// hosting step itself is a no-op and must not error.
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}}
	if err := rec.ensureHosting(context.Background(), &ZitiManager{logger: zap.NewNop()},
		DesiredRoute{ServiceName: "x", BrowZerEnabled: true}); err != nil {
		t.Fatalf("direct mode hosting should be a no-op, got %v", err)
	}
}

func TestReconcileRouteRecordsSyncedStatus(t *testing.T) {
	// Use initialized=false so that HostService returns a deterministic error
	// ("ziti SDK not initialized") rather than launching a goroutine that would
	// panic on a nil zitiCtx. The point of this test is that reconcileRoute
	// always records a per-route status, regardless of which step fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/edge/management/v1/services" {
			json.NewEncoder(w).Encode(map[string]interface{}{"data": []map[string]interface{}{
				{"id": "svc1", "name": "openidx-Test", "roleAttributes": []string{"openidx-Test"}}}})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{}})
	}))
	defer srv.Close()
	zm := &ZitiManager{logger: zap.NewNop(), mgmtToken: "fake", mgmtClient: srv.Client(),
		cfg: &config.Config{ZitiCtrlURL: srv.URL}, initialized: false,
		hostedServices: make(map[string]*hostedService)}
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}}
	rec.reconcileRoute(context.Background(), zm,
		DesiredRoute{ServiceName: "openidx-Test", ToURL: "http://10.0.0.9:80", HostingMode: "identity"})
	got := rec.status["openidx-Test"]
	if got == "" {
		t.Fatalf("expected a per-route status to be recorded, got empty string")
	}
	// ensureService calls GetServiceByName which calls ListServices — the service
	// exists in the fake server's response, so ensureService and ensurePolicies
	// pass through. HostService fails because initialized=false, so the status
	// is recorded as an "error: ..." string.
	if got != "synced" && !strings.HasPrefix(got, "error:") {
		t.Fatalf("unexpected status %q — expected 'synced' or 'error: ...'", got)
	}
}

func TestEnsureHostingDirectCreatesHostV1AndRouterBind(t *testing.T) {
	var createdConfig, createdServiceWithConfig bool
	var bindIdentityRoles []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/edge/management/v1/configs" && r.Method == "POST":
			createdConfig = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"cfg-1"}}`))
		case r.URL.Path == "/edge/management/v1/services" && r.Method == "GET":
			if createdServiceWithConfig {
				// After creation the lookup must resolve so ensureService can
				// proceed to ensureServiceAttr / ensurePolicies.
				_, _ = w.Write([]byte(`{"data":[{"id":"svc-1","name":"psm-zt","roleAttributes":["psm-zt"]}]}`))
			} else {
				_, _ = w.Write([]byte(`{"data":[]}`)) // not yet present
			}
		case r.URL.Path == "/edge/management/v1/services" && r.Method == "POST":
			b, _ := io.ReadAll(r.Body)
			createdServiceWithConfig = bytesContains(b, "cfg-1")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"svc-1"}}`))
		case r.URL.Path == "/edge/management/v1/service-policies" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"data":[]}`)) // GetServicePolicyByName: none yet -> create
		case r.URL.Path == "/edge/management/v1/service-policies" && r.Method == "POST":
			b, _ := io.ReadAll(r.Body)
			if bytesContains(b, "Bind") {
				bindIdentityRoles = extractIdentityRoles(b)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"pol-1"}}`))
		case r.URL.Path == "/edge/management/v1/edge-routers" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"data":[]}`)) // EnsureRouterRoleAttribute list
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{}}`))
		}
	}))
	defer srv.Close()

	// The reconciler's live ZitiManager is supplied directly to reconcileRoute
	// (there is no rec.provider in the unit harness); per-service status is read
	// from rec.status under statusMu via setStatus, so we read the map directly.
	zm := &ZitiManager{logger: zap.NewNop(), mgmtToken: "fake", mgmtClient: srv.Client(),
		cfg: &config.Config{ZitiCtrlURL: srv.URL}, initialized: true,
		hostedServices: make(map[string]*hostedService)}
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}}

	d := DesiredRoute{ServiceName: "psm-zt", ToURL: "https://192.168.152.112:443", BrowZerEnabled: true}
	rec.reconcileRoute(context.Background(), zm, d)

	if !createdConfig {
		t.Fatal("direct mode must create a host.v1 config")
	}
	if !createdServiceWithConfig {
		t.Fatal("direct mode must create the service attached to the host.v1 config")
	}
	if len(bindIdentityRoles) != 1 || bindIdentityRoles[0] != "#ziti-routers" {
		t.Fatalf("direct Bind must grant #ziti-routers, got %+v", bindIdentityRoles)
	}
	if got := rec.status["psm-zt"]; got != "synced" {
		t.Fatalf("want synced, got %q", got)
	}
}

func TestEnsureServiceHopUsesHopAddr(t *testing.T) {
	// hop mode must point the per-app host.v1 config at the shared hop nginx
	// addr (the reconciler's hopAddr), NOT at the route's to_url.
	var cfgAddr, cfgPort interface{}
	var bindIdentityRoles []string
	createdServiceWithConfig := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/edge/management/v1/configs" && r.Method == "POST":
			var body map[string]interface{}
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &body)
			if data, ok := body["data"].(map[string]interface{}); ok {
				cfgAddr = data["address"]
				cfgPort = data["port"]
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"cfg-1"}}`))
		case r.URL.Path == "/edge/management/v1/services" && r.Method == "GET":
			if createdServiceWithConfig {
				_, _ = w.Write([]byte(`{"data":[{"id":"svc-1","name":"psm-zt","roleAttributes":["psm-zt"]}]}`))
			} else {
				_, _ = w.Write([]byte(`{"data":[]}`))
			}
		case r.URL.Path == "/edge/management/v1/services" && r.Method == "POST":
			b, _ := io.ReadAll(r.Body)
			createdServiceWithConfig = bytesContains(b, "cfg-1")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"svc-1"}}`))
		case r.URL.Path == "/edge/management/v1/service-policies" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"data":[]}`)) // GetServicePolicyByName: none yet -> create
		case r.URL.Path == "/edge/management/v1/service-policies" && r.Method == "POST":
			b, _ := io.ReadAll(r.Body)
			if bytesContains(b, "Bind") {
				bindIdentityRoles = extractIdentityRoles(b)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"pol-1"}}`))
		case r.URL.Path == "/edge/management/v1/edge-routers" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{}}`))
		}
	}))
	defer srv.Close()

	zm := &ZitiManager{logger: zap.NewNop(), mgmtToken: "fake", mgmtClient: srv.Client(),
		cfg: &config.Config{ZitiCtrlURL: srv.URL}, initialized: true,
		hostedServices: make(map[string]*hostedService)}
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}, hopAddr: "127.0.0.1:8095"}

	d := DesiredRoute{ServiceName: "psm-zt", ToURL: "https://psm.tdv.org:443", HostingMode: "hop", HopPort: 8095}
	rec.reconcileRoute(context.Background(), zm, d)

	if fmt.Sprint(cfgAddr) != "127.0.0.1" {
		t.Fatalf("hop host.v1 address must be the hop addr, got %v", cfgAddr)
	}
	// JSON numbers decode to float64; compare via Sprint to tolerate "8095".
	if fmt.Sprint(cfgPort) != "8095" {
		t.Fatalf("hop host.v1 port must be 8095, got %v", cfgPort)
	}
	if len(bindIdentityRoles) != 1 || bindIdentityRoles[0] != "#ziti-routers" {
		t.Fatalf("hop Bind must grant #ziti-routers (router-hosted), got %+v", bindIdentityRoles)
	}
	if got := rec.status["psm-zt"]; got != "synced" {
		t.Fatalf("want synced, got %q", got)
	}
}

func bytesContains(b []byte, s string) bool { return strings.Contains(string(b), s) }

func extractIdentityRoles(b []byte) []string {
	var p struct {
		IdentityRoles []string `json:"identityRoles"`
	}
	_ = json.Unmarshal(b, &p)
	return p.IdentityRoles
}

func TestEffectiveModeBrowZerIdentityPromotedToDirect(t *testing.T) {
	// identity mode is never valid for a BrowZer route; the resolver auto-
	// corrects it to a router-hosted mode (direct) so the dial policy is
	// granted to #browzer-users rather than #access-proxy-clients.
	d := DesiredRoute{ServiceName: "openidx-Test", BrowZerEnabled: true, HostingMode: HostingModeIdentity}
	if got := d.EffectiveMode(); got != HostingModeDirect {
		t.Fatalf("browzer+identity should promote to direct, got %q", got)
	}
}

func TestSameRoleSet(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{[]string{"#browzer-users"}, []string{"#browzer-users"}, true},
		{[]string{"#a", "#b"}, []string{"#b", "#a"}, true}, // order-insensitive
		{[]string{"#access-proxy-clients"}, []string{"#browzer-users"}, false},
		{[]string{"#a"}, []string{"#a", "#b"}, false},
		{nil, nil, true},
		{[]string{"#a", "#a"}, []string{"#a", "#b"}, false}, // multiset, not set
	}
	for i, c := range cases {
		if got := sameRoleSet(c.a, c.b); got != c.want {
			t.Errorf("case %d: sameRoleSet(%v,%v)=%v want %v", i, c.a, c.b, got, c.want)
		}
	}
}

func TestEnsureServicePolicyUpdatesStaleRoles(t *testing.T) {
	// An existing identity-mode dial policy (#access-proxy-clients) must be
	// UPDATED in place (PUT) to the desired #browzer-users when a route flips
	// to router-hosted — not left stale (the BrowZer-1003 self-heal).
	var putBody []byte
	var putHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/edge/management/v1/service-policies":
			_, _ = w.Write([]byte(`{"data":[{"id":"pol-1","name":"openidx-dial-openidx-Test","type":"Dial","serviceRoles":["#openidx-Test"],"identityRoles":["#access-proxy-clients"]}]}`))
		case r.Method == "PUT" && r.URL.Path == "/edge/management/v1/service-policies/pol-1":
			putHit = true
			putBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"id":"pol-1"}}`))
		case r.Method == "POST" && r.URL.Path == "/edge/management/v1/service-policies":
			t.Errorf("unexpected create POST — an existing policy must be updated in place")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"pol-x"}}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{}}`))
		}
	}))
	defer srv.Close()
	zm := &ZitiManager{logger: zap.NewNop(), mgmtToken: "fake", mgmtClient: srv.Client(),
		cfg: &config.Config{ZitiCtrlURL: srv.URL}, initialized: true}
	id, err := zm.EnsureServicePolicy(context.Background(), "openidx-dial-openidx-Test", "Dial",
		[]string{"#openidx-Test"}, []string{"#browzer-users"})
	if err != nil {
		t.Fatalf("EnsureServicePolicy: %v", err)
	}
	if id != "pol-1" {
		t.Fatalf("expected existing id pol-1, got %q", id)
	}
	if !putHit {
		t.Fatalf("expected a PUT to update the stale policy")
	}
	if !bytesContains(putBody, "browzer-users") {
		t.Fatalf("PUT body must carry the corrected identity role, got %s", putBody)
	}
}

func TestEnsureServicePolicyNoopWhenConverged(t *testing.T) {
	// When the existing policy already matches the desired roles, neither a PUT
	// nor a create POST is issued.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/edge/management/v1/service-policies":
			_, _ = w.Write([]byte(`{"data":[{"id":"pol-1","name":"openidx-dial-openidx-Test","type":"Dial","serviceRoles":["#openidx-Test"],"identityRoles":["#browzer-users"]}]}`))
		case r.Method == "PUT", r.Method == "POST" && r.URL.Path == "/edge/management/v1/service-policies":
			t.Errorf("unexpected %s — a converged policy should be a no-op", r.Method)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{}}`))
		}
	}))
	defer srv.Close()
	zm := &ZitiManager{logger: zap.NewNop(), mgmtToken: "fake", mgmtClient: srv.Client(),
		cfg: &config.Config{ZitiCtrlURL: srv.URL}, initialized: true}
	if _, err := zm.EnsureServicePolicy(context.Background(), "openidx-dial-openidx-Test", "Dial",
		[]string{"#openidx-Test"}, []string{"#browzer-users"}); err != nil {
		t.Fatalf("EnsureServicePolicy: %v", err)
	}
}
