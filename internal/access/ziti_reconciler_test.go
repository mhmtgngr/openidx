package access

import (
	"context"
	"encoding/json"
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

func bytesContains(b []byte, s string) bool { return strings.Contains(string(b), s) }

func extractIdentityRoles(b []byte) []string {
	var p struct {
		IdentityRoles []string `json:"identityRoles"`
	}
	_ = json.Unmarshal(b, &p)
	return p.IdentityRoles
}
