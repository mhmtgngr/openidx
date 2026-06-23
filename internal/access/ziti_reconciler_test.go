package access

import (
	"context"
	"encoding/json"
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

func TestEnsureHostingDirectNotImplemented(t *testing.T) {
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}}
	if err := rec.ensureHosting(context.Background(), &ZitiManager{logger: zap.NewNop()},
		DesiredRoute{ServiceName: "x", BrowZerEnabled: true}); err == nil {
		t.Fatalf("expected direct mode to be not-implemented in Phase 1")
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
