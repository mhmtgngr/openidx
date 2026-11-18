package access

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// A hosting router sees a service the moment its Bind policy grants it access,
// opens a Bind session and asks the controller for a terminator. The session
// only lists the edge routers an existing service-edge-router policy allows, so
// a policy created after Bind makes the controller answer "invalid edge router
// for session", and the router retries after about two minutes: a new service
// was undialable for 2m12s on the box (7-9 ms with the policy first). These
// tests pin the order at the three provisioning paths a person can trigger.

// firstIndex is the position of the first write whose line has the prefix, or -1.
func firstIndex(lines []string, prefix string) int {
	for i, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return i
		}
	}
	return -1
}

func TestNetworkServiceCreatesItsEdgeRouterPolicyBeforeBind(t *testing.T) {
	f, zm, rec, d := failClosedFixture(t)
	resetRouterHosts(t, false)
	rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) { return []DesiredNetworkService{d}, nil }
	rec.reconcileNetworkServices(context.Background(), zm)
	if !f.has("service", d.ServiceName) {
		t.Fatalf("setup: the service did not converge: %q", rec.StatusSnapshot()[d.ServiceName])
	}

	f.mu.Lock()
	writes := append([]string(nil), f.writes...)
	f.mu.Unlock()
	serp := firstIndex(writes, "POST /edge/management/v1/service-edge-router-policies")
	policy := firstIndex(writes, "POST /edge/management/v1/service-policies")
	if serp < 0 || policy < 0 {
		t.Fatalf("expected both writes, got %v", writes)
	}
	if serp > policy {
		t.Errorf("the service-edge-router policy was written at position %d, after the first service policy at %d: %v", serp, policy, writes)
	}
}

// routeOrderHarness runs ensurePolicies for a router-hosted route against a
// minimal controller and returns the policy POSTs in the order they arrived,
// each as "serp", "bind" or "dial".
func routeOrderHarness(t *testing.T, d DesiredRoute) []string {
	t.Helper()
	var mu sync.Mutex
	var order []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/service-edge-router-policies"):
			order = append(order, "serp")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"serp-1"}}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/service-policies"):
			b, _ := io.ReadAll(r.Body)
			if strings.Contains(string(b), `"Bind"`) {
				order = append(order, "bind")
			} else {
				order = append(order, "dial")
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"pol-1"}}`))
		case r.URL.Path == "/edge/management/v1/edge-routers" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"data":[{"id":"r1","roleAttributes":["ziti-routers","site-default"]}]}`))
		case r.Method == "GET":
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{}}`))
		}
	}))
	t.Cleanup(srv.Close)
	zm := &ZitiManager{logger: zap.NewNop(), mgmtToken: "fake", mgmtClient: srv.Client(),
		cfg: &config.Config{ZitiCtrlURL: srv.URL}, initialized: true,
		hostedServices:  make(map[string]*hostedService),
		configTypeCache: map[string]string{"host.v1": "host-type", "intercept.v1": "intercept-type"}}
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}}
	if err := rec.ensurePolicies(context.Background(), zm, d); err != nil {
		t.Fatalf("ensurePolicies: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), order...)
}

func TestRouteServiceCreatesItsEdgeRouterPolicyBeforeBind(t *testing.T) {
	d := DesiredRoute{ServiceName: "ord-app", ToURL: "http://192.0.2.4:80", BrowZerEnabled: true, HostingMode: HostingModeDirect, SiteSlug: "default"}
	got := strings.Join(routeOrderHarness(t, d), ",")
	if !strings.HasPrefix(got, "serp,bind") {
		t.Fatalf("policies created in the order %q, want the edge-router policy first, then Bind", got)
	}
	if !strings.Contains(got, "dial") {
		t.Errorf("no Dial policy was created: %q", got)
	}
}
