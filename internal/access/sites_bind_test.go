package access

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

func TestSiteBindRoleDefaultKeepsZitiRouters(t *testing.T) {
	for _, s := range []string{"", "default"} {
		if got := siteBindRole(s); got != "#ziti-routers" {
			t.Errorf("siteBindRole(%q) = %q, want #ziti-routers", s, got)
		}
	}
	if got := siteBindRole("azure"); got != "#site-azure" {
		t.Errorf("siteBindRole(azure) = %q", got)
	}
}

// routerTagServer fakes the edge-router list/patch and records each PATCH.
func routerTagServer(t *testing.T, routers string) (*ZitiManager, map[string][]string, *sync.Mutex) {
	t.Helper()
	patched := map[string][]string{}
	mu := &sync.Mutex{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/edge/management/v1/edge-routers" && r.Method == "GET":
			_, _ = w.Write([]byte(routers))
		case r.Method == "PATCH" && strings.HasPrefix(r.URL.Path, "/edge/management/v1/edge-routers/"):
			b, _ := io.ReadAll(r.Body)
			var body struct {
				RoleAttributes []string `json:"roleAttributes"`
			}
			_ = json.Unmarshal(b, &body)
			mu.Lock()
			patched[strings.TrimPrefix(r.URL.Path, "/edge/management/v1/edge-routers/")] = body.RoleAttributes
			mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return newTestZitiManager(t, srv.URL), patched, mu
}

func TestEnsureRouterSiteAttributesTagsEachRouterWithItsSite(t *testing.T) {
	zm, patched, _ := routerTagServer(t, `{"data":[
		{"id":"r1","roleAttributes":[]},
		{"id":"r2","roleAttributes":["ziti-routers","site-default","x"]},
		{"id":"r3","roleAttributes":["ziti-routers","site-old"]}]}`)
	counts, err := zm.EnsureRouterSiteAttributes(context.Background(), map[string]string{"r3": "azure"})
	if err != nil {
		t.Fatal(err)
	}
	if counts["default"] != 2 || counts["azure"] != 1 {
		t.Fatalf("counts = %+v", counts)
	}
	if got := strings.Join(patched["r1"], ","); got != "ziti-routers,site-default" {
		t.Errorf("unmapped router r1 tagged %q, want ziti-routers,site-default", got)
	}
	if _, ok := patched["r2"]; ok {
		t.Error("an already-converged router was patched")
	}
	if got := strings.Join(patched["r3"], ","); got != "ziti-routers,site-azure" {
		t.Errorf("moved router r3 tagged %q, want the old site removed", got)
	}
}

// directRouteHarness converges one direct route and returns the Bind roles.
func directRouteHarness(t *testing.T, siteMap map[string]string, d DesiredRoute) (*[]string, error) {
	t.Helper()
	var bind []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/edge/management/v1/config-types":
			_, _ = w.Write([]byte(`{"data":[{"id":"host-type","name":"host.v1"}]}`))
		case r.URL.Path == "/edge/management/v1/configs" && r.Method == "POST":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"cfg-1"}}`))
		case r.URL.Path == "/edge/management/v1/services" && r.Method == "POST":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"svc-1"}}`))
		case r.URL.Path == "/edge/management/v1/service-policies" && r.Method == "POST":
			b, _ := io.ReadAll(r.Body)
			if bytesContains(b, "Bind") {
				bind = extractIdentityRoles(b)
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
		hostedServices: make(map[string]*hostedService), siteRoutersOverride: siteMap,
		configTypeCache: map[string]string{"host.v1": "host-type", "intercept.v1": "intercept-type"}}
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}}
	err := rec.ensurePolicies(context.Background(), zm, d)
	return &bind, err
}

func TestDirectRouteInASiteIsBoundToThatSitesRouters(t *testing.T) {
	d := DesiredRoute{ServiceName: "az-app", ToURL: "http://192.0.2.4:80", BrowZerEnabled: true, HostingMode: HostingModeDirect, SiteSlug: "azure"}
	bind, err := directRouteHarness(t, map[string]string{"r1": "azure"}, d)
	if strings.Join(*bind, ",") != "#site-azure" {
		t.Fatalf("Bind = %+v, want [#site-azure]; err %v", *bind, err)
	}
}

func TestDirectRouteInTheDefaultSiteKeepsZitiRouters(t *testing.T) {
	d := DesiredRoute{ServiceName: "def-app", ToURL: "http://192.0.2.4:80", BrowZerEnabled: true, HostingMode: HostingModeDirect, SiteSlug: "default"}
	bind, _ := directRouteHarness(t, map[string]string{}, d)
	if strings.Join(*bind, ",") != "#ziti-routers" {
		t.Fatalf("Bind = %+v, want [#ziti-routers]", *bind)
	}
}

func TestDirectRouteInASiteWithoutRoutersFailsClosed(t *testing.T) {
	d := DesiredRoute{ServiceName: "az-app", ToURL: "http://192.0.2.4:80", BrowZerEnabled: true, HostingMode: HostingModeDirect, SiteSlug: "azure"}
	bind, err := directRouteHarness(t, map[string]string{}, d)
	if len(*bind) != 0 {
		t.Errorf("a Bind policy was written for a site with no router: %+v", *bind)
	}
	if err == nil || !strings.Contains(err.Error(), "no router in site") {
		t.Errorf("err = %v, want 'no router in site' (reconcileRoute records it as the converge status)", err)
	}
}
