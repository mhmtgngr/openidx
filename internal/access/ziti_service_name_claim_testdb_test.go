package access

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// A ZITI SERVICE NAME BELONGS TO ONE ORGANIZATION.
//
// The controller has one namespace of service names, and Add Service and the
// reconciler adopt a service that already exists under the name they are
// given, converging its host.v1 target and its policies to the new claim. So
// the second organization's admin, through the real route table, is refused
// with a conflict when they name the first organization's service, a name the
// first organization's route or PAM entry holds before its service exists, one
// of the install's own services, or -- for Add Service -- a service on the
// controller that no organization holds, and the controller hears no write
// about it; Ziti on their route keeps no such name, and a bulk route whose
// name would make one is not created. A name nobody holds goes through. The
// reconciler, given routes of two organizations that already name the same
// service, converges neither onto it and reports the conflict, while it still
// converges a name one organization holds -- at the hop port the hop's own
// config gives it, which still counts the routes left out.
func TestAZitiServiceNameBelongsToOneOrganization(t *testing.T) {
	f := newZitiScopeFixture(t)
	fm := NewFeatureManager(f.db, zap.NewNop())
	fm.SetReconcilerEnabled(true)
	f.svc.SetFeatureManager(fm)
	for _, pattern := range []string{
		"POST /edge/management/v1/", "PUT /edge/management/v1/", "PATCH /edge/management/v1/", "DELETE /edge/management/v1/",
	} {
		f.stub.ok(pattern, `{"data":{"id":"created-`+f.sfx+`"}}`)
	}
	f.stub.ok("GET /edge/management/v1/services/"+f.zsB, `{"data":{"id":"`+f.zsB+`","roleAttributes":["`+f.svcB+`"]}}`)
	writes := func() []string {
		var out []string
		for _, c := range f.managementCalls() {
			if !strings.HasPrefix(c, "GET ") {
				out = append(out, c)
			}
		}
		return out
	}
	routeB := f.scalar(`INSERT INTO proxy_routes (org_id, name, from_url, to_url, require_auth)
		VALUES ($1::uuid, $2, $3, 'http://192.0.2.44:80', true) RETURNING id::text`,
		f.orgB.ID, "route-b-"+f.sfx, "https://route-b-"+f.sfx+".example.test")
	routeServiceName := func() string {
		return f.scalar(`SELECT COALESCE(ziti_service_name, '') FROM proxy_routes WHERE id::text = $1`, routeB)
	}
	// Names the first organization holds before any service carries them: a
	// route of its that is switched off, and a PAM entry.
	routeA, pamA := "openidx-wiki-"+f.sfx, "pam-a-"+f.sfx
	f.exec(`INSERT INTO proxy_routes (org_id, name, from_url, to_url, require_auth, enabled, ziti_enabled, ziti_service_name)
		VALUES ($1::uuid, $2, $3, 'http://192.0.2.46:80', true, false, true, $4)`,
		middleware.DefaultOrgID, "wiki-a-"+f.sfx, "https://wiki-a-"+f.sfx+".example.test", routeA)
	f.exec(`INSERT INTO pam_entries (org_id, name, entry_type, ziti_service_name) VALUES ($1::uuid, $2, 'ssh', $3)`,
		middleware.DefaultOrgID, "pam-a-"+f.sfx, pamA)

	adminB := f.caller("adminB", "admin")
	for _, name := range []string{f.svcA, routeA, pamA, "openidx-console", f.svcInstall} {
		f.resetCalls()
		code, body := f.do(adminB, http.MethodPost, "/api/v1/access/ziti/services", `{"name":"`+name+`","host":"192.0.2.44","port":80}`)
		if code != http.StatusConflict || !strings.Contains(body, "already exists") {
			t.Errorf("Add Service %q as B's admin: %d %s, want 409", name, code, body)
		}
		if w := writes(); len(w) != 0 {
			t.Errorf("Add Service %q as B's admin wrote to the controller: %v", name, w)
		}
	}
	for _, name := range []string{f.svcA, routeA, pamA, "openidx-console"} {
		f.resetCalls()
		code, body := f.do(adminB, http.MethodPost, "/api/v1/access/ziti/routes/"+routeB+"/enable",
			`{"service_name":"`+name+`","host":"192.0.2.44","port":80}`)
		if code != http.StatusConflict {
			t.Errorf("Ziti on B's route as %q: %d %s, want 409", name, code, body)
		}
		if w := writes(); len(w) != 0 {
			t.Errorf("Ziti on B's route as %q wrote to the controller: %v", name, w)
		}
		code, body = f.do(adminB, http.MethodPost, "/api/v1/access/services/"+routeB+"/features/ziti/enable",
			`{"ziti_service_name":"`+name+`"}`)
		if code != http.StatusBadRequest || !strings.Contains(body, "already exists") {
			t.Errorf("the Ziti feature on B's route as %q: %d %s, want 400 already exists", name, code, body)
		}
		if got := routeServiceName(); got != "" {
			t.Errorf("B's route names the service %q after being refused %q", got, name)
		}
	}

	// A name nobody holds goes through: Add Service reaches the controller, and
	// the feature records the name on the route for the reconciler.
	f.resetCalls()
	if code, body := f.do(adminB, http.MethodPost, "/api/v1/access/ziti/services",
		`{"name":"fresh-b-`+f.sfx+`","host":"192.0.2.44","port":80}`); code == http.StatusConflict || code == http.StatusForbidden {
		t.Errorf("Add Service with a free name as B's admin: %d %s", code, body)
	}
	if !f.stub.saw("POST /edge/management/v1/configs") {
		t.Errorf("Add Service with a free name did not reach the controller: %v", f.stub.received())
	}
	if code, body := f.do(adminB, http.MethodPost, "/api/v1/access/services/"+routeB+"/features/ziti/enable",
		`{"ziti_service_name":"route-svc-b-`+f.sfx+`"}`); code != http.StatusOK {
		t.Errorf("the Ziti feature on B's route with a free name: %d %s", code, body)
	}
	if got := routeServiceName(); got != "route-svc-b-"+f.sfx {
		t.Errorf("B's route names %q, want route-svc-b-%s", got, f.sfx)
	}

	// Bulk routes name their services after the route: the one whose name the
	// first organization's route holds and the one the install's console
	// holds are left out, and the other is created.
	code, body := f.do(adminB, http.MethodPost, "/api/v1/access/routes/bulk", `{"routes":[
		{"name":"wiki-`+f.sfx+`","from_url":"https://wiki-b-`+f.sfx+`.example.test","to_url":"http://192.0.2.47:80","ziti":true},
		{"name":"console","from_url":"https://console-b-`+f.sfx+`.example.test","to_url":"http://192.0.2.47:81","ziti":true},
		{"name":"bulk-b-`+f.sfx+`","from_url":"https://bulk-b-`+f.sfx+`.example.test","to_url":"http://192.0.2.47:82","ziti":true}]}`)
	var bulk struct {
		Created   int      `json:"created"`
		Conflicts []string `json:"name_conflicts"`
	}
	_ = json.Unmarshal([]byte(body), &bulk)
	if code != http.StatusOK || bulk.Created != 1 || strings.Join(bulk.Conflicts, ",") != "wiki-"+f.sfx+",console" {
		t.Errorf("bulk routes as B's admin: %d %s, want 1 created and the other two in name_conflicts", code, body)
	}
	if n := f.scalar(`SELECT COUNT(*)::text FROM proxy_routes WHERE org_id = $1::uuid AND ziti_service_name IN ($2, 'openidx-console')`,
		f.orgB.ID, routeA); n != "0" {
		t.Errorf("bulk routes as B's admin left %s routes naming a taken service", n)
	}
	if n := f.scalar(`SELECT COUNT(*)::text FROM proxy_routes WHERE org_id = $1::uuid AND ziti_service_name = $2`,
		f.orgB.ID, "openidx-bulk-b-"+f.sfx); n != "1" {
		t.Errorf("bulk routes as B's admin: %s routes name the free service, want 1", n)
	}

	// Routes that already name the same service in two organizations -- from
	// before this check, or a race -- and one that names an install service.
	// They are router-hosted, so converging one needs no SDK context, which
	// this controller does not provide. Two of each organization's routes are
	// hop-hosted: a contested pair, and B's own, whose name sorts after it.
	f.exec(`UPDATE proxy_routes SET hosting_mode = 'direct' WHERE org_id = $1::uuid`, f.orgB.ID)
	seedRoute := func(org, name, service, mode string) {
		f.exec(`INSERT INTO proxy_routes (org_id, name, from_url, to_url, require_auth, enabled, ziti_enabled, ziti_service_name, hosting_mode)
			VALUES ($1::uuid, $2, $3, 'http://192.0.2.45:80', true, true, true, $4, $5)`,
			org, name+"-"+f.sfx, "https://"+name+"-"+f.sfx+".example.test", service, mode)
	}
	seedRoute(middleware.DefaultOrgID, "claim-a", f.svcA, "direct")
	seedRoute(f.orgB.ID, "claim-b", f.svcA, "direct")
	seedRoute(f.orgB.ID, "own-b", f.svcB, "direct")
	seedRoute(f.orgB.ID, "console-b", "openidx-console", "direct")
	hopShared, hopOwn := "hop-shared-"+f.sfx, "hop-zz-b-"+f.sfx
	seedRoute(middleware.DefaultOrgID, "hop-a", hopShared, "hop")
	seedRoute(f.orgB.ID, "hop-b", hopShared, "hop")
	seedRoute(f.orgB.ID, "hop-own-b", hopOwn, "hop")
	var mu sync.Mutex
	hostConfigs := map[string]string{} // host.v1 config name -> its data
	f.stub.on("POST /edge/management/v1/configs", func(w http.ResponseWriter, r *http.Request) {
		var cfg struct {
			Name string          `json:"name"`
			Data json.RawMessage `json:"data"`
		}
		_ = json.NewDecoder(r.Body).Decode(&cfg)
		mu.Lock()
		hostConfigs[cfg.Name] = string(cfg.Data)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"cfg-` + cfg.Name + `"}}`))
	})

	f.resetCalls()
	rec := NewZitiReconciler(f.db, zap.NewNop(), newZitiProviderWith(f.svc.ziti()), "hop.internal.example:9100")
	rec.reconcileOnce(orgctx.WithBypassRLS(context.Background()))
	for _, c := range f.stub.received() {
		if strings.Contains(c, f.zsA) {
			t.Errorf("the reconciler converged the contested service %s: %s", f.svcA, c)
		}
	}
	if !f.stub.saw("GET /edge/management/v1/services/" + f.zsB) {
		t.Errorf("the reconciler did not converge B's own service: %v", f.stub.received())
	}
	// The hop config gives every hop route a port in the order of all their
	// names, the contested pair's included: B's own comes third.
	mu.Lock()
	if got := hostConfigs[hopOwn+"-host"]; !strings.Contains(got, `"address":"hop.internal.example"`) || !strings.Contains(got, `"port":9102`) {
		t.Errorf("B's own hop route's host.v1 config: %q, want hop.internal.example port 9102", got)
	}
	if got, ok := hostConfigs[hopShared+"-host"]; ok {
		t.Errorf("the reconciler converged the contested hop service: %s", got)
	}
	mu.Unlock()
	status := rec.StatusSnapshot()
	for _, name := range []string{f.svcA, hopShared, "openidx-console"} {
		if !strings.Contains(status[name], "held by more than one organization") {
			t.Errorf("reconcile state of %s: %q, want the conflict reported", name, status[name])
		}
	}
	if strings.Contains(status[f.svcB], "held by more than one organization") {
		t.Errorf("reconcile state of B's own service %s: %q", f.svcB, status[f.svcB])
	}
}
