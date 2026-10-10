package access

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/appaccess"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// The network-resource API on the migrated schema: create, list, the target's
// validation and its refusal on a resource of another kind, the delete, the
// organization's tunnel policy and its defaults, the CSV import with a group
// assignment, what the reconciler then loads, and the agent's tunnel status.
func TestNetworkResourceAPIOnTheMigratedSchema(t *testing.T) {
	pinTargetGuard(t)
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(bg, orgctx.Org{ID: org})

	gin.SetMode(gin.TestMode)
	svc := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Next()
	})
	api := r.Group("/api/v1/access")
	api.GET("/network-resources", svc.handleListNetworkResources)
	api.POST("/network-resources", svc.handleCreateNetworkResource)
	api.POST("/network-resources/import", svc.handleImportNetworkResources)
	api.GET("/resources/:id/network-target", svc.handleGetNetworkTarget)
	api.PUT("/resources/:id/network-target", svc.handlePutNetworkTarget)
	api.DELETE("/resources/:id/network-target", svc.handleDeleteNetworkTarget)
	api.GET("/network-policy", svc.handleGetNetworkPolicy)
	api.PUT("/network-policy", svc.handlePutNetworkPolicy)

	do := func(method, path, body string) (int, map[string]interface{}) {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var out map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	if code, _ := do("POST", "/api/v1/access/network-resources", `{"name":"x","target":{"cidrs":["10.0.0.0/40"]}}`); code != http.StatusBadRequest {
		t.Errorf("a bad CIDR on create answered %d, want 400", code)
	}
	code, created := do("POST", "/api/v1/access/network-resources",
		`{"name":"File servers","target":{"hosts":["fs1.corp.example"],"cidrs":["10.20.0.0/16"],"port_ranges":[{"low":445,"high":445}],"protocols":["tcp"]}}`)
	if code != http.StatusCreated {
		t.Fatalf("create answered %d: %v", code, created)
	}
	id, _ := created["id"].(string)

	code, list := do("GET", "/api/v1/access/network-resources", "")
	if code != http.StatusOK || list["total"].(float64) != 1 {
		t.Fatalf("list answered %d: %v", code, list)
	}

	if code, _ := do("PUT", "/api/v1/access/resources/"+id+"/network-target", `{"hosts":["a.example"],"port_ranges":[{"low":0,"high":70000}]}`); code != http.StatusBadRequest {
		t.Errorf("an out-of-range port answered %d, want 400", code)
	}
	if code, _ := do("PUT", "/api/v1/access/resources/"+id+"/network-target", `{}`); code != http.StatusBadRequest {
		t.Errorf("a target with no address answered %d, want 400", code)
	}

	var web string
	if err := db.Pool.QueryRow(ctx, `INSERT INTO applications (client_id, name, type, kind, org_id)
		VALUES ('web-nt', 'Wiki', 'web', 'web', $1) RETURNING id::text`, org).Scan(&web); err != nil {
		t.Fatalf("seed web app: %v", err)
	}
	if code, _ := do("PUT", "/api/v1/access/resources/"+web+"/network-target", `{"hosts":["a.example"]}`); code != http.StatusConflict {
		t.Errorf("a network target on a web resource answered %d, want 409", code)
	}
	if code, _ := do("PUT", "/api/v1/access/resources/00000000-0000-0000-0000-00000000dead/network-target", `{"hosts":["a.example"]}`); code != http.StatusNotFound {
		t.Errorf("an unknown resource answered %d, want 404", code)
	}

	code, got := do("PUT", "/api/v1/access/resources/"+id+"/network-target", `{"dns_names":["*.corp.example"],"cidrs":["10.20.9.9/16"]}`)
	if code != http.StatusOK {
		t.Fatalf("put target answered %d: %v", code, got)
	}
	code, got = do("GET", "/api/v1/access/resources/"+id+"/network-target", "")
	tgt, _ := got["target"].(map[string]interface{})
	if code != http.StatusOK || tgt["cidrs"].([]interface{})[0] != "10.20.0.0/16" {
		t.Errorf("get target answered %d: %v", code, got)
	}

	// The reconciler loads it.
	rec := &ZitiReconciler{db: db, logger: zap.NewNop(), status: map[string]string{}}
	desired, err := rec.loadDesiredNetworkServices(bg)
	if err != nil || len(desired) != 1 || desired[0].ApplicationID != id || desired[0].OrgID != org {
		t.Fatalf("loadDesiredNetworkServices = %+v, %v", desired, err)
	}
	if !strings.Contains(strings.Join(desired[0].Target.DNSNames, ","), "*.corp.example") {
		t.Errorf("the loaded target lost its DNS name: %+v", desired[0].Target)
	}

	if code, _ := do("DELETE", "/api/v1/access/resources/"+id+"/network-target", ""); code != http.StatusNoContent {
		t.Errorf("delete answered %d", code)
	}
	if code, _ := do("GET", "/api/v1/access/resources/"+id+"/network-target", ""); code != http.StatusNotFound {
		t.Errorf("get after delete answered %d", code)
	}
	if desired, _ := rec.loadDesiredNetworkServices(bg); len(desired) != 0 {
		t.Errorf("a resource without a target is still desired: %+v", desired)
	}

	// The tunnel policy: defaults, then a partial update.
	code, pol := do("GET", "/api/v1/access/network-policy", "")
	if code != http.StatusOK || pol["always_on"] != false || pol["split_tunnel"] != true {
		t.Errorf("default policy answered %d: %v", code, pol)
	}
	if code, pol = do("PUT", "/api/v1/access/network-policy", `{"always_on":true}`); code != http.StatusOK || pol["always_on"] != true || pol["split_tunnel"] != true {
		t.Errorf("put policy answered %d: %v", code, pol)
	}
	if code, pol = do("PUT", "/api/v1/access/network-policy", `{"split_tunnel":false}`); code != http.StatusOK || pol["always_on"] != true || pol["split_tunnel"] != false {
		t.Errorf("a second partial update answered %d: %v", code, pol)
	}

	// The CSV import.
	if _, err := db.Pool.Exec(ctx, `INSERT INTO groups (org_id, name) VALUES ($1, 'NetOps-p2a')`, org); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	csvBody := "name,cidrs,ports,group\nFinance share,10.30.0.0/24,445,NetOps-p2a\nLab,10.40.0.0/16,22,Nobody\nBad,10.0.0.0/99,,\n"
	req := httptest.NewRequest("POST", "/api/v1/access/network-resources/import?dry_run=true", strings.NewReader(csvBody))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var imp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &imp)
	if w.Code != http.StatusOK || imp["created"].(float64) != 0 || imp["failed"].(float64) != 1 {
		t.Errorf("dry run answered %d: %v", w.Code, imp)
	}
	req = httptest.NewRequest("POST", "/api/v1/access/network-resources/import", strings.NewReader(csvBody))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	_ = json.Unmarshal(w.Body.Bytes(), &imp)
	if w.Code != http.StatusOK || imp["created"].(float64) != 2 || imp["failed"].(float64) != 1 {
		t.Fatalf("import answered %d: %v", w.Code, imp)
	}
	var assigned int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM group_application_assignments gaa
		JOIN applications a ON a.id = gaa.application_id WHERE a.name = 'Finance share' AND gaa.org_id = $1`, org).Scan(&assigned); err != nil || assigned != 1 {
		t.Errorf("the imported resource has %d group assignments (%v), want 1", assigned, err)
	}
	rows := imp["rows"].([]interface{})
	if warn, _ := rows[1].(map[string]interface{})["warning"].(string); !strings.Contains(warn, "Nobody") {
		t.Errorf("an unknown group carried no warning: %v", rows[1])
	}

	// Another organization's resource, target and group are out of reach. The
	// test role is a superuser, so RLS does not apply here: what holds is the
	// org_id each query takes from the caller's context.
	var orgB, appB, groupB string
	if err := db.Pool.QueryRow(bg, `INSERT INTO organizations (name, slug) VALUES ('net-b', 'net-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	if err := db.Pool.QueryRow(bg, `INSERT INTO applications (client_id, name, type, kind, org_id)
		VALUES ('network-b', 'B secrets', 'network', 'network', $1) RETURNING id::text`, orgB).Scan(&appB); err != nil {
		t.Fatalf("seed org B app: %v", err)
	}
	if _, err := db.Pool.Exec(bg, `INSERT INTO network_targets (application_id, org_id, cidrs) VALUES ($1, $2, '{10.99.0.0/24}')`, appB, orgB); err != nil {
		t.Fatalf("seed org B target: %v", err)
	}
	if err := db.Pool.QueryRow(bg, `INSERT INTO groups (org_id, name) VALUES ($1, 'only-in-b') RETURNING id::text`, orgB).Scan(&groupB); err != nil {
		t.Fatalf("seed org B group: %v", err)
	}
	if code, _ := do("GET", "/api/v1/access/resources/"+appB+"/network-target", ""); code != http.StatusNotFound {
		t.Errorf("org A read org B's target: %d", code)
	}
	if code, _ := do("PUT", "/api/v1/access/resources/"+appB+"/network-target", `{"cidrs":["10.98.0.0/24"]}`); code != http.StatusNotFound {
		t.Errorf("org A wrote org B's target: %d", code)
	}
	if code, _ := do("DELETE", "/api/v1/access/resources/"+appB+"/network-target", ""); code != http.StatusNotFound {
		t.Errorf("org A deleted org B's target: %d", code)
	}
	var stillB string
	if err := db.Pool.QueryRow(bg, `SELECT array_to_string(cidrs::text[], ',') FROM network_targets WHERE application_id = $1`, appB).Scan(&stillB); err != nil || stillB != "10.99.0.0/24" {
		t.Errorf("org B's target after org A's attempts: %q, %v", stillB, err)
	}
	_, listA := do("GET", "/api/v1/access/network-resources", "")
	for _, r := range listA["resources"].([]interface{}) {
		if r.(map[string]interface{})["id"] == appB {
			t.Error("org A's list shows org B's resource")
		}
	}
	reqB := httptest.NewRequest("POST", "/api/v1/access/network-resources/import", strings.NewReader("name,cidrs,group\nSneaky,10.97.0.0/24,only-in-b\n"))
	wB := httptest.NewRecorder()
	r.ServeHTTP(wB, reqB)
	var bAssigned int
	if err := db.Pool.QueryRow(bg, `SELECT count(*) FROM group_application_assignments WHERE group_id = $1`, groupB).Scan(&bAssigned); err != nil || bAssigned != 0 {
		t.Errorf("an import in org A assigned org B's group (%d, %v)", bAssigned, err)
	}
	if !strings.Contains(wB.Body.String(), "was not found") {
		t.Errorf("the import did not report org B's group as not found: %s", wB.Body.String())
	}

	// A target pointing at the platform is refused through the API.
	if code, _ := do("PUT", "/api/v1/access/resources/"+id+"/network-target", `{"hosts":["169.254.169.254"]}`); code != http.StatusBadRequest {
		t.Errorf("a metadata-address target answered %d, want 400", code)
	}
	if code, _ := do("PUT", "/api/v1/access/resources/"+id+"/network-target", `{"cidrs":["10.0.0.0/8"]}`); code != http.StatusBadRequest {
		t.Errorf("a /8 target answered %d, want 400", code)
	}
	// One written past the API is not converged either.
	if _, err := db.Pool.Exec(bg, `INSERT INTO network_targets (application_id, org_id, hosts) VALUES ($1, $2, '{127.0.0.1}')`, id, org); err != nil {
		t.Fatalf("seed a loopback target: %v", err)
	}
	loaded, err := rec.loadDesiredNetworkServices(bg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, d := range loaded {
		if d.ApplicationID == id {
			t.Error("the reconciler loads a target that points at loopback")
		}
	}
	if st := rec.StatusSnapshot()[networkServiceName(id)]; !strings.HasPrefix(st, "error:") {
		t.Errorf("the refused target's converge state is %q, want an error", st)
	}
	if _, err := db.Pool.Exec(bg, `DELETE FROM network_targets WHERE application_id = $1`, id); err != nil {
		t.Fatalf("clean up: %v", err)
	}

	// An assigned network resource travels as an app marker; a web app with
	// no route does not.
	zm := &ZitiManager{db: db, logger: zap.NewNop()}
	marked := zm.networkAppIDs(ctx, org, []appaccess.AppRef{{ID: id}, {ID: web}})
	if !marked[id] || marked[web] {
		t.Errorf("networkAppIDs = %v; want only the network resource", marked)
	}

	// The agent's tunnel status.
	if _, err := db.Pool.Exec(ctx, `INSERT INTO enrolled_agents (agent_id, device_id, auth_token_hash, status, org_id)
		VALUES ('agent-tun', 'agent-tun', 'x', 'active', $1)`, org); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	h := NewAgentAPIHandler(zap.NewNop(), db, nil, &config.Config{})
	h.recordTunnelStatus(ctx, "agent-tun", &agentTunnelStatus{State: "up", Version: "1.5.0",
		Services: []agentTunnelService{{Name: networkServiceName(id), DialFailures: 2}}})
	var state string
	var seen bool
	if err := db.Pool.QueryRow(ctx, `SELECT tunnel_status->>'state', tunnel_last_seen IS NOT NULL
		FROM enrolled_agents WHERE agent_id = 'agent-tun' AND org_id = $1`, org).Scan(&state, &seen); err != nil {
		t.Fatalf("read tunnel status: %v", err)
	}
	if state != "up" || !seen {
		t.Errorf("tunnel status stored as %q, last seen set %v", state, seen)
	}
}
