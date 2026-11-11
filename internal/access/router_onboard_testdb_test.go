package access

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

func TestSplitCtrlAddress(t *testing.T) {
	for in, want := range map[string][2]string{
		"ctrl.tdv.org:1280":         {"ctrl.tdv.org", "1280"},
		"ctrl.tdv.org":              {"ctrl.tdv.org", "1280"},
		"https://ctrl.tdv.org:443/": {"ctrl.tdv.org", "443"},
		"":                          {"", "1280"},
	} {
		h, p := splitCtrlAddress(in)
		if h != want[0] || p != want[1] {
			t.Errorf("splitCtrlAddress(%q) = %q,%q want %v", in, h, p, want)
		}
	}
}

func TestRouterOnboardCommandCarriesTheImageEnv(t *testing.T) {
	cmd := routerOnboardCommand("az-r1", "JWT", "ctrl.tdv.org", "1280", "192.0.2.4", "1.6.12")
	for _, want := range []string{
		"-e ZITI_ENROLL_TOKEN='JWT'",
		"-e ZITI_CTRL_ADVERTISED_ADDRESS=ctrl.tdv.org",
		"-e ZITI_CTRL_ADVERTISED_PORT=1280",
		"-e ZITI_ROUTER_ADVERTISED_ADDRESS=192.0.2.4",
		"-e ZITI_ROUTER_PORT=3022",
		"-e ZITI_ROUTER_MODE=host",
		"openziti/ziti-router:1.6.12",
		"-v az-r1-data:/ziti-router",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("command lacks %q: %s", want, cmd)
		}
	}
}

// Router onboarding and the sites API on the migrated schema: a site is
// created, a router enrolled into it is tagged site-<slug> on the controller
// and recorded in site_routers, the reconciler's map then places it in that
// site, and bad input never reaches the controller.
func TestRouterOnboardingIntoASite(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	ctx := orgctx.WithBypassRLS(bg)
	_, _ = db.Pool.Exec(ctx, `DELETE FROM site_routers`)
	_, _ = db.Pool.Exec(ctx, `DELETE FROM sites WHERE NOT is_default`)

	var mu sync.Mutex
	var created []map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/edge/management/v1/edge-routers" && r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			var body map[string]interface{}
			_ = json.Unmarshal(b, &body)
			mu.Lock()
			created = append(created, body)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"er-1","enrollmentJwt":"eyJ.jwt"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	zm := newTestZitiManager(t, srv.URL)
	zm.cfg.ZitiCtrlPublicAddress = "ctrl.tdv.org:1280"
	zm.db = db

	gin.SetMode(gin.TestMode)
	svc := &Service{db: db, config: &config.Config{ZitiRouterImageTag: "1.6.12"}, logger: zap.NewNop(), zitiProvider: newZitiProviderWith(zm)}
	r := gin.New()
	api := r.Group("/api/v1/access")
	api.GET("/sites", svc.handleListSites)
	api.POST("/sites", svc.handleCreateSite)
	api.PATCH("/sites/:id", svc.handlePatchSite)
	api.POST("/ziti/fabric/routers/enroll-token", svc.handleRouterEnrollToken)
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

	if code, _ := do("POST", "/api/v1/access/sites", `{"slug":"Azure!"}`); code != http.StatusBadRequest {
		t.Errorf("a bad slug answered %d, want 400", code)
	}
	code, site := do("POST", "/api/v1/access/sites", `{"slug":"azure","name":"Azure West Europe"}`)
	if code != http.StatusCreated {
		t.Fatalf("create site answered %d: %v", code, site)
	}
	if code, _ := do("POST", "/api/v1/access/sites", `{"slug":"azure"}`); code != http.StatusConflict {
		t.Errorf("a duplicate slug answered %d, want 409", code)
	}
	siteID, _ := site["id"].(string)
	if code, _ := do("PATCH", "/api/v1/access/sites/"+siteID, `{"slug":"other"}`); code != http.StatusBadRequest {
		t.Errorf("a slug change answered %d, want 400", code)
	}
	if code, got := do("PATCH", "/api/v1/access/sites/"+siteID, `{"name":"Azure WE","hop_addr":"192.0.2.4"}`); code != http.StatusOK || got["name"] != "Azure WE" || got["hop_addr"] != "192.0.2.4" {
		t.Errorf("patch site answered %d: %v", code, got)
	}
	if code, _ := do("PATCH", "/api/v1/access/sites/00000000-0000-0000-0000-00000000dead", `{"name":"x"}`); code != http.StatusNotFound {
		t.Errorf("patching an unknown site answered %d, want 404", code)
	}

	for _, bad := range []string{
		`{"site_slug":"azure"}`,
		`{"site_slug":"nowhere","advertised_address":"192.0.2.4"}`,
		`{"site_slug":"azure","advertised_address":"192.0.2.4:3022"}`,
		`{"site_slug":"azure","advertised_address":"192.0.2.4","image_tag":"1.6; rm -rf /"}`,
		`{"name":"a b","site_slug":"azure","advertised_address":"192.0.2.4"}`,
	} {
		if code, _ := do("POST", "/api/v1/access/ziti/fabric/routers/enroll-token", bad); code != http.StatusBadRequest {
			t.Errorf("%s answered %d, want 400", bad, code)
		}
	}
	if len(created) != 0 {
		t.Fatalf("bad input reached the controller: %v", created)
	}

	code, got := do("POST", "/api/v1/access/ziti/fabric/routers/enroll-token",
		`{"name":"az-r1","site_slug":"azure","advertised_address":"router.azure.tdv.org"}`)
	if code != http.StatusOK {
		t.Fatalf("enroll answered %d: %v", code, got)
	}
	cmd, _ := got["onboard_command"].(string)
	for _, want := range []string{"ZITI_ENROLL_TOKEN='eyJ.jwt'", "ZITI_CTRL_ADVERTISED_ADDRESS=ctrl.tdv.org", "ZITI_ROUTER_ADVERTISED_ADDRESS=router.azure.tdv.org", "openziti/ziti-router:1.6.12"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("command lacks %q: %s", want, cmd)
		}
	}
	if len(created) != 1 {
		t.Fatalf("controller saw %d creates", len(created))
	}
	attrs, _ := created[0]["roleAttributes"].([]interface{})
	if len(attrs) != 2 || attrs[0] != "site-azure" || attrs[1] != "ziti-routers" {
		t.Errorf("router role attributes = %v", attrs)
	}
	var host, tag string
	if err := db.Pool.QueryRow(ctx, `SELECT advertised_host, image_tag FROM site_routers WHERE ziti_router_id = 'er-1' AND site_id = $1`, siteID).Scan(&host, &tag); err != nil {
		t.Fatalf("site_routers row: %v", err)
	}
	if host != "router.azure.tdv.org" || tag != "1.6.12" {
		t.Errorf("site_routers row = %q %q", host, tag)
	}
	if m := zm.siteRouterMap(bg); m["er-1"] != "azure" {
		t.Errorf("siteRouterMap = %v, want er-1 in azure", m)
	}
	code, list := do("GET", "/api/v1/access/sites", "")
	if code != http.StatusOK {
		t.Fatalf("list sites answered %d", code)
	}
	sites, _ := list["sites"].([]interface{})
	if len(sites) != 2 || sites[0].(map[string]interface{})["slug"] != "default" || sites[1].(map[string]interface{})["routers"].(float64) != 1 {
		t.Errorf("sites = %v", sites)
	}

	// A site_id on a network target: resolve rejects an unknown slug and maps
	// the default to NULL.
	if id, err := svc.resolveSiteID(bg, "default"); err != nil || id != nil {
		t.Errorf("default resolves to %v, %v", id, err)
	}
	if id, err := svc.resolveSiteID(bg, "azure"); err != nil || id != siteID {
		t.Errorf("azure resolves to %v, %v", id, err)
	}
	if _, err := svc.resolveSiteID(bg, "mars"); err == nil {
		t.Error("an unknown site resolved")
	}

	// A network resource placed in the site stores its site_id and reads it back.
	pinTargetGuard(t)
	const org = "00000000-0000-0000-0000-000000000010"
	nr := gin.New()
	nr.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Next()
	})
	nr.POST("/nr", svc.handleCreateNetworkResource)
	post := func(body string) (int, map[string]interface{}) {
		req := httptest.NewRequest("POST", "/nr", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		nr.ServeHTTP(w, req)
		var out map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, _ := post(`{"name":"bad","target":{"hosts":["db.azure.example"],"site":"mars"}}`); code != http.StatusBadRequest {
		t.Errorf("an unknown site on a target answered %d, want 400", code)
	}
	code, res := post(`{"name":"Azure DB","target":{"hosts":["db.azure.example"],"site":"azure"}}`)
	if code != http.StatusCreated {
		t.Fatalf("create network resource answered %d: %v", code, res)
	}
	nid, _ := res["id"].(string)
	tgt, ok, err := svc.loadNetworkTarget(orgctx.With(bg, orgctx.Org{ID: org}), org, nid)
	if err != nil || !ok || tgt.Site != "azure" {
		t.Errorf("loaded target site = %q (%v, %v)", tgt.Site, ok, err)
	}
}
