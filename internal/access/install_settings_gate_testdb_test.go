package access

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// THE ACCESS SERVICE'S INSTALL-WIDE SETTINGS, THROUGH ITS REAL ROUTE TABLE.
//
// One OpenZiti controller, one BrowZer bootstrapper and one platform TLS
// certificate serve every organization on the install. Each route that changes
// them -- or reads the controller's admin account, or dials a controller with
// the stored password -- is driven through RegisterRoutes by six callers, and
// what the route touches (a system_settings row, a certificate file on disk,
// apisix.yaml, the controller the caller named) is read back around every call:
//
//   - another organization's admin and super_admin are refused with 403 and
//     "platform administrator required", even when their request resolved to
//     the default organization, and nothing changes;
//   - a plain user is refused by the admin gate in front;
//   - the default organization's admin and super_admin get through.
//
// The refused callers go first, so each meets the state the previous route
// left: a refused revert is only evidence if there is a certificate to revert.
func TestInstallWideAccessSettingsNeedAPlatformAdministrator(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := orgctx.WithBypassRLS(context.Background())
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	defaultOrg := middleware.DefaultOrgID

	var otherOrg string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`,
		"tenant-"+suffix).Scan(&otherOrg); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	seedUser := func(org, name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	platformAdmin := seedUser(defaultOrg, "platform-admin")
	platformSuper := seedUser(defaultOrg, "platform-super")
	tenantAdmin := seedUser(otherOrg, "tenant-admin")
	tenantSuper := seedUser(otherOrg, "tenant-super")
	plainUser := seedUser(defaultOrg, "plain-user")

	// A controller that counts who dials it. The settings test logs in to the
	// controller the request names, with the STORED password when the request
	// sends the mask, so a refused caller's controller must never hear a word.
	var controllerHits atomic.Int32
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		controllerHits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(controller.Close)

	// DEFAULT_ORG_ID names the tenant, as an operator might point the resolver's
	// fallback at a customer's organization. It must not make that
	// organization's administrators the install's: every caller below is judged
	// against the default organization all the same.
	cfg := &config.Config{
		Environment:   "production",
		EncryptionKey: "0123456789abcdef0123456789abcdef",
		DefaultOrgID:  otherOrg,
	}
	logger := zap.NewNop()
	svc := NewService(db, &database.RedisClient{}, cfg, logger)
	if err := saveZitiConnSettings(ctx, db, cfg.EncryptionKey, ZitiConnSettingsView{
		ControllerURL: "https://ziti-controller.install.example.test:1280",
		AdminUser:     "install-ziti-admin",
		AdminPassword: "install-ziti-password",
	}, ""); err != nil {
		t.Fatalf("seed the controller connection: %v", err)
	}

	stateDir := t.TempDir()
	btm := NewBrowZerTargetManager(db, logger, filepath.Join(stateDir, "browzer-targets.json"))
	btm.SetCertsPath(stateDir)
	svc.SetBrowZerTargetManager(btm)
	apisixYAML := filepath.Join(stateDir, "apisix.yaml")
	if err := os.WriteFile(apisixYAML, []byte("routes: []\n#END\n"), 0o600); err != nil {
		t.Fatalf("seed apisix.yaml: %v", err)
	}
	svc.SetAPISIXConfigPath(apisixYAML)

	type caller struct {
		name        string
		user        string
		roles       []string
		resolvedOrg string
		allowed     bool
	}
	var current caller
	r := gin.New()
	RegisterRoutes(r, svc, func(c *gin.Context) {
		c.Set("user_id", current.user)
		c.Set("roles", current.roles)
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: current.resolvedOrg}))
		c.Next()
	})
	callers := []caller{
		{"another organization's admin", tenantAdmin, []string{"admin"}, otherOrg, false},
		{"another organization's admin, request resolved to the default organization", tenantAdmin, []string{"admin"}, defaultOrg, false},
		{"another organization's super_admin", tenantSuper, []string{"admin", "super_admin"}, otherOrg, false},
		{"plain user", plainUser, []string{"user"}, defaultOrg, false},
		{"default-organization admin", platformAdmin, []string{"admin"}, defaultOrg, true},
		{"default-organization super_admin", platformSuper, []string{"super_admin"}, defaultOrg, true},
	}

	setting := func(key string) string {
		var v string
		if err := db.Pool.QueryRow(ctx, `SELECT COALESCE((SELECT value::text FROM system_settings WHERE key = $1), '')`, key).Scan(&v); err != nil {
			t.Fatalf("read system_settings %s: %v", key, err)
		}
		return v
	}
	file := func(name string) func() string {
		return func() string {
			b, _ := os.ReadFile(filepath.Join(stateDir, name))
			return string(b)
		}
	}
	certAndSetting := func() string { return file("browzer-tls.crt")() + setting("browzer_domain_config") }
	apisixState := func() string { return file("apisix.yaml")() + setting("apisix_ssl_config") }
	upload := func(int) (string, string) {
		certPEM, keyPEM, err := generateSelfSignedCert("upload.example.test")
		if err != nil {
			t.Fatalf("generate a certificate to upload: %v", err)
		}
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for field, content := range map[string][]byte{"cert": certPEM, "key": keyPEM} {
			part, _ := mw.CreateFormFile(field, field+".pem")
			_, _ = part.Write(content)
		}
		_ = mw.Close()
		return buf.String(), mw.FormDataContentType()
	}
	jsonBody := func(f func(i int) string) func(int) (string, string) {
		return func(i int) (string, string) { return f(i), "application/json" }
	}

	n := 0
	for _, ep := range []struct {
		method, path string
		body         func(i int) (string, string)
		state        func() string
		// admitted, when set, replaces the default "the state changed" check
		// for an admitted caller: some routes converge to a state the second
		// admitted caller finds already there.
		admitted    func(t *testing.T, code int, before, after string)
		refusedMust func(t *testing.T, body string)
	}{
		{method: http.MethodGet, path: "/api/v1/access/ziti/settings",
			refusedMust: func(t *testing.T, body string) {
				if strings.Contains(body, "install-ziti-admin") || strings.Contains(body, "ziti-controller.install") {
					t.Errorf("a refused read still carried the controller connection: %s", body)
				}
			}},
		{method: http.MethodPut, path: "/api/v1/access/ziti/settings",
			body: jsonBody(func(i int) string {
				return fmt.Sprintf(`{"controller_url":"https://ctrl-%d.example.test:1280","admin_user":"admin-%d","admin_password":"********"}`, i, i)
			}),
			state: func() string { return setting("ziti_connection") }},
		{method: http.MethodPost, path: "/api/v1/access/ziti/settings/test",
			body: jsonBody(func(int) string {
				return fmt.Sprintf(`{"controller_url":%q,"admin_user":"install-ziti-admin","admin_password":"********","insecure_skip_verify":true}`, controller.URL)
			}),
			state: func() string { return fmt.Sprint(controllerHits.Load()) }},
		{method: http.MethodPost, path: "/api/v1/access/ziti/connect"},
		{method: http.MethodPost, path: "/api/v1/access/ziti/disconnect",
			state: func() string { return setting("ziti_connection") },
			admitted: func(t *testing.T, code int, _, _ string) {
				if code != http.StatusOK {
					t.Errorf("admitted disconnect: status %d, want 200", code)
				}
			}},
		{method: http.MethodPost, path: "/api/v1/access/ziti/browzer/enable"},
		{method: http.MethodPost, path: "/api/v1/access/ziti/browzer/disable"},
		{method: http.MethodPost, path: "/api/v1/access/ziti/browzer/certificates", body: upload, state: certAndSetting},
		{method: http.MethodDelete, path: "/api/v1/access/ziti/browzer/certificates", state: certAndSetting},
		{method: http.MethodPut, path: "/api/v1/access/ziti/browzer/domain",
			body:  jsonBody(func(i int) string { return fmt.Sprintf(`{"domain":"browzer-%d.example.test"}`, i) }),
			state: func() string { return setting("browzer_domain_config") }},
		{method: http.MethodPost, path: "/api/v1/access/ziti/browzer/restart",
			state: file("browzer-targets.json"),
			admitted: func(t *testing.T, code int, _, after string) {
				if code != http.StatusOK || after == "" {
					t.Errorf("admitted restart: status %d, targets file %q; want 200 and a written file", code, after)
				}
			}},
		{method: http.MethodPost, path: "/api/v1/access/certificates/platform", body: upload, state: file("browzer-tls.key")},
		{method: http.MethodDelete, path: "/api/v1/access/certificates/platform", state: file("browzer-tls.key")},
		{method: http.MethodPost, path: "/api/v1/access/certificates/apisix/enable", state: apisixState,
			admitted: func(t *testing.T, code int, _, after string) {
				if code != http.StatusOK || !strings.Contains(after, "ssls:") {
					t.Errorf("admitted APISIX SSL enable: status %d, want 200 and an ssls block in apisix.yaml", code)
				}
			}},
		{method: http.MethodPost, path: "/api/v1/access/certificates/apisix/disable", state: apisixState,
			admitted: func(t *testing.T, code int, _, after string) {
				if code != http.StatusOK || strings.Contains(after, "ssls:") {
					t.Errorf("admitted APISIX SSL disable: status %d, want 200 and no ssls block", code)
				}
			}},
	} {
		ep := ep
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			for _, cl := range callers {
				n++
				current = cl
				body, contentType := "", "application/json"
				if ep.body != nil {
					body, contentType = ep.body(n)
				}
				var before string
				if ep.state != nil {
					before = ep.state()
				}
				req := httptest.NewRequest(ep.method, ep.path, strings.NewReader(body))
				req.Header.Set("Content-Type", contentType)
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				var after string
				if ep.state != nil {
					after = ep.state()
				}
				var resp map[string]interface{}
				_ = json.Unmarshal(w.Body.Bytes(), &resp)

				if cl.allowed {
					if w.Code == http.StatusForbidden {
						t.Errorf("%s was refused (%s); a platform administrator must be admitted", cl.name, w.Body.String())
						continue
					}
					switch {
					case ep.admitted != nil:
						ep.admitted(t, w.Code, before, after)
					case ep.state != nil && before == after:
						t.Errorf("%s was admitted (%d %s) but nothing changed", cl.name, w.Code, w.Body.String())
					}
					continue
				}
				if w.Code != http.StatusForbidden {
					t.Errorf("%s: status %d (%s), want 403", cl.name, w.Code, w.Body.String())
				}
				if cl.roles[0] != "user" && resp["error"] != middleware.PlatformAdminRequired {
					t.Errorf("%s: error %v, want %q", cl.name, resp["error"], middleware.PlatformAdminRequired)
				}
				if before != after {
					t.Errorf("%s was refused but the state changed:\n  before %.200s\n  after  %.200s", cl.name, before, after)
				}
				if ep.refusedMust != nil {
					ep.refusedMust(t, w.Body.String())
				}
			}
		})
	}
}
