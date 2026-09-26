package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	adminhandlers "github.com/openidx/openidx/internal/admin/handlers"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/selfheal"
)

// INSTALL-WIDE SETTINGS, THROUGH THE REAL ADMIN-API ROUTE TABLE.
//
// Every route below changes something that exists once for the whole install
// (a system_settings row, the OAuth signing keys, the shared IP deny-list, the
// error catalog, the self-heal loop) or reads the SMS provider's credentials.
// Each is driven through RegisterRoutes -- the route table cmd/admin-api
// serves -- by five callers, and the setting it touches is read back before
// and after:
//
//   - an admin and a super_admin of the default organization change it;
//   - an admin and a super_admin of another organization are refused with 403
//     and "platform administrator required", and the setting is unchanged --
//     including when the request resolved to the default organization, which
//     is the organization a caller can ask for, not the one they belong to;
//   - a plain user is refused by the admin gate in front of it all.
//
// The self-heal routes are mounted by cmd/admin-api rather than RegisterRoutes;
// they are mounted here with the gates main.go passes (its call is pinned by
// cmd/admin-api's TestSelfHealMutationsNeedAPlatformAdministrator), with a
// permission stand-in that always admits, so the platform gate is the only
// thing that can refuse.
func TestInstallWideSettingsNeedAPlatformAdministrator(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupPAMTestDB(t)
	t.Cleanup(cleanup)
	ctx := orgctx.WithBypassRLS(context.Background())
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	defaultOrg := middleware.DefaultOrgID
	const catalogCode = "PLATFORM-GATE-SEEDED"

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

	// The SMS provider every organization's codes go through, as a platform
	// administrator configured it.
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO system_settings (key, value) VALUES ('sms_config', $1::jsonb)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
		`{"enabled":true,"provider":"webhook","message_prefix":"Install","otp_length":6,"otp_expiry":300,"max_attempts":3,`+
			`"credentials":{"webhook_url":"https://sms-gateway.install.example.test/send","webhook_api_key":"install-key"}}`); err != nil {
		t.Fatalf("seed sms_config: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO error_catalog (code, http_status, category, description)
		VALUES ($1, 400, 'auth', 'seeded') ON CONFLICT (code) DO NOTHING`, catalogCode); err != nil {
		t.Fatalf("seed error catalog: %v", err)
	}

	svc := NewService(db, &database.RedisClient{}, &config.Config{}, zap.NewNop())
	threats := &recordingThreatList{}
	svc.SetSecurityService(threats)
	stateDir := t.TempDir()
	selfhealStore := selfheal.New(stateDir)

	type caller struct {
		name        string
		user        string
		roles       []string
		resolvedOrg string
		allowed     bool
	}
	// The refused callers go first, so each of them meets the setting as it
	// was seeded -- a refused delete is only evidence if there was something
	// to delete.
	callers := []caller{
		{"another organization's admin", tenantAdmin, []string{"admin"}, otherOrg, false},
		{"another organization's admin, request resolved to the default organization", tenantAdmin, []string{"admin"}, defaultOrg, false},
		{"another organization's super_admin", tenantSuper, []string{"admin", "super_admin"}, otherOrg, false},
		{"plain user", plainUser, []string{"user"}, defaultOrg, false},
		{"default-organization admin", platformAdmin, []string{"admin"}, defaultOrg, true},
		{"default-organization super_admin", platformSuper, []string{"super_admin"}, defaultOrg, true},
	}

	engineFor := func(cl caller) *gin.Engine {
		r := gin.New()
		v1 := r.Group("/api/v1")
		v1.Use(func(c *gin.Context) {
			c.Set("user_id", cl.user)
			c.Set("roles", cl.roles)
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: cl.resolvedOrg}))
			c.Next()
		})
		RegisterRoutes(v1, svc)
		admitManage := func(c *gin.Context) { c.Next() }
		adminhandlers.SelfHealRoutes(v1,
			adminhandlers.NewSelfHealHandler(zap.NewNop(), stateDir, t.TempDir(), nil),
			RequireAdmin(), admitManage, middleware.RequirePlatformAdmin(db, zap.NewNop()))
		return r
	}

	rawSetting := func(key string) string {
		var v string
		if err := db.Pool.QueryRow(ctx, `SELECT COALESCE((SELECT value::text FROM system_settings WHERE key = $1), '')`, key).Scan(&v); err != nil {
			t.Fatalf("read system_settings %s: %v", key, err)
		}
		return v
	}
	activeKid := func() string {
		var kid string
		if err := db.Pool.QueryRow(ctx, `SELECT COALESCE((SELECT kid FROM oauth_signing_keys WHERE status = 'active'), '')`).Scan(&kid); err != nil {
			t.Fatalf("read active signing key: %v", err)
		}
		return kid
	}
	catalogEntry := func(code string) string {
		var v string
		if err := db.Pool.QueryRow(ctx, `SELECT COALESCE((SELECT description FROM error_catalog WHERE code = $1), '<absent>')`, code).Scan(&v); err != nil {
			t.Fatalf("read error catalog %s: %v", code, err)
		}
		return v
	}
	selfhealState := func() string {
		mode, _ := selfhealStore.Mode()
		kill, _ := selfhealStore.KillSwitch()
		return fmt.Sprintf("mode=%s kill=%v", mode, kill)
	}

	n := 0
	for _, ep := range []struct {
		method, path string
		body         func(i int) string
		state        func() string // what the route changes; nil for a read
		refusedMust  func(t *testing.T, body string)
	}{
		{method: http.MethodGet, path: "/api/v1/settings/sms",
			refusedMust: func(t *testing.T, body string) {
				if strings.Contains(body, "sms-gateway.install.example.test") {
					t.Errorf("a refused read still carried the SMS provider's endpoint: %s", body)
				}
			}},
		{method: http.MethodPut, path: "/api/v1/settings/sms",
			body: func(i int) string {
				return fmt.Sprintf(`{"enabled":true,"provider":"webhook","message_prefix":"P%d","otp_length":6,"otp_expiry":300,"max_attempts":3,`+
					`"credentials":{"webhook_url":"https://collector-%d.example.test/","webhook_api_key":"********"}}`, i, i)
			},
			state: func() string { return rawSetting("sms_config") }},
		// provider mock answers 501 without sending anything, so an admitted
		// caller is told the provider cannot deliver and a refused one never
		// gets as far as merging the stored credentials in.
		{method: http.MethodPost, path: "/api/v1/settings/sms/test",
			body: func(int) string {
				return `{"phone_number":"+15550000000","settings":{"provider":"mock","credentials":{"webhook_api_key":"********"}}}`
			}},
		{method: http.MethodPut, path: "/api/v1/mfa/methods",
			body:  func(i int) string { return fmt.Sprintf(`["totp","m%d"]`, i) },
			state: func() string { return rawSetting("mfa_methods") }},
		{method: http.MethodPost, path: "/api/v1/oauth/signing-keys/rotate",
			body:  func(int) string { return `{"grace_days":1}` },
			state: activeKid},
		{method: http.MethodPost, path: "/api/v1/ip-threats",
			body:  func(i int) string { return fmt.Sprintf(`{"ip_address":"198.51.100.%d","threat_type":"manual"}`, i) },
			state: threats.snapshot},
		{method: http.MethodDelete, path: "/api/v1/ip-threats/some-entry",
			state: threats.snapshot},
		{method: http.MethodPost, path: "/api/v1/error-catalog",
			body: func(i int) string {
				return fmt.Sprintf(`{"code":"PLATFORM-GATE-NEW-%d","http_status":400,"category":"auth","description":"created %d"}`, i, i)
			},
			state: func() string {
				var v int
				_ = db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM error_catalog WHERE code LIKE 'PLATFORM-GATE-NEW-%'`).Scan(&v)
				return fmt.Sprint(v)
			}},
		{method: http.MethodPut, path: "/api/v1/error-catalog/" + catalogCode,
			body: func(i int) string {
				return fmt.Sprintf(`{"http_status":400,"category":"auth","description":"rewritten %d"}`, i)
			},
			state: func() string { return catalogEntry(catalogCode) }},
		// Last of the catalog routes: the first admitted delete removes the
		// row, and the second finds it gone.
		{method: http.MethodDelete, path: "/api/v1/error-catalog/" + catalogCode,
			state: func() string { return catalogEntry(catalogCode) }},
		// Both self-heal bodies ask for the opposite of the current state, so
		// an admitted call always changes it.
		{method: http.MethodPut, path: "/api/v1/selfheal/mode",
			body: func(int) string {
				if mode, _ := selfhealStore.Mode(); mode == "observe" {
					return `{"mode":"tier0"}`
				}
				return `{"mode":"observe"}`
			},
			state: selfhealState},
		{method: http.MethodPost, path: "/api/v1/selfheal/kill-switch",
			body: func(int) string {
				on, _ := selfhealStore.KillSwitch()
				return fmt.Sprintf(`{"enabled":%v}`, !on)
			},
			state: selfhealState},
		// No sweep script exists in the handler's scripts directory, so an
		// admitted sweep fails in the handler (500) and a refused one is 403.
		{method: http.MethodPost, path: "/api/v1/selfheal/sweep"},
	} {
		ep := ep
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			for _, cl := range callers {
				n++
				body := ""
				if ep.body != nil {
					body = ep.body(n)
				}
				var before string
				if ep.state != nil {
					before = ep.state()
				}
				w := httptest.NewRecorder()
				req := httptest.NewRequest(ep.method, ep.path, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				engineFor(cl).ServeHTTP(w, req)

				var after string
				if ep.state != nil {
					after = ep.state()
				}
				var resp map[string]interface{}
				_ = json.Unmarshal(w.Body.Bytes(), &resp)
				errMsg, _ := resp["error"].(string)

				if cl.allowed {
					if w.Code == http.StatusForbidden {
						t.Errorf("%s was refused (%s); a platform administrator must be admitted", cl.name, w.Body.String())
						continue
					}
					if ep.state != nil && ep.method != http.MethodDelete && before == after {
						t.Errorf("%s was admitted (%d) but the setting did not change: %s", cl.name, w.Code, after)
					}
					continue
				}
				if w.Code != http.StatusForbidden {
					t.Errorf("%s: status %d (%s), want 403", cl.name, w.Code, w.Body.String())
				}
				if cl.roles[0] != "user" && errMsg != middleware.PlatformAdminRequired {
					t.Errorf("%s: error %q, want %q", cl.name, errMsg, middleware.PlatformAdminRequired)
				}
				if before != after {
					t.Errorf("%s was refused but the setting changed:\n  before %s\n  after  %s", cl.name, before, after)
				}
				if ep.refusedMust != nil {
					ep.refusedMust(t, w.Body.String())
				}
			}
		})
	}

	// Admitted DELETEs are not judged per caller above, because the first one
	// leaves nothing for the second. Prove that they acted.
	if got := catalogEntry(catalogCode); got != "<absent>" {
		t.Errorf("no admitted caller deleted the catalog entry (still %q)", got)
	}
	if threats.removed == 0 {
		t.Error("no admitted caller reached the IP deny-list removal")
	}
}

// recordingThreatList stands in for the risk service behind the IP deny-list
// routes: the gate is what is under test, so it is enough to know whether a
// call reached the list at all.
type recordingThreatList struct {
	added, removed int
}

func (r *recordingThreatList) snapshot() string {
	return fmt.Sprintf("added=%d removed=%d", r.added, r.removed)
}

func (r *recordingThreatList) ListSecurityAlerts(context.Context, string, string, string, int, int) (interface{}, int, error) {
	return []interface{}{}, 0, nil
}
func (r *recordingThreatList) GetSecurityAlert(context.Context, string) (interface{}, error) {
	return nil, nil
}
func (r *recordingThreatList) UpdateAlertStatus(context.Context, string, string, string) error {
	return nil
}
func (r *recordingThreatList) ListIPThreats(context.Context, int, int) (interface{}, int, error) {
	return []interface{}{}, 0, nil
}
func (r *recordingThreatList) AddToThreatList(context.Context, string, string, string, bool, *time.Time) error {
	r.added++
	return nil
}
func (r *recordingThreatList) RemoveFromThreatList(context.Context, string) error {
	r.removed++
	return nil
}
