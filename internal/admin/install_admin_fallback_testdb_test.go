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

	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/organization"
)

// DEFAULT_ORG_ID DOES NOT CHOOSE WHO ADMINISTERS THE INSTALL.
//
// DEFAULT_ORG_ID names the tenant resolver's fallback: the organization a
// request with no other tenant signal belongs to. An operator can point it at
// any organization, a customer's included, and that must not make the
// customer's administrators administrators of the install. Here the service
// and the resolver in front of it are configured as cmd/admin-api would be with
// a tenant's organization as the fallback, and two administrators change the
// SMS settings -- one row for every organization -- through RegisterRoutes,
// behind a stand-in for the validator that binds their user id, roles and
// credential organization:
//
//   - the tenant's admin, whose request falls back to their own organization,
//     is refused with "platform administrator required" and the setting reads
//     back unchanged;
//   - the default organization's admin gets through, though the fallback names
//     another organization.
func TestTheFallbackOrganizationDoesNotChooseInstallAdministrators(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupPAMTestDB(t)
	t.Cleanup(cleanup)
	ctx := orgctx.WithBypassRLS(context.Background())
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	scalar := func(query string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, query, args...).Scan(&v); err != nil {
			t.Fatalf("read %q: %v", query, err)
		}
		return v
	}
	tenant := scalar(`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "fallback-tenant-"+suffix)
	seedUser := func(org, name string) string {
		return scalar(`INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2::text, $2::text || '@example.test', true)
			RETURNING id::text`, org, name+"-"+suffix)
	}
	tenantAdmin := seedUser(tenant, "fallback-tenant-admin")
	defaultAdmin := seedUser(middleware.DefaultOrgID, "fallback-default-admin")
	scalar(`INSERT INTO system_settings (key, value) VALUES ('sms_config', $1::jsonb)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value RETURNING key`,
		`{"enabled":true,"provider":"webhook","message_prefix":"Install","otp_length":6,"otp_expiry":300,"max_attempts":3,`+
			`"credentials":{"webhook_url":"https://sms-gateway.install.example.test/send","webhook_api_key":"install-key"}}`)
	smsConfig := func() string {
		return scalar(`SELECT value::text FROM system_settings WHERE key = 'sms_config'`)
	}

	cfg := &config.Config{DefaultOrgFallback: true, DefaultOrgID: tenant}
	svc := NewService(db, &database.RedisClient{}, cfg, zap.NewNop())
	lookup := organization.NewOrgLookup(organization.NewService(db, &database.RedisClient{}, cfg, zap.NewNop()))
	putSMS := func(user, credentialOrg string, n int) (int, string) {
		t.Helper()
		r := gin.New()
		v1 := r.Group("/api/v1")
		v1.Use(func(c *gin.Context) {
			c.Set("user_id", user)
			c.Set("roles", []string{"admin"})
			c.Set("org_id", credentialOrg)
			c.Next()
		})
		v1.Use(middleware.TenantResolver(lookup, middleware.TenantResolverConfig{
			DefaultOrgFallback:     cfg.DefaultOrgFallback,
			DefaultOrgID:           cfg.DefaultOrgID,
			PlatformAdminPredicate: auth.SuperAdminPredicate,
		}))
		v1.GET("/probe/resolved", func(c *gin.Context) {
			org, _ := orgctx.From(c.Request.Context())
			c.String(http.StatusOK, org.ID)
		})
		RegisterRoutes(v1, svc)

		// Where the request resolved, to show the fallback is in play.
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/probe/resolved", nil))
		if want := credentialOrg; w.Body.String() != want {
			t.Fatalf("the request resolved to %q, want the caller's own organization %q", w.Body.String(), want)
		}

		body := fmt.Sprintf(`{"enabled":true,"provider":"webhook","message_prefix":"P%d","otp_length":6,"otp_expiry":300,"max_attempts":3,`+
			`"credentials":{"webhook_url":"https://collector-%d.example.test/","webhook_api_key":"********"}}`, n, n)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/sms", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var resp map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		msg, _ := resp["error"].(string)
		return w.Code, msg
	}

	before := smsConfig()
	if code, msg := putSMS(tenantAdmin, tenant, 1); code != http.StatusForbidden || msg != middleware.PlatformAdminRequired {
		t.Errorf("the admin of the organization DEFAULT_ORG_ID names: %d %q, want 403 %q", code, msg, middleware.PlatformAdminRequired)
	}
	if after := smsConfig(); after != before {
		t.Errorf("the tenant's admin was refused but the SMS settings changed:\n  before %s\n  after  %s", before, after)
	}
	if code, msg := putSMS(defaultAdmin, middleware.DefaultOrgID, 2); code != http.StatusOK {
		t.Errorf("the default organization's admin: %d %q, want 200", code, msg)
	}
	if after := smsConfig(); after == before {
		t.Error("the default organization's admin was admitted but the SMS settings did not change")
	}
}
