package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// THE PLATFORM-ADMINISTRATOR LOOKUP UNDER THE BELT IT HAS TO CROSS.
//
// users is FORCE'd behind row-level security, and a superuser ignores RLS
// entirely -- so a test connected as the container's default user would pass
// whether or not the lookup took the bypass. This one connects the gate's pool
// as an ordinary member of openidx_app, the runtime role, with the production
// checkout hook, and then drives requests whose resolved tenant differs from
// the caller's own organization in both directions:
//
//   - a platform administrator working inside another tenant must still be
//     recognised: their user row is outside the request's scope, so only the
//     bypassed read finds it;
//   - an administrator of another organization whose request resolved to the
//     default organization must still be refused: the resolved tenant is not
//     their organization and must not stand in for it;
//   - and a default-organization administrator presenting a credential of
//     another organization is refused: the roles are that credential's.
func TestRequirePlatformAdminAgainstTheRLSBelt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	admin := delegationTestPool(t) // migrated; skips when no database is configured
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	var otherOrg string
	if err := admin.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`,
		"platform-other-"+suffix).Scan(&otherOrg); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	seedUser := func(org, name string) string {
		t.Helper()
		var id string
		if err := admin.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	platformAdmin := seedUser(DefaultOrgID, "platform-admin")
	tenantAdmin := seedUser(otherOrg, "tenant-admin")
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DELETE FROM users WHERE id = ANY(ARRAY[$1,$2]::uuid[])`, platformAdmin, tenantAdmin)
		_, _ = admin.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1::uuid`, otherOrg)
	})

	// An ordinary login role that inherits openidx_app's grants. Roles are
	// cluster-wide, so the name is unique to this run and dropped afterwards.
	role := "platform_gate_" + suffix
	password := "pw_" + suffix
	if _, err := admin.Exec(ctx, fmt.Sprintf(
		`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOBYPASSRLS IN ROLE openidx_app`, role, password)); err != nil {
		t.Skipf("cannot create a non-superuser role to test RLS with (%v); the decision itself is covered by TestPlatformAdminDecision", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), `DROP ROLE IF EXISTS `+role) })

	appURL, err := url.Parse(admin.Config().ConnString())
	if err != nil {
		t.Fatalf("parse test DSN: %v", err)
	}
	appURL.User = url.UserPassword(role, password)
	appDB, err := database.NewPostgres(appURL.String())
	if err != nil {
		t.Fatalf("connect as the non-superuser role: %v", err)
	}
	t.Cleanup(func() { _ = appDB.Close() })

	// Vacuity: prove the belt is on for this role. A scoped read of the
	// platform administrator's row from inside another tenant must see nothing,
	// or the cases below would pass without the bypass they exist to test.
	var visible int
	if err := appDB.Pool.QueryRow(orgctx.With(ctx, orgctx.Org{ID: otherOrg}),
		`SELECT COUNT(*) FROM users WHERE id = $1`, platformAdmin).Scan(&visible); err != nil {
		t.Fatalf("scoped read: %v", err)
	}
	if visible != 0 {
		t.Fatalf("a read scoped to another tenant saw the default organization's user; RLS is not in force for %s, so this test would prove nothing", role)
	}

	gate := RequirePlatformAdmin(appDB, zap.NewNop())
	call := func(userID, credentialOrg, resolvedOrg string, roles ...string) (int, string) {
		t.Helper()
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Set("user_id", userID)
			c.Set("roles", roles)
			c.Set("org_id", credentialOrg)
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: resolvedOrg}))
			c.Next()
		})
		r.PUT("/settings/sms", gate, func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"saved": true}) })
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/settings/sms", nil))
		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		msg, _ := body["error"].(string)
		return w.Code, msg
	}

	for _, tc := range []struct {
		name          string
		user          string
		credentialOrg string
		resolvedOrg   string
		roles         []string
		want          int
	}{
		{"a default-organization admin in their own organization", platformAdmin, DefaultOrgID, DefaultOrgID, []string{"admin"}, http.StatusOK},
		{"a default-organization admin working inside another tenant", platformAdmin, DefaultOrgID, otherOrg, []string{"admin"}, http.StatusOK},
		{"a default-organization super_admin working inside another tenant", platformAdmin, DefaultOrgID, otherOrg, []string{"super_admin"}, http.StatusOK},
		{"another organization's admin in their own organization", tenantAdmin, otherOrg, otherOrg, []string{"admin"}, http.StatusForbidden},
		{"another organization's admin whose request resolved to the default organization", tenantAdmin, otherOrg, DefaultOrgID, []string{"admin"}, http.StatusForbidden},
		{"another organization's super_admin whose request resolved to the default organization", tenantAdmin, otherOrg, DefaultOrgID, []string{"super_admin"}, http.StatusForbidden},
		// The users lookup alone would admit this one; the credential is what refuses it.
		{"a default-organization admin presenting a credential of another organization", platformAdmin, otherOrg, otherOrg, []string{"admin"}, http.StatusForbidden},
		{"a plain user of the default organization", platformAdmin, DefaultOrgID, DefaultOrgID, []string{"user"}, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, msg := call(tc.user, tc.credentialOrg, tc.resolvedOrg, tc.roles...)
			if code != tc.want {
				t.Fatalf("status %d (%q), want %d", code, msg, tc.want)
			}
			if code == http.StatusForbidden && msg != PlatformAdminRequired {
				t.Errorf("error = %q, want %q", msg, PlatformAdminRequired)
			}
		})
	}
}
