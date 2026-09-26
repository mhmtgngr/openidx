package identity

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
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// THE PASSWORDLESS SETTINGS ARE THE INSTALL'S, NOT AN ORGANIZATION'S.
//
// They are one system_settings row, read by CreateMagicLink and
// CreateQRLoginSession for every organization, so turning magic links off --
// or stretching their lifetime -- is a change to every tenant's login.
//
// Driven end to end: RegisterRoutes builds identity's real route table, a real
// RSA key signs each caller's token and a JWKS endpoint serves it, so the roles
// the gates read are the ones openIDXAuthMiddleware bound from a verified token.
// The stored row is read back after every request.
func TestPasswordlessSettingsNeedAPlatformAdministrator(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)

	ctx := orgctx.WithBypassRLS(context.Background())
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

	jwks := jwksServer(t)
	// DEFAULT_ORG_ID names the tenant, as an operator might point the resolver's
	// fallback at a customer's organization. It must not make that
	// organization's administrators the install's: every caller below is judged
	// against the default organization all the same.
	cfg := &config.Config{Environment: "production", OAuthIssuer: "https://issuer.test", OAuthJWKSURL: jwks.URL,
		DefaultOrgID: otherOrg}
	svc := NewService(db, &database.RedisClient{}, cfg, zap.NewNop())
	r := gin.New()
	RegisterRoutes(r, svc)

	stored := func() string {
		var v string
		if err := db.Pool.QueryRow(ctx,
			`SELECT COALESCE((SELECT value::text FROM system_settings WHERE key = 'passwordless'), '')`).Scan(&v); err != nil {
			t.Fatalf("read passwordless settings: %v", err)
		}
		return v
	}

	type caller struct {
		name    string
		user    string
		org     string
		roles   []string
		allowed bool
	}
	callers := []caller{
		{"another organization's admin", tenantAdmin, otherOrg, []string{"admin"}, false},
		{"another organization's super_admin", tenantSuper, otherOrg, []string{"admin", "super_admin"}, false},
		// The token names the default organization, and the user's own row
		// does not: the users lookup refuses it.
		{"another organization's admin, with a token naming the default organization", tenantAdmin, defaultOrg, []string{"admin"}, false},
		// The user's own row is in the default organization, and the token
		// names another: the roles are that token's, and the credential's
		// organization refuses it.
		{"a default-organization admin, with a token naming another organization", platformAdmin, otherOrg, []string{"admin"}, false},
		{"plain user", plainUser, defaultOrg, []string{"user"}, false},
		{"default-organization admin", platformAdmin, defaultOrg, []string{"admin"}, true},
		{"default-organization super_admin", platformSuper, defaultOrg, []string{"super_admin"}, true},
	}

	n := 0
	for _, ep := range []struct {
		method string
		body   func(i int) string
	}{
		{http.MethodPut, func(i int) string {
			return fmt.Sprintf(`{"magic_link_enabled":true,"magic_link_expiry_minutes":%d,"qr_login_enabled":true,"qr_session_expiry_minutes":5,"max_magic_links_per_hour":5}`, 10+i)
		}},
		{http.MethodPatch, func(i int) string { return fmt.Sprintf(`{"magic_link_expiry_minutes":%d}`, 10+i) }},
	} {
		t.Run(ep.method, func(t *testing.T) {
			for _, cl := range callers {
				n++
				bearer := token(t, cfg.OAuthIssuer, jwt.MapClaims{
					"sub": cl.user, "roles": cl.roles, "org_id": cl.org,
				})
				before := stored()
				req := httptest.NewRequest(ep.method, "/api/v1/identity/passwordless/settings", strings.NewReader(ep.body(n)))
				req.Header.Set("Authorization", "Bearer "+bearer)
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				after := stored()

				var resp map[string]interface{}
				_ = json.Unmarshal(w.Body.Bytes(), &resp)
				if cl.allowed {
					if w.Code != http.StatusOK {
						t.Errorf("%s: status %d (%s), want 200", cl.name, w.Code, w.Body.String())
					}
					if before == after {
						t.Errorf("%s was admitted but the stored settings did not change: %s", cl.name, after)
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
					t.Errorf("%s was refused but the stored settings changed:\n  before %s\n  after  %s", cl.name, before, after)
				}
			}
		})
	}

	// The read stays an admin read: it holds switches and lifetimes, no secret,
	// and the console's page is built on it.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/identity/passwordless/settings", nil)
	req.Header.Set("Authorization", "Bearer "+token(t, cfg.OAuthIssuer, jwt.MapClaims{
		"sub": tenantAdmin, "roles": []string{"admin"}, "org_id": otherOrg,
	}))
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("another organization's admin reading the settings: status %d (%s), want 200", w.Code, w.Body.String())
	}
}
