package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/jwksverify"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/migrations"
	"github.com/openidx/openidx/internal/organization"
)

// tokenHarness is the issuer over a migrated database, publishing its key at a
// real JWKS endpoint, with three consumers of its tokens in front of it, each
// mounted the way its binary mounts it:
//
//   - identityAPI: the identity routes behind the tenant resolver, as
//     cmd/identity-service mounts them, verified by identity's own middleware;
//   - adminAPI: an admin route behind middleware.Auth and RequireRoles, the
//     chain the services built on the shared middleware use;
//   - oauthAPI: this service's own userinfo endpoint behind the resolver.
//
// Nothing puts a claim into a request context by hand: every token is minted by
// GenerateJWT or GenerateIDToken from database rows.
type tokenHarness struct {
	t           *testing.T
	db          *database.PostgresDB
	issuer      *Service
	suffix      string
	jwksURL     string
	orgs        middleware.OrgLookup
	orgService  *organization.Service
	identityAPI *gin.Engine
	adminAPI    *gin.Engine
	oauthAPI    *gin.Engine
}

func newTokenHarness(t *testing.T) *tokenHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, cleanup := ssfSetupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	jwksverify.ResetCache()
	t.Cleanup(jwksverify.ResetCache)

	mini := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	rdb := &database.RedisClient{Client: rc}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	h := &tokenHarness{t: t, db: db, suffix: fmt.Sprintf("%d", time.Now().UnixNano())}
	h.issuer = &Service{
		db: db, redis: rdb, config: &config.Config{}, logger: zap.NewNop(),
		privateKey: key, publicKey: &key.PublicKey, issuer: "https://token-binding.test",
		clients: NewPostgresOAuthClientStore(db),
	}

	h.orgService = organization.NewService(db, rdb, &config.Config{}, zap.NewNop())
	h.orgs = organization.NewOrgLookup(h.orgService)
	resolver := middleware.TenantResolver(h.orgs, middleware.TenantResolverConfig{
		DefaultOrgFallback:     true,
		DefaultOrgID:           middleware.DefaultOrgID,
		PlatformAdminPredicate: auth.SuperAdminPredicate,
	})

	h.oauthAPI = gin.New()
	h.oauthAPI.Use(resolver)
	h.oauthAPI.GET("/.well-known/jwks.json", h.issuer.handleJWKS)
	h.oauthAPI.GET("/oauth/userinfo", h.issuer.handleUserInfo)
	srv := httptest.NewServer(h.oauthAPI)
	t.Cleanup(srv.Close)
	jwksURL := srv.URL + "/.well-known/jwks.json"
	h.jwksURL = jwksURL

	idSvc := identity.NewService(db, rdb, &config.Config{
		Environment: "production", OAuthIssuer: h.issuer.issuer, OAuthJWKSURL: jwksURL,
	}, zap.NewNop())
	h.identityAPI = gin.New()
	h.identityAPI.Use(resolver)
	identity.RegisterRoutesForProfile(h.identityAPI, idSvc, identity.ProfileAll)

	h.adminAPI = gin.New()
	h.adminAPI.Use(resolver)
	h.adminAPI.GET("/api/v1/admin/probe", middleware.AuthWithAPIKey(jwksURL, nil), middleware.RequireRoles("admin"),
		func(c *gin.Context) { c.Status(http.StatusOK) })
	return h
}

// seedUser inserts a user into orgID holding the named roles, creating each
// role in that organization as needed. Roles are per organization: an "admin"
// role in one grants nothing in another.
func (h *tokenHarness) seedUser(orgID, name string, roles ...string) string {
	h.t.Helper()
	ctx := context.Background()
	var id string
	if err := h.db.Pool.QueryRow(ctx, `
		INSERT INTO users (org_id, username, email, first_name, last_name, enabled)
		VALUES ($1::uuid, $2, $3, 'Token', 'Binding', true) RETURNING id::text`,
		orgID, name+"-"+h.suffix, name+"-"+h.suffix+"@example.test").Scan(&id); err != nil {
		h.t.Fatalf("seed user %s: %v", name, err)
	}
	for _, role := range roles {
		if _, err := h.db.Pool.Exec(ctx,
			`INSERT INTO roles (org_id, name) VALUES ($1::uuid, $2) ON CONFLICT DO NOTHING`, orgID, role); err != nil {
			h.t.Fatalf("seed role %s: %v", role, err)
		}
		var roleID string
		if err := h.db.Pool.QueryRow(ctx,
			`SELECT id::text FROM roles WHERE org_id = $1::uuid AND name = $2`, orgID, role).Scan(&roleID); err != nil {
			h.t.Fatalf("read role %s: %v", role, err)
		}
		if _, err := h.db.Pool.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
			id, roleID, orgID); err != nil {
			h.t.Fatalf("grant %s to %s: %v", role, name, err)
		}
	}
	return id
}

// registerClient registers an application in org, allowed to call OpenIDX's
// own APIs or not, and returns its client_id, which is unique across the
// install and so is made unique to the organization and the run.
func (h *tokenHarness) registerClient(org orgctx.Org, name string, apiAccess bool) string {
	h.t.Helper()
	clientID := name + "-" + org.ID[:8] + "-" + h.suffix
	if _, err := h.db.Pool.Exec(context.Background(), `
		INSERT INTO oauth_clients (client_id, name, type, api_access, org_id)
		VALUES ($1, $1, 'public', $2, $3::uuid) ON CONFLICT DO NOTHING`,
		clientID, apiAccess, org.ID); err != nil {
		h.t.Fatalf("register client %s: %v", clientID, err)
	}
	return clientID
}

// consoleClient is the application a sign-in to the console in org is issued
// to: in the default organization the seeded admin-console, which v205 left
// allowed to call the APIs, and in any other a client registered there with
// that permission, since the seeded one exists in the default organization
// only.
func (h *tokenHarness) consoleClient(org orgctx.Org) string {
	if org.ID == middleware.DefaultOrgID {
		return "admin-console"
	}
	return h.registerClient(org, "console", true)
}

// accessToken and idToken mint the two tokens a sign-in to the admin console
// produces, in the organization the sign-in resolved to.
func (h *tokenHarness) accessToken(org orgctx.Org, userID string) string {
	h.t.Helper()
	return h.tokenFor(org, userID, h.consoleClient(org))
}

// tokenFor mints the access token a sign-in to clientID in org produces.
func (h *tokenHarness) tokenFor(org orgctx.Org, userID, clientID string) string {
	h.t.Helper()
	tok, err := h.issuer.GenerateJWT(orgctx.With(context.Background(), org), userID, clientID, "openid profile email", 300)
	if err != nil {
		h.t.Fatalf("mint access token for %s: %v", clientID, err)
	}
	return tok
}

func (h *tokenHarness) idToken(org orgctx.Org, userID string) string {
	h.t.Helper()
	tok, err := h.issuer.GenerateIDToken(orgctx.With(context.Background(), org), userID, "admin-console", "", "openid profile email", 300)
	if err != nil {
		h.t.Fatalf("mint ID token: %v", err)
	}
	return tok
}

// call sends one request with a bearer and, when orgSlug is set, the X-Org-Slug
// header the gateway derives from a tenant's subdomain.
func (h *tokenHarness) call(api *gin.Engine, path, bearer, orgSlug string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	if orgSlug != "" {
		req.Header.Set("X-Org-Slug", orgSlug)
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	return w
}

var defaultOrg = orgctx.Org{ID: middleware.DefaultOrgID, Slug: "default"}

func header(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse %q: %v", token, err)
	}
	return parsed.Header
}

func TestTheIssuerTypesItsAccessTokensAndNotItsIDTokens(t *testing.T) {
	h := newTokenHarness(t)
	admin := h.seedUser(middleware.DefaultOrgID, "typ-admin", "admin")

	if typ := header(t, h.accessToken(defaultOrg, admin))["typ"]; typ != middleware.AccessTokenType {
		t.Errorf("GenerateJWT typ = %v, want %q", typ, middleware.AccessTokenType)
	}
	if typ := header(t, h.idToken(defaultOrg, admin))["typ"]; typ == middleware.AccessTokenType {
		t.Errorf("GenerateIDToken typ = %v: an ID token typed as an access token is a bearer again", typ)
	}
}

// An administrator's ID token carries their roles and permissions and is
// handed to every relying party they sign in to. It opens no admin route and
// is not an answer at userinfo; their access token, minted from the same rows,
// is the control that says the refusal is about the kind of token.
func TestAnAdminsIDTokenIsNotABearer(t *testing.T) {
	h := newTokenHarness(t)
	admin := h.seedUser(middleware.DefaultOrgID, "idt-admin", "admin")
	access, id := h.accessToken(defaultOrg, admin), h.idToken(defaultOrg, admin)

	for _, route := range []struct {
		name string
		api  *gin.Engine
		path string
	}{
		{"identity admin route", h.identityAPI, "/api/v1/identity/users/" + admin},
		{"shared-middleware admin route", h.adminAPI, "/api/v1/admin/probe"},
		{"userinfo", h.oauthAPI, "/oauth/userinfo"},
	} {
		if w := h.call(route.api, route.path, access, ""); w.Code != http.StatusOK {
			t.Errorf("%s: the admin's access token answered %d, want 200: %s", route.name, w.Code, w.Body.String())
		}
		if w := h.call(route.api, route.path, id, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: the admin's ID token answered %d, want 401: %s", route.name, w.Code, w.Body.String())
		}
	}
}
