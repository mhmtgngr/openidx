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

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/jwksverify"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// The Role / group row of docs/evidence/display-equals-enforcement.md with a
// real token: "probe an admin route as a member, then as a non-member".
//
// The roles the Users page shows are user_roles rows. The token is minted from
// those rows by the issuer (GenerateJWT), its key is published at the issuer's
// JWKS endpoint, and the admin route is guarded the way the services guard it:
// middleware.Auth verifies the token against that JWKS, and RequireRoles reads
// the roles claim. Nothing is put into the request context by hand.
func TestARealTokenOpensAnAdminRouteOnlyForAMember(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := ssfSetupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	jwksverify.ResetCache()
	t.Cleanup(jwksverify.ResetCache)

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	seedUser := func(name string) string {
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
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO roles (org_id, name) VALUES ($1::uuid, 'admin') ON CONFLICT DO NOTHING`, org); err != nil {
		t.Fatalf("seed admin role: %v", err)
	}
	var adminRole string
	if err := db.Pool.QueryRow(ctx,
		`SELECT id::text FROM roles WHERE org_id = $1::uuid AND name = 'admin'`, org).Scan(&adminRole); err != nil {
		t.Fatalf("read admin role: %v", err)
	}
	assign := func(userID string, expires *time.Time) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, org_id, expires_at)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4)`, userID, adminRole, org, expires); err != nil {
			t.Fatalf("assign admin to %s: %v", userID, err)
		}
	}
	member := seedUser("probe-admin")
	assign(member, nil)
	nonMember := seedUser("probe-user")
	lapsed := seedUser("probe-lapsed")
	past := time.Now().Add(-time.Minute)
	assign(lapsed, &past)
	removed := seedUser("probe-removed")
	assign(removed, nil)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	issuer := &Service{
		db: db, config: &config.Config{}, logger: zap.NewNop(),
		privateKey: key, publicKey: &key.PublicKey, issuer: "https://role-probe.test",
	}
	jwks := gin.New()
	jwks.GET("/.well-known/jwks.json", issuer.handleJWKS)
	jwksServer := httptest.NewServer(jwks)
	t.Cleanup(jwksServer.Close)

	api := gin.New()
	api.Use(middleware.Auth(jwksServer.URL + "/.well-known/jwks.json"))
	api.GET("/admin/users", middleware.RequireRoles("admin"), func(c *gin.Context) { c.Status(http.StatusOK) })
	probe := func(token string) int {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		api.ServeHTTP(w, req)
		return w.Code
	}
	mint := func(userID string) string {
		t.Helper()
		tok, err := issuer.GenerateJWT(orgCtx, userID, "admin-console", "openid", 300)
		if err != nil {
			t.Fatalf("mint token for %s: %v", userID, err)
		}
		return tok
	}

	t.Run("a member of the admin role gets in", func(t *testing.T) {
		if code := probe(mint(member)); code != http.StatusOK {
			t.Fatalf("status %d, want 200", code)
		}
	})
	t.Run("a user without the role is refused", func(t *testing.T) {
		if code := probe(mint(nonMember)); code != http.StatusForbidden {
			t.Fatalf("status %d, want 403", code)
		}
	})
	t.Run("a time-bound role that has lapsed is not in the token", func(t *testing.T) {
		if code := probe(mint(lapsed)); code != http.StatusForbidden {
			t.Fatalf("status %d, want 403", code)
		}
	})
	t.Run("a token minted after the role is removed is refused", func(t *testing.T) {
		if code := probe(mint(removed)); code != http.StatusOK {
			t.Fatalf("before removal: status %d, want 200", code)
		}
		if _, err := db.Pool.Exec(ctx,
			`DELETE FROM user_roles WHERE user_id = $1::uuid AND role_id = $2::uuid`, removed, adminRole); err != nil {
			t.Fatalf("remove role: %v", err)
		}
		if code := probe(mint(removed)); code != http.StatusForbidden {
			t.Fatalf("after removal: status %d, want 403", code)
		}
	})
	t.Run("a token the issuer did not sign is refused", func(t *testing.T) {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		forged := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": member, "roles": []string{"admin"}, "iss": "https://role-probe.test",
			"exp": time.Now().Add(time.Minute).Unix(), "org_id": org,
		})
		kid, _, _ := jwt.NewParser().ParseUnverified(mint(member), jwt.MapClaims{})
		forged.Header["kid"] = kid.Header["kid"]
		signed, err := forged.SignedString(other)
		if err != nil {
			t.Fatal(err)
		}
		if code := probe(signed); code != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", code)
		}
		if code := probe(""); code != http.StatusUnauthorized {
			t.Fatalf("no token: status %d, want 401", code)
		}
	})
}
