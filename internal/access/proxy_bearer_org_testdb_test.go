package access

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/migrations"
)

// machineBearer signs a client_credentials-shaped access token: an application
// allowed to call the API, in org, with no subject.
func machineBearer(t *testing.T, org string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "", "client_id": "batch-job", "aud": "batch-job",
		middleware.APIAccessClaim: true, middleware.OrgIDClaim: org,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = bearerKid
	tok.Header["typ"] = middleware.AccessTokenType
	signed, err := tok.SignedString(bearerKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// A route that asks only for a signed-in caller, in organization B, behind
// the APISIX forward-auth hook and the built-in proxy. A bearer is a session
// only for a person of the route's organization: org A's token for its admin
// and a machine token naming no subject are both sent to sign in, and org B's
// token for a person passes. Both used to pass: a bearer session named no
// organization, and a subjectless token made a session of nobody.
func TestABearerIsHeldToItsRoutesOrganization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := t.Context()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1::uuid, 'B', 'bearer-b')
		ON CONFLICT DO NOTHING`, bearerOrgB); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	host := "payroll-bearer.example.test"
	if _, err := db.Pool.Exec(ctx, `INSERT INTO proxy_routes (org_id, name, from_url, to_url, require_auth, enabled)
		VALUES ($1::uuid, 'payroll-bearer', $2, 'http://127.0.0.1:9', true, true)`, bearerOrgB, "https://"+host); err != nil {
		t.Fatalf("seed route: %v", err)
	}
	mini := miniredis.RunT(t)
	s := &Service{
		db: db, logger: zap.NewNop(), oauthJWKSURL: bearerJWKS(t),
		redis:  &database.RedisClient{Client: redis.NewClient(&redis.Options{Addr: mini.Addr()})},
		config: &config.Config{},
	}
	r := gin.New()
	r.GET("/access/.auth/decide", s.handleAuthDecide)
	decide := func(bearer string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/access/.auth/decide", nil)
		req.Header.Set("X-Forwarded-Host", host)
		req.Header.Set("X-Forwarded-Uri", "/salaries")
		req.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	if code := decide(bearerFor(t, bearerOrgA)); code != http.StatusFound {
		t.Errorf("org A's admin token on org B's route answered %d, want 302 to sign in", code)
	}
	if code := decide(machineBearer(t, bearerOrgB)); code != http.StatusFound {
		t.Errorf("a machine token naming no subject answered %d, want 302 to sign in", code)
	}
	if code := decide(bearerFor(t, bearerOrgB)); code != http.StatusOK {
		t.Errorf("org B's own token answered %d, want 200", code)
	}

	// The built-in reverse proxy, the other enforcement point: org A's token
	// is sent to sign in before anything is forwarded.
	p := gin.New()
	p.NoRoute(s.handleProxy)
	req := httptest.NewRequest(http.MethodGet, "/salaries", nil)
	req.Host = host
	req.Header.Set("Authorization", "Bearer "+bearerFor(t, bearerOrgA))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("the built-in proxy answered org A's token on org B's route with %d, want 302", w.Code)
	}
}

// The bearer session itself names its organization and its person.
func TestABearerSessionNamesItsOrganization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{logger: zap.NewNop(), oauthJWKSURL: bearerJWKS(t)}
	session := func(bearer string) *ProxySession {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("Authorization", "Bearer "+bearer)
		return s.getSessionFromBearer(c)
	}
	if got := session(bearerFor(t, bearerOrgA)); got == nil || got.orgID != bearerOrgA || got.UserID != bearerSubject {
		t.Errorf("org A's token made %+v", got)
	}
	if got := session(machineBearer(t, bearerOrgA)); got != nil {
		t.Errorf("a token with no subject made a session for %q", got.UserID)
	}
	if sessionOnRoute(session(bearerFor(t, bearerOrgA)), &ProxyRoute{OrgID: bearerOrgB}) != nil {
		t.Error("org A's bearer session is accepted on org B's route")
	}
}
