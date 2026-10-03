package provisioning

import (
	"crypto/rand"
	"crypto/rsa"
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
)

// TestTheSCIMServerAnswersMachineCredentialsAndAdministrators drives the REAL
// route table behind the REAL authentication middleware, with access tokens
// signed by a key the service trusts. Every SCIM user and group route refuses
// a signed-in person's own token (a plain user, an operator, an auditor, a
// person with no roles) with a SCIM 403, and lets through a machine
// credential (a client_credentials token, which names no user) and an
// administrator. The discovery routes refuse no one the middleware admits.
func TestTheSCIMServerAnswersMachineCredentialsAndAdministrators(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const issuer = "https://issuer.example.test"
	token := func(sub string, roles ...string) string {
		t.Helper()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": sub, "iss": issuer, "exp": time.Now().Add(time.Hour).Unix(),
			"client_id": "upstream-idp", "openidx_api": true,
			"org_id": "00000000-0000-0000-0000-000000000010", "roles": roles,
		})
		signed, err := tok.SignedString(key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return signed
	}
	svc := NewService(&database.PostgresDB{}, &database.RedisClient{}, &config.Config{OAuthIssuer: issuer}, zap.NewNop())
	svc.jwksCachedKey = &key.PublicKey
	svc.jwksCacheExpiry = time.Now().Add(time.Hour)
	r := gin.New()
	r.Use(gin.CustomRecovery(func(c *gin.Context, _ any) { c.AbortWithStatus(http.StatusInternalServerError) }))
	RegisterRoutes(r, svc)

	refused := func(method, path, bearer string) (bool, int, string) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/scim+json")
		req.Header.Set("Authorization", "Bearer "+bearer)
		r.ServeHTTP(w, req)
		body := w.Body.String()
		return w.Code == http.StatusForbidden && strings.Contains(body, "not a signed-in user's own token"), w.Code, body
	}
	const person = "11111111-0000-0000-0000-000000000001"
	gated, discovery := 0, 0
	for _, ri := range r.Routes() {
		if !strings.HasPrefix(ri.Path, "/scim/v2/") {
			continue
		}
		path := strings.ReplaceAll(ri.Path, ":id", "00000000-0000-0000-0000-0000000000aa")
		key := ri.Method + " " + ri.Path
		if strings.HasPrefix(ri.Path, "/scim/v2/Users") || strings.HasPrefix(ri.Path, "/scim/v2/Groups") {
			gated++
			for _, roles := range [][]string{{"user"}, {"operator"}, {"auditor"}, {}} {
				if ok, code, body := refused(ri.Method, path, token(person, roles...)); !ok {
					t.Errorf("%s let a signed-in person with roles %v through (%d %s)", key, roles, code, body)
				}
			}
			if ok, code, _ := refused(ri.Method, path, token("")); ok {
				t.Errorf("%s refused a machine credential (%d)", key, code)
			}
			for _, role := range []string{"admin", "super_admin"} {
				if ok, code, _ := refused(ri.Method, path, token(person, role)); ok {
					t.Errorf("%s refused an %s (%d)", key, role, code)
				}
			}
			continue
		}
		discovery++
		if ok, code, _ := refused(ri.Method, path, token(person, "user")); ok {
			t.Errorf("the discovery route %s refused a signed-in user (%d)", key, code)
		}
	}
	if gated != 12 || discovery < 4 {
		t.Fatalf("found %d SCIM user and group routes and %d discovery routes; want 12 and at least 4: "+
			"the census is not reading the route table", gated, discovery)
	}
}
