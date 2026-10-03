package audit

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/cell"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
)

// notAuditRead names the audit-service routes the reader gate does not decide:
// the ingest route takes the internal service token, the webhook routes need an
// administrator, and the WebSocket upgrade checks its own token (driven below).
func notAuditRead(method, path string) bool {
	return (method == http.MethodPost && path == "/api/v1/audit/events") ||
		strings.HasPrefix(path, "/api/v1/audit/webhooks") ||
		(method == http.MethodGet && path == "/api/v1/audit/stream")
}

// TestTheAuditTrailIsReadByTheRolesThatHoldAuditRead drives the REAL route
// table as cmd/audit-service mounts it, behind the REAL JWT middleware, with
// access tokens signed by a key the JWKS serves. Every read, report, export,
// scheduled-report and stream route answers a plain user, a caller with no
// roles, a machine credential and an unknown role 403 audit_reader_required,
// and lets super_admin, admin, operator, auditor and compliance_reader past the
// gate. The WebSocket stream refuses and admits the same roles at its upgrade.
func TestTheAuditTrailIsReadByTheRolesThatHoldAuditRead(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "audit-reader-gate"
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(middleware.JWKS{Keys: []middleware.JWKSKey{{
			Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid,
			N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	defer jwksSrv.Close()
	token := func(sub string, roles ...string) string {
		t.Helper()
		claims := jwt.MapClaims{
			"sub": sub, "client_id": "admin-console", middleware.APIAccessClaim: true,
			middleware.OrgIDClaim: middleware.DefaultOrgID, "exp": time.Now().Add(time.Hour).Unix(),
		}
		if roles != nil {
			rs := make([]interface{}, len(roles))
			for i, r := range roles {
				rs[i] = r
			}
			claims["roles"] = rs
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		tok.Header["typ"] = middleware.AccessTokenType
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	const person = "11111111-0000-0000-0000-000000000001"
	refusedCallers := map[string]string{
		"a plain user":           token(person, "user"),
		"a caller with no roles": token(person),
		"a machine credential":   token("", []string{}...),
		"an unknown role":        token(person, "auditors"),
	}
	admitted := []string{"super_admin", "admin", "operator", "auditor", "compliance_reader"}

	// The chain cmd/audit-service mounts when OAUTH_JWKS_URL is set.
	cfg := &config.Config{OAuthJWKSURL: jwksSrv.URL}
	svc := NewService(&database.PostgresDB{}, nil, cfg, zap.NewNop())
	r := gin.New()
	r.Use(gin.CustomRecovery(func(c *gin.Context, _ any) { c.AbortWithStatus(http.StatusInternalServerError) }))
	auditAuth := []gin.HandlerFunc{middleware.Auth(jwksSrv.URL), cell.Guard("", zap.NewNop())}
	RegisterRoutes(r, svc, auditAuth...)
	RegisterReportRoutes(r.Group("/api/v1/audit"), svc, auditAuth...)
	streamer := NewEventStreamerWithConfig(zap.NewNop(), svc, nil)
	streamer.SetJWKSURL(jwksSrv.URL)
	streamer.RegisterRoutes(r.Group("/api/v1/audit"))

	gated := func(method, path, bearer string) (bool, int) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+bearer)
		r.ServeHTTP(w, req)
		return w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), `"audit_reader_required"`), w.Code
	}
	reads := 0
	for _, ri := range r.Routes() {
		if !strings.HasPrefix(ri.Path, "/api/v1/audit/") || notAuditRead(ri.Method, ri.Path) {
			continue
		}
		reads++
		key := ri.Method + " " + ri.Path
		path := strings.NewReplacer(":id", "00000000-0000-0000-0000-0000000000aa").Replace(ri.Path)
		for who, bearer := range refusedCallers {
			if g, code := gated(ri.Method, path, bearer); !g {
				t.Errorf("%s: %s got past the audit reader gate (%d)", key, who, code)
			}
		}
		for _, role := range admitted {
			if g, code := gated(ri.Method, path, token(person, role)); g {
				t.Errorf("%s: the gate refused a %s (%d)", key, role, code)
			}
		}
	}
	if reads < 20 {
		t.Fatalf("only %d audit read routes were found; the census is not reading the route table", reads)
	}
	if g, code := gated(http.MethodPost, "/api/v1/audit/events", token(person, "user")); g {
		t.Errorf("the ingest route was decided by the reader gate (%d); it takes the internal service token", code)
	}

	// The WebSocket stream: its token arrives as a subprotocol and is checked
	// before the upgrade, so a refused caller gets the gate's 403 and an
	// admitted one reaches the upgrade (which a plain request then fails).
	stream := func(bearer string) (bool, int) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/stream", nil)
		req.Header.Set("Sec-WebSocket-Protocol", "access_token_"+bearer)
		r.ServeHTTP(w, req)
		return w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), `"audit_reader_required"`), w.Code
	}
	for who, bearer := range refusedCallers {
		if g, code := stream(bearer); !g {
			t.Errorf("the WebSocket stream let %s through (%d)", who, code)
		}
	}
	for _, role := range admitted {
		if g, code := stream(token(person, role)); g {
			t.Errorf("the WebSocket stream refused a %s (%d)", role, code)
		}
	}
}

// TestTheAuditReaderGateIsOpenOnlyWhereAuthenticationIsNot: outside
// production with no OAUTH_JWKS_URL, cmd/audit-service mounts no
// authentication on these routes and says so at start-up; the gate does not
// shut them there. In production, or with a JWKS URL, a request with no roles
// is refused.
func TestTheAuditReaderGateIsOpenOnlyWhereAuthenticationIsNot(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		open bool
	}{
		{"development without a JWKS URL", &config.Config{Environment: "development"}, true},
		{"production without a JWKS URL", &config.Config{Environment: "production"}, false},
		{"development with a JWKS URL", &config.Config{Environment: "development", OAuthJWKSURL: "https://issuer.example.test/jwks"}, false},
		{"no configuration", nil, false},
	} {
		svc := &Service{config: tc.cfg, logger: zap.NewNop()}
		r := gin.New()
		r.GET("/probe", svc.requireAuditReader(), func(c *gin.Context) { c.Status(http.StatusNoContent) })
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/probe", nil))
		if open := w.Code == http.StatusNoContent; open != tc.open {
			t.Errorf("%s: answered %d, want open=%v", tc.name, w.Code, tc.open)
		}
	}
}
