package access

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The MCP gateway and device enrollment verify a bearer themselves, with
// middleware.VerifyBearerToken, rather than behind middleware.Auth. So each
// has to hold the token to the organization the request resolved to, as
// middleware.Auth does: the token's subject and roles are its holder's in the
// organization it was minted in, while the MCP server, its allowlist and the
// enrollment belong to the request's. A real key signs real tokens here and a
// real JWKS endpoint serves the public half, so the only thing standing between
// a token and another organization is the binding under test.

// bearerKey signs every token in this file: 2048-bit RSA key generation is the
// slowest thing here by an order of magnitude, and every case wants the same
// key.
var bearerKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

// bearerKid names bearerKey in the JWKS. VerifyBearerToken's key cache is
// process-wide and keyed by kid, so no other test in this package signs under
// it.
const bearerKid = "access-bearer-org-binding"

const (
	bearerOrgA    = "aaaaaaaa-0000-0000-0000-00000000000a"
	bearerOrgB    = "bbbbbbbb-0000-0000-0000-00000000000b"
	bearerSubject = "11111111-1111-1111-1111-111111111111"
)

// bearerJWKS serves the public half of bearerKey and returns its URL.
func bearerJWKS(t *testing.T) string {
	t.Helper()
	pub := &bearerKey.PublicKey
	jwks := middleware.JWKS{Keys: []middleware.JWKSKey{{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: bearerKid,
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// bearerFor signs an access token that the agent client agent-a holds for an
// administrator, minted in org, or naming no organization when org is empty.
func bearerFor(t *testing.T, org string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": bearerSubject, "client_id": "agent-a", "roles": []interface{}{"admin"},
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	if org != "" {
		claims[middleware.OrgIDClaim] = org
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = bearerKid
	tok.Header["typ"] = middleware.AccessTokenType
	signed, err := tok.SignedString(bearerKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// inOrg scopes r to org, as the tenant resolver the service mounts ahead of
// these routes does.
func inOrg(r *http.Request, org string) *http.Request {
	return r.WithContext(orgctx.With(r.Context(), orgctx.Org{ID: org}))
}

// Both organizations run an MCP server named helpdesk whose allowlist admits
// "admin", a role name every organization has. Organization A's agent token is
// refused at organization B's gateway before B's server is reached, is served
// by A's own, and a token naming no organization is refused.
func TestTheMCPGatewayBindsATokenToItsOrganization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
		t.Fatalf("pgcrypto: %v", err)
	}
	// require_approval is read by the approval gate; no tool here needs one.
	for _, stmt := range []string{mcpSchema,
		`ALTER TABLE mcp_tool_policies ADD COLUMN IF NOT EXISTS require_approval BOOLEAN NOT NULL DEFAULT false`} {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	s := &Service{db: db, logger: zap.NewNop(), oauthJWKSURL: bearerJWKS(t)}

	var reached [2]atomic.Int32 // calls each organization's upstream received
	for i, org := range []string{bearerOrgA, bearerOrgB} {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached[i].Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		t.Cleanup(upstream.Close)
		srv, err := s.CreateMCPServer(ctx, org, &MCPServerInput{Name: "helpdesk", UpstreamURL: upstream.URL, Enabled: true})
		if err != nil {
			t.Fatalf("create %s's server: %v", org, err)
		}
		if err := s.AddMCPToolPolicy(ctx, org, srv.ID, &MCPToolPolicyInput{Principal: "role:admin", Tool: "search"}); err != nil {
			t.Fatalf("seed %s's allowlist: %v", org, err)
		}
	}

	router := gin.New()
	router.POST("/api/v1/mcp/:server/tools/:tool", s.handleMCPInvoke)
	invoke := func(org, bearer string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/helpdesk/tools/search", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, inOrg(req, org))
		return w
	}

	if w := invoke(bearerOrgB, bearerFor(t, bearerOrgA)); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), middleware.ErrWrongOrganization.Error()) {
		t.Errorf("org A's token at org B's gateway answered %d %s, want 403 %q",
			w.Code, w.Body.String(), middleware.ErrWrongOrganization)
	}
	if n := reached[1].Load(); n != 0 {
		t.Errorf("org B's MCP server was called %d time(s) with org A's token", n)
	}
	if w := invoke(bearerOrgA, bearerFor(t, bearerOrgA)); w.Code != http.StatusOK || reached[0].Load() != 1 {
		t.Errorf("org A's token at its own gateway answered %d %s after %d upstream call(s), want 200 from org A's server",
			w.Code, w.Body.String(), reached[0].Load())
	}
	if w := invoke(bearerOrgA, bearerFor(t, "")); w.Code != http.StatusUnauthorized {
		t.Errorf("a token naming no organization answered %d %s, want 401", w.Code, w.Body.String())
	}
}

// A verified session entitles its holder to enroll a device only in the
// organization the token was minted in. Anywhere else, and for a token naming
// no organization, the bearer is no session, and a request presenting no other
// entitlement is refused.
func TestEnrollBindsASessionToItsOrganization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{logger: zap.NewNop(), oauthJWKSURL: bearerJWKS(t)}
	resolve := func(org, bearer string) (string, string, error) {
		t.Helper()
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = inOrg(httptest.NewRequest(http.MethodPost, "/api/v1/access/enroll", strings.NewReader(`{}`)), org)
		c.Request.Header.Set("Authorization", "Bearer "+bearer)
		return s.resolveEnrollSubject(c, &darkEnrollRequest{})
	}

	if sub, method, err := resolve(bearerOrgA, bearerFor(t, bearerOrgA)); err != nil || sub != bearerSubject || method != "session" {
		t.Errorf("org A's session enrolling in org A: subject %q, method %q, error %v; want %q by session",
			sub, method, err, bearerSubject)
	}
	if sub, method, err := resolve(bearerOrgB, bearerFor(t, bearerOrgA)); err == nil {
		t.Errorf("org A's session enrolled a device in org B for %q by %s", sub, method)
	}
	if sub, method, err := resolve(bearerOrgA, bearerFor(t, "")); err == nil {
		t.Errorf("a token naming no organization enrolled a device for %q by %s", sub, method)
	}
}
