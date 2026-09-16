package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/cell"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// identity-service REFUSING A TOKEN MINTED IN ANOTHER CELL, END TO END.
//
// Nothing here stubs the middleware. A real RSA key signs a real token, a real
// JWKS endpoint serves the public half, openIDXAuthMiddleware verifies the
// signature and binds the claims, and cell.Guard is mounted exactly the way
// cmd/identity-service mounts it. The reason for going the long way round is
// that the defect this item started from was invisible from any shorter angle:
// the guard reads the key middleware.BindSubjectClaims binds, and this service
// used to extract "roles" by hand and bind nothing else. Mounting the guard on
// top of that would have produced a service that answers 200 to every
// misdirected request while a census records it as guarded -- a control
// reporting success while the thing it exists to make true is not true.
//
// A test that fed the guard a claims map directly would have passed against
// that exact defect. This one cannot: the only thing that puts the cell claim
// in the gin context here is the authentication middleware under test.

// signingKey is generated once: 2048-bit RSA keygen is the slowest thing in
// this file by an order of magnitude, and every case wants the same key.
var signingKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

// jwksServer serves the public half of signingKey in the shape
// getOAuthPublicKey parses: the first RSA key with use "sig".
func jwksServer(t *testing.T) *httptest.Server {
	t.Helper()
	pub := signingKey.Public().(*rsa.PublicKey)
	body, err := json.Marshal(map[string]interface{}{
		"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// celledIdentity builds the identity router the way cmd/identity-service does,
// for a process serving cell `serving`.
func celledIdentity(t *testing.T, serving string) (*gin.Engine, string) {
	t.Helper()
	jwks := jwksServer(t)
	cfg := &config.Config{
		Environment:  "production",
		CellID:       serving,
		OAuthIssuer:  "https://issuer.test",
		OAuthJWKSURL: jwks.URL,
	}
	// A non-nil wrapper with a nil pool, as in authzSurfaceService: reaching a
	// query is itself a finding here, and the nil pool makes it a loud one.
	svc := NewService(&database.PostgresDB{}, &database.RedisClient{}, cfg, zap.NewNop())

	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterRoutesForProfile(r, svc, ProfileAll, cell.Guard(cfg.CellID, zap.NewNop()))
	return r, cfg.OAuthIssuer
}

// token mints a signed token for these claims, merged over the minimum the
// middleware requires (sub, iss, exp).
func token(t *testing.T, issuer string, claims jwt.MapClaims) string {
	t.Helper()
	full := jwt.MapClaims{
		"sub": "11111111-1111-1111-1111-111111111111",
		"iss": issuer,
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	for k, v := range claims {
		full[k] = v
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, full).SignedString(signingKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// call drives one request at an ADMINISTRATIVE route -- GET /users, the user
// directory. Admin rather than self-service on purpose: it is the tenant data
// the guard exists to keep a foreign token away from.
func call(t *testing.T, r *gin.Engine, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/identity/users", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAForeignCellsTokenIsRefusedByIdentity(t *testing.T) {
	r, issuer := celledIdentity(t, "us-1")
	w := call(t, r, token(t, issuer, jwt.MapClaims{cell.Claim: "eu-1"}))

	if w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("a token minted in eu-1 presented to us-1 answered %d, want 421.\n"+
			"Either the guard is not mounted, or it is mounted over a context key nothing binds -- "+
			"which is the same thing from the caller's side.", w.Code)
	}
	if got := w.Header().Get(cell.Header); got != "us-1" {
		t.Errorf("%s = %q, want %q. Without it the caller learns that it guessed wrong and nothing "+
			"about what would be right, which leaves retrying here as its only move.", cell.Header, got, "us-1")
	}
}

// The guard has to run before anything that costs a query. The nil pool makes
// that measurable rather than a matter of reading the registration order: if
// PermissionResolver ran first it would reach for PostgreSQL with the roles
// below and this would not be a 421.
func TestTheRefusalCostsNoQuery(t *testing.T) {
	r, issuer := celledIdentity(t, "us-1")
	w := call(t, r, token(t, issuer, jwt.MapClaims{
		cell.Claim: "eu-1",
		"roles":    []interface{}{"admin"},
	}))

	if w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("a misdirected request carrying roles answered %d, want 421; the guard is running "+
			"after the permission resolver", w.Code)
	}
}

// The control that says the guard is not simply refusing everything. 403 is the
// admin gate answering, which is three middlewares past the guard.
func TestTheCellThatOwnsTheTokenIsServed(t *testing.T) {
	r, issuer := celledIdentity(t, "us-1")
	w := call(t, r, token(t, issuer, jwt.MapClaims{cell.Claim: "us-1"}))

	if w.Code == http.StatusMisdirectedRequest {
		t.Fatalf("us-1 refused a token it minted itself")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403 from the admin gate: this request should have travelled the whole "+
			"authenticated chain and been stopped for holding no admin role", w.Code)
	}
}

// A token minted before the claim existed is served, deliberately: requiring it
// the moment CELL_ID is set would fail every token outstanding at that instant.
// internal/common/cell writes down what that costs.
func TestATokenFromBeforeTheClaimIsServed(t *testing.T) {
	r, issuer := celledIdentity(t, "us-1")
	w := call(t, r, token(t, issuer, jwt.MapClaims{}))

	if w.Code == http.StatusMisdirectedRequest {
		t.Fatalf("a token with no cell claim was refused; every token outstanding when an operator " +
			"first sets CELL_ID looks exactly like this one")
	}
}

// Every install today, which is the case that must not change.
func TestAnUncelledInstallServesEverything(t *testing.T) {
	r, issuer := celledIdentity(t, "")
	w := call(t, r, token(t, issuer, jwt.MapClaims{cell.Claim: "eu-1"}))

	if w.Code == http.StatusMisdirectedRequest {
		t.Fatalf("an install with no CELL_ID refused a request; there is no cell here to be wrong about")
	}
	if got := w.Header().Get(cell.Header); got != "" {
		t.Errorf("%s = %q on an uncelled install", cell.Header, got)
	}
}

// The binding the guard depends on, stated on its own so a failure names the
// cause rather than the symptom: if this fails, every 421 above is unreachable.
func TestTheAuthMiddlewareBindsTheMintingCell(t *testing.T) {
	jwks := jwksServer(t)
	cfg := &config.Config{
		Environment:  "production",
		OAuthIssuer:  "https://issuer.test",
		OAuthJWKSURL: jwks.URL,
	}
	svc := NewService(&database.PostgresDB{}, &database.RedisClient{}, cfg, zap.NewNop())

	gin.SetMode(gin.TestMode)
	r := gin.New()
	var bound interface{}
	var present bool
	r.GET("/probe", svc.openIDXAuthMiddleware(), func(c *gin.Context) {
		bound, present = c.Get(cell.Claim)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+token(t, cfg.OAuthIssuer, jwt.MapClaims{cell.Claim: "eu-1"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("probe answered %d; the token did not authenticate: %s", w.Code, w.Body.String())
	}
	if !present {
		t.Fatalf("openIDXAuthMiddleware verified a token carrying %q and left the context key unset. "+
			"cell.Guard reads this key and nothing else, so mounting it would be a guard that can "+
			"never fire.", cell.Claim)
	}
	if bound != "eu-1" {
		t.Errorf("bound %v, want eu-1", bound)
	}
}
