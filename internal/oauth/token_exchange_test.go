package oauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// mintTestToken signs a token with the test service's key so validateExchangeToken
// accepts it (same key = same issuer for the unit path).
func mintTestToken(t *testing.T, svc *Service, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(svc.privateKey)
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}
	return signed
}

// teClient is an exchange-capable client the stub GetClient returns.
func teFormRequest(form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestNarrowScope(t *testing.T) {
	cases := []struct {
		subject, requested, want string
	}{
		{"a b c", "", "a b c"},  // empty request keeps subject scope
		{"a b c", "a b", "a b"}, // subset
		{"a b c", "a d", "a"},   // requesting unheld scope drops it (no escalation)
		{"a b", "x y", ""},      // nothing in common
		{"read write", "write", "write"},
	}
	for _, tc := range cases {
		if got := narrowScope(tc.subject, tc.requested); got != tc.want {
			t.Errorf("narrowScope(%q,%q)=%q want %q", tc.subject, tc.requested, got, tc.want)
		}
	}
}

func TestValidateExchangeTokenRejectsBadSig(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()

	// A token signed by a different key must fail.
	other := NewTestOIDCContext(t)
	defer other.Cleanup()
	bad := mintTestToken(t, other.Service, jwt.MapClaims{"sub": "u1"})

	if _, err := ctx.Service.validateExchangeToken(bad); err == nil {
		t.Fatal("expected validation to reject a foreign-signed token")
	}

	// A token signed by our key passes.
	good := mintTestToken(t, ctx.Service, jwt.MapClaims{"sub": "u1", "scope": "read"})
	claims, err := ctx.Service.validateExchangeToken(good)
	if err != nil {
		t.Fatalf("expected valid token, got %v", err)
	}
	if claims["sub"] != "u1" {
		t.Errorf("expected sub u1, got %v", claims["sub"])
	}
}

func TestValidateExchangeTokenRejectsExpired(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()
	expired := mintTestToken(t, ctx.Service, jwt.MapClaims{
		"sub": "u1", "exp": time.Now().Add(-time.Hour).Unix(),
	})
	if _, err := ctx.Service.validateExchangeToken(expired); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestIssueExchangedTokenDelegation(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()
	svc := ctx.Service

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	client := &OAuthClient{ClientID: "svc-a", AccessTokenLifetime: 1200}
	subjectClaims := jwt.MapClaims{"sub": "alice", "scope": "read write", "email": "alice@corp.com"}
	actorClaims := jwt.MapClaims{"sub": "svc-a", "client_id": "svc-a"}

	tok, expiresIn, err := svc.issueExchangedToken(c, "alice", "https://api.example.com", "read", subjectClaims, actorClaims, client)
	if err != nil {
		t.Fatalf("issueExchangedToken: %v", err)
	}
	if expiresIn != 1200 {
		t.Errorf("expected 1200s lifetime, got %d", expiresIn)
	}

	// Verify the issued token: subject preserved, audience set, act claim present.
	claims, err := svc.validateExchangeToken(tok)
	if err != nil {
		t.Fatalf("issued token should validate: %v", err)
	}
	if claims["sub"] != "alice" {
		t.Errorf("expected sub alice, got %v", claims["sub"])
	}
	if claims["aud"] != "https://api.example.com" {
		t.Errorf("expected audience, got %v", claims["aud"])
	}
	if claims["scope"] != "read" {
		t.Errorf("expected narrowed scope read, got %v", claims["scope"])
	}
	act, ok := claims["act"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected act claim (delegation), got %v", claims["act"])
	}
	if act["sub"] != "svc-a" {
		t.Errorf("expected act.sub svc-a, got %v", act["sub"])
	}
	// Identity claim carried over from subject.
	if claims["email"] != "alice@corp.com" {
		t.Errorf("expected subject email preserved, got %v", claims["email"])
	}
}

func TestIssueExchangedTokenChainedDelegation(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()
	svc := ctx.Service
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	client := &OAuthClient{ClientID: "svc-b", AccessTokenLifetime: 600}
	// Subject token already has an act (svc-a acted for alice); svc-b now acts.
	priorAct := map[string]interface{}{"sub": "svc-a"}
	subjectClaims := jwt.MapClaims{"sub": "alice", "scope": "read", "act": priorAct}
	actorClaims := jwt.MapClaims{"sub": "svc-b", "client_id": "svc-b"}

	tok, _, err := svc.issueExchangedToken(c, "alice", "aud", "read", subjectClaims, actorClaims, client)
	if err != nil {
		t.Fatalf("issueExchangedToken: %v", err)
	}
	claims, _ := svc.validateExchangeToken(tok)
	act, _ := claims["act"].(map[string]interface{})
	if act["sub"] != "svc-b" {
		t.Fatalf("expected outer act svc-b, got %v", act["sub"])
	}
	nested, ok := act["act"].(map[string]interface{})
	if !ok || nested["sub"] != "svc-a" {
		t.Errorf("expected nested prior act svc-a, got %v", act["act"])
	}
}

func TestHandleTokenExchangeMissingSubject(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = teFormRequest(url.Values{"grant_type": {grantTypeTokenExchange}})

	ctx.Service.handleTokenExchangeGrant(c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing subject_token, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid_request") {
		t.Errorf("expected invalid_request, got %s", w.Body.String())
	}
}

func TestSupportedTokenType(t *testing.T) {
	if !isSupportedTokenType(tokenTypeAccessToken) || !isSupportedTokenType(tokenTypeJWT) {
		t.Error("expected access_token and jwt token types supported")
	}
	if isSupportedTokenType("urn:ietf:params:oauth:token-type:saml2") {
		t.Error("saml2 token type should not be supported")
	}
}
