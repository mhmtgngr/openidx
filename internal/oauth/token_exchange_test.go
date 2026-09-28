package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/revocation"
)

// exchangeTestOrg is the organization the exchange tests run in.
const exchangeTestOrg = "55555555-5555-5555-5555-555555555555"

// exchangeContext is a gin context for a request resolved to exchangeTestOrg,
// as TenantResolver leaves it.
func exchangeContext() *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: exchangeTestOrg}))
	return c
}

// mintTestToken signs an access token with the test service's key so
// validateExchangeToken accepts it (same key = same issuer for the unit path).
// It is typed "at+jwt" and bound to exchangeTestOrg unless the claims name
// another organization, as newAccessToken types and binds every bearer this
// package mints.
func mintTestToken(t *testing.T, svc *Service, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}
	if _, ok := claims[middleware.OrgIDClaim]; !ok {
		claims[middleware.OrgIDClaim] = exchangeTestOrg
	}
	if _, ok := claims[middleware.APIAccessClaim]; !ok {
		claims[middleware.APIAccessClaim] = true
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["typ"] = middleware.AccessTokenType
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

	if _, err := ctx.Service.validateExchangeToken(context.Background(), bad); err == nil {
		t.Fatal("expected validation to reject a foreign-signed token")
	}

	// A token signed by our key passes.
	good := mintTestToken(t, ctx.Service, jwt.MapClaims{"sub": "u1", "scope": "read"})
	claims, err := ctx.Service.validateExchangeToken(context.Background(), good)
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
	if _, err := ctx.Service.validateExchangeToken(context.Background(), expired); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestIssueExchangedTokenDelegation(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()
	svc := ctx.Service

	c := exchangeContext()

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
	claims, err := svc.validateExchangeToken(context.Background(), tok)
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
	if claims[middleware.OrgIDClaim] != exchangeTestOrg {
		t.Errorf("expected the token bound to the request's organization, got %v", claims[middleware.OrgIDClaim])
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
	c := exchangeContext()

	client := &OAuthClient{ClientID: "svc-b", AccessTokenLifetime: 600}
	// Subject token already has an act (svc-a acted for alice); svc-b now acts.
	priorAct := map[string]interface{}{"sub": "svc-a"}
	subjectClaims := jwt.MapClaims{"sub": "alice", "scope": "read", "act": priorAct}
	actorClaims := jwt.MapClaims{"sub": "svc-b", "client_id": "svc-b"}

	tok, _, err := svc.issueExchangedToken(c, "alice", "aud", "read", subjectClaims, actorClaims, client)
	if err != nil {
		t.Fatalf("issueExchangedToken: %v", err)
	}
	claims, _ := svc.validateExchangeToken(context.Background(), tok)
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

// An exchanged token is bound to the organization the exchange was requested
// in, and the subject token has to come from that same organization: its roles
// are what the issued token carries. A subject token of another organization,
// or of none, is refused, and there is no token to issue without an
// organization to bind it to.
func TestTokenExchangeIsBoundToTheRequestsOrganization(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()
	svc := ctx.Service

	elsewhere := mintTestToken(t, svc, jwt.MapClaims{"sub": "alice", middleware.OrgIDClaim: "66666666-6666-6666-6666-666666666666"})
	if _, err := svc.validateExchangeToken(exchangeContext().Request.Context(), elsewhere); !errors.Is(err, middleware.ErrWrongOrganization) {
		t.Errorf("a subject token of another organization: err = %v, want ErrWrongOrganization", err)
	}
	unbound := mintTestToken(t, svc, jwt.MapClaims{"sub": "alice", middleware.OrgIDClaim: ""})
	if _, err := svc.validateExchangeToken(exchangeContext().Request.Context(), unbound); !errors.Is(err, middleware.ErrNoOrganization) {
		t.Errorf("a subject token naming no organization: err = %v, want ErrNoOrganization", err)
	}

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	if _, _, err := svc.issueExchangedToken(c, "alice", "aud", "read", jwt.MapClaims{"sub": "alice"}, nil,
		&OAuthClient{ClientID: "svc-a"}); err == nil {
		t.Error("a token was issued with no organization to bind it to")
	}
}

// Whether an exchanged token may call OpenIDX's own APIs follows the client
// that asked for the exchange, and an exchange never grants it from a subject
// token that did not carry it: that would turn a third-party application's
// token into one the APIs accept.
func TestAnExchangedTokenCallsTheAPIOnlyIfItsClientAndItsSubjectMay(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()
	svc := ctx.Service

	allowed, refused := true, false
	for _, tc := range []struct {
		name       string
		client     *bool
		subjectAPI bool
		want       bool
	}{
		{"a client allowed to call the API, exchanging a token that may", &allowed, true, true},
		{"a client not allowed to, exchanging a token that may", &refused, true, false},
		{"a client that says nothing, exchanging a token that may", nil, true, false},
		{"a client allowed to, exchanging a token that may not", &allowed, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &OAuthClient{ClientID: "svc-a", APIAccess: tc.client}
			subject := jwt.MapClaims{"sub": "alice", "scope": "read"}
			if tc.subjectAPI {
				subject[middleware.APIAccessClaim] = true
			}
			tok, _, err := svc.issueExchangedToken(exchangeContext(), "alice", "https://api.example.com", "read", subject, nil, client)
			if err != nil {
				t.Fatalf("issueExchangedToken: %v", err)
			}
			claims, err := svc.validateExchangeToken(orgctx.With(context.Background(), orgctx.Org{ID: exchangeTestOrg}), tok)
			if err != nil {
				t.Fatalf("validate the issued token: %v", err)
			}
			if got := middleware.HasAPIAccess(claims); got != tc.want {
				t.Fatalf("issued token may call the API = %v, want %v", got, tc.want)
			}
		})
	}
}

// An exchanged token lives no longer than its subject token, and dates from
// the subject token's grant: the two halves of "never more than the subject
// token had" that are about time rather than content.
func TestAnExchangedTokenEndsWithItsSubjectAndDatesFromItsGrant(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()
	svc := ctx.Service
	client := &OAuthClient{ClientID: "svc-a", AccessTokenLifetime: 3600}

	iat := time.Now().Add(-time.Minute)
	subject := jwt.MapClaims{
		"sub": "alice", "scope": "read",
		"iat": float64(iat.Unix()), "exp": float64(time.Now().Add(90 * time.Second).Unix()),
		revocation.GrantedAtClaim: float64(iat.UnixMicro()),
	}
	tok, expiresIn, err := svc.issueExchangedToken(exchangeContext(), "alice", "svc-a", "read", subject, nil, client)
	if err != nil {
		t.Fatalf("issueExchangedToken: %v", err)
	}
	if expiresIn > 90 {
		t.Errorf("expires_in %d, beyond the subject token's remaining 90 seconds", expiresIn)
	}
	claims, err := svc.validateExchangeToken(orgctx.With(context.Background(), orgctx.Org{ID: exchangeTestOrg}), tok)
	if err != nil {
		t.Fatalf("validate the issued token: %v", err)
	}
	if exp, _ := claims.GetExpirationTime(); exp == nil || exp.Unix() > int64(subject["exp"].(float64)) {
		t.Errorf("issued exp %v, after the subject token's", exp)
	}
	if got := claims[revocation.GrantedAtClaim]; got != float64(iat.UnixMicro()) {
		t.Errorf("issued %s = %v, want the subject token's %d", revocation.GrantedAtClaim, got, iat.UnixMicro())
	}

	// A subject token with no grant time of its own dates from the start of
	// its iat second, which is how the revocation cutoff reads it.
	delete(subject, revocation.GrantedAtClaim)
	tok, _, err = svc.issueExchangedToken(exchangeContext(), "alice", "svc-a", "read", subject, nil, client)
	if err != nil {
		t.Fatalf("issueExchangedToken: %v", err)
	}
	claims, _ = svc.validateExchangeToken(orgctx.With(context.Background(), orgctx.Org{ID: exchangeTestOrg}), tok)
	if got := claims[revocation.GrantedAtClaim]; got != float64(iat.Unix()*1e6) {
		t.Errorf("issued %s = %v, want the start of the subject token's second %d", revocation.GrantedAtClaim, got, iat.Unix()*1e6)
	}
}

// The audience list an administrator gives a client is checked and stored
// trimmed and without duplicates; nil means "leave it as it is" and empty
// means "none".
func TestTokenExchangeAudienceLists(t *testing.T) {
	list := func(v ...string) *[]string { return &v }
	for _, bad := range []*[]string{list(""), list("  "), list(strings.Repeat("a", maxTokenExchangeAudienceLength+1))} {
		if err := validateTokenExchangeAudiences(bad); !errors.Is(err, ErrInvalidTokenExchangeAudiences) {
			t.Errorf("validate %q: %v, want ErrInvalidTokenExchangeAudiences", *bad, err)
		}
	}
	tooMany := make([]string, maxTokenExchangeAudiences+1)
	for i := range tooMany {
		tooMany[i] = "https://aud.example.test/" + strings.Repeat("x", i)
	}
	if err := validateTokenExchangeAudiences(&tooMany); !errors.Is(err, ErrInvalidTokenExchangeAudiences) {
		t.Errorf("validate %d entries: %v", len(tooMany), err)
	}
	for _, ok := range []*[]string{nil, list(), list("https://payroll.example.test", "svc-b")} {
		if err := validateTokenExchangeAudiences(ok); err != nil {
			t.Errorf("validate %v: %v", ok, err)
		}
	}
	if got := marshalTokenExchangeAudiences(nil); got != nil {
		t.Errorf("nil list stored as %s, want NULL", got)
	}
	if got := string(marshalTokenExchangeAudiences(list())); got != "[]" {
		t.Errorf("empty list stored as %s, want []", got)
	}
	if got := string(marshalTokenExchangeAudiences(list(" svc-b ", "svc-b", "https://payroll.example.test"))); got != `["svc-b","https://payroll.example.test"]` {
		t.Errorf("stored as %s", got)
	}

	client := &OAuthClient{ClientID: "svc-a", TokenExchangeAudiences: list("svc-b")}
	for aud, want := range map[string]bool{"svc-a": true, "svc-b": true, "svc-c": false, "": false} {
		if got := client.mayExchangeFor(aud); got != want {
			t.Errorf("mayExchangeFor(%q) = %v, want %v", aud, got, want)
		}
	}
	if (&OAuthClient{ClientID: "svc-a"}).mayExchangeFor("svc-b") {
		t.Error("a client that lists nothing may exchange for another audience")
	}
}

// A client that can keep a secret is one registered with a secret and not as
// a client that cannot: the dynamic registration's and the seeds' "public",
// and the console's "native".
func TestWhichClientsAreConfidential(t *testing.T) {
	for _, tc := range []struct {
		typ, secret string
		want        bool
	}{
		{"confidential", "s", true},
		{"web", "s", true},
		{"service", "s", true},
		{"confidential", "", false},
		{"public", "s", false},
		{"Public", "s", false},
		{"native", "s", false},
		{"web", "", false},
	} {
		if got := (&OAuthClient{Type: tc.typ, ClientSecret: tc.secret}).isConfidential(); got != tc.want {
			t.Errorf("type %q secret %q: confidential = %v, want %v", tc.typ, tc.secret, got, tc.want)
		}
	}
}
