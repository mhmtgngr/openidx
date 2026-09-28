package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/revocation"
)

// exchangeCall is one token-exchange request against the route table.
type exchangeCall struct {
	client, secret string
	basic          bool // present the credentials as HTTP Basic instead of the form
	subject, actor string
	audience       string
	resource       string
	scope          string
	slug           string // the organization the request resolves to
}

func (h *tokenHarness) exchange(api *gin.Engine, x exchangeCall) (int, map[string]interface{}) {
	h.t.Helper()
	form := url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {x.subject},
		"subject_token_type": {tokenTypeAccessToken},
	}
	if x.actor != "" {
		form.Set("actor_token", x.actor)
		form.Set("actor_token_type", tokenTypeAccessToken)
	}
	for k, v := range map[string]string{"audience": x.audience, "resource": x.resource, "scope": x.scope} {
		if v != "" {
			form.Set(k, v)
		}
	}
	header := []string{"X-Org-Slug", x.slug}
	if x.basic {
		header = append(header, "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(x.client+":"+x.secret)))
	} else {
		form.Set("client_id", x.client)
		if x.secret != "" {
			form.Set("client_secret", x.secret)
		}
	}
	w := serve(api, http.MethodPost, "/oauth/token", formType, form.Encode(), header...)
	var body map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

// exchangeClient registers an application in org for the token-exchange grant.
func (h *tokenHarness) exchangeClient(org orgctx.Org, name, clientType, secret string, grantTypes, audiences []string, apiAccess bool) string {
	h.t.Helper()
	clientID := name + "-" + org.ID[:8] + "-" + h.suffix
	grants, _ := json.Marshal(grantTypes)
	var auds interface{}
	if audiences != nil {
		b, _ := json.Marshal(audiences)
		auds = string(b)
	}
	var sec interface{}
	if secret != "" {
		sec = secret
	}
	h.exec(`INSERT INTO oauth_clients (client_id, client_secret, name, type, grant_types, token_exchange_audiences, api_access, org_id)
		VALUES ($1, $2, $1, $3, $4::jsonb, $5::jsonb, $6, $7::uuid)`,
		clientID, sec, clientType, string(grants), auds, apiAccess, org.ID)
	return clientID
}

// TOKEN EXCHANGE NEEDS A CONFIDENTIAL CLIENT REGISTERED FOR IT.
//
// RFC 8693's exchange mints a user's token -- their subject, roles and groups --
// from any access token of theirs the caller holds. It used to authenticate a
// public client by its client_id, which is no secret, and any client whose type
// was not the literal "confidential" -- the console creates web, native and
// service clients -- without a secret at all. Driven through RegisterRoutes
// behind the tenant resolver, as cmd/oauth-service serves /oauth/token, with a
// subject token minted by GenerateJWT from database rows:
//
//   - a public client, with or without a made-up secret, a console "native"
//     client with its secret, a console "web" client without its secret or with
//     a wrong one, and a confidential client with a wrong secret are refused
//     with 401 invalid_client; credentials sent by two methods at once are 400;
//     a confidential client not registered for the grant is 400
//     unauthorized_client -- and none of them is issued a token;
//   - a confidential client registered for the grant, and a console "web"
//     client with its secret, are issued one, by form and by HTTP Basic.
func TestTokenExchangeNeedsAConfidentialClientRegisteredForIt(t *testing.T) {
	h := newTokenHarness(t)
	orgA := h.seedOrg("te-auth")
	api := h.oauthRouteTable(nil)
	alice := h.seedUser(orgA.ID, "te-auth-alice", "admin")
	subject := h.tokenFor(orgA, alice, h.registerClient(orgA, "te-auth-app", false))
	exchangeOnly := []string{grantTypeTokenExchange}

	public := h.exchangeClient(orgA, "te-public", "public", "", exchangeOnly, nil, false)
	native := h.exchangeClient(orgA, "te-native", "native", "native-secret", exchangeOnly, nil, false)
	web := h.exchangeClient(orgA, "te-web", "web", "web-secret", exchangeOnly, nil, false)
	confidential := h.exchangeClient(orgA, "te-conf", "confidential", "conf-secret", exchangeOnly, nil, false)
	unregistered := h.exchangeClient(orgA, "te-unreg", "confidential", "unreg-secret", []string{"client_credentials"}, nil, false)

	for _, tc := range []struct {
		name  string
		call  exchangeCall
		code  int
		error string
	}{
		{"a public client naming itself", exchangeCall{client: public}, http.StatusUnauthorized, ErrorInvalidClient},
		{"a public client with a made-up secret", exchangeCall{client: public, secret: "guess"}, http.StatusUnauthorized, ErrorInvalidClient},
		{"a public client over Basic", exchangeCall{client: public, secret: "guess", basic: true}, http.StatusUnauthorized, ErrorInvalidClient},
		{"a native client with its own secret", exchangeCall{client: native, secret: "native-secret"}, http.StatusUnauthorized, ErrorInvalidClient},
		{"a web client without its secret", exchangeCall{client: web}, http.StatusUnauthorized, ErrorInvalidClient},
		{"a web client with a wrong secret", exchangeCall{client: web, secret: "wrong"}, http.StatusUnauthorized, ErrorInvalidClient},
		{"a confidential client with a wrong secret", exchangeCall{client: confidential, secret: "wrong"}, http.StatusUnauthorized, ErrorInvalidClient},
		{"a client that does not exist", exchangeCall{client: "te-ghost", secret: "x"}, http.StatusUnauthorized, ErrorInvalidClient},
		{"a confidential client not registered for the grant", exchangeCall{client: unregistered, secret: "unreg-secret"}, http.StatusBadRequest, ErrorUnauthorizedClient},
		{"a confidential client with its secret", exchangeCall{client: confidential, secret: "conf-secret"}, http.StatusOK, ""},
		{"a confidential client with its secret over Basic", exchangeCall{client: confidential, secret: "conf-secret", basic: true}, http.StatusOK, ""},
		{"a web client with its secret", exchangeCall{client: web, secret: "web-secret"}, http.StatusOK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.call.subject, tc.call.slug = subject, orgA.Slug
			code, body := h.exchange(api, tc.call)
			if code != tc.code {
				t.Fatalf("status %d (%v), want %d", code, body, tc.code)
			}
			if tc.error != "" {
				if body["error"] != tc.error {
					t.Errorf("error %v, want %s", body["error"], tc.error)
				}
				if body["access_token"] != nil {
					t.Errorf("a refused exchange carried a token: %v", body)
				}
				return
			}
			tok, _ := body["access_token"].(string)
			if got := claimsOf(t, tok)["sub"]; got != alice {
				t.Errorf("issued token's subject %v, want %s", got, alice)
			}
		})
	}

	// Both client authentication methods at once is refused before the client
	// is looked up (RFC 6749 §2.3.1).
	form := url.Values{"grant_type": {grantTypeTokenExchange}, "subject_token": {subject}, "client_secret": {"conf-secret"}}
	w := serve(api, http.MethodPost, "/oauth/token", formType, form.Encode(), "X-Org-Slug", orgA.Slug,
		"Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(confidential+":conf-secret")))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), ErrorInvalidRequest) {
		t.Errorf("two authentication methods: %d %s, want 400 invalid_request", w.Code, w.Body.String())
	}
}

// AN EXCHANGE ISSUES ONLY AUDIENCES THE CLIENT IS ALLOWED.
//
// The audience used to be whatever the request named in audience or resource,
// so a client could turn a user's token for one application into a token for
// any other. It is now the client itself, or one of the audiences an
// administrator listed for it (token_exchange_audiences); anything else --
// another application's client id, the subject token's own application, an
// unlisted URI, or two different targets in one request -- is 400
// invalid_target and issues nothing.
func TestTokenExchangeIssuesOnlyAudiencesTheClientIsAllowed(t *testing.T) {
	h := newTokenHarness(t)
	orgA := h.seedOrg("te-aud")
	api := h.oauthRouteTable(nil)
	alice := h.seedUser(orgA.ID, "te-aud-alice")
	app := h.registerClient(orgA, "te-aud-app", false)
	subject := h.tokenFor(orgA, alice, app)
	const payroll = "https://payroll.example.test"
	listed := h.exchangeClient(orgA, "te-listed", "confidential", "listed-secret",
		[]string{grantTypeTokenExchange}, []string{payroll}, false)
	unlisted := h.exchangeClient(orgA, "te-unlisted", "service", "unlisted-secret",
		[]string{grantTypeTokenExchange}, nil, false)

	for _, tc := range []struct {
		name   string
		call   exchangeCall
		code   int
		wanted string // the issued token's audience
	}{
		{"no audience: the client itself", exchangeCall{client: listed, secret: "listed-secret"}, http.StatusOK, listed},
		{"the client itself, by name", exchangeCall{client: listed, secret: "listed-secret", audience: listed}, http.StatusOK, listed},
		{"a listed audience", exchangeCall{client: listed, secret: "listed-secret", audience: payroll}, http.StatusOK, payroll},
		{"a listed audience as resource", exchangeCall{client: listed, secret: "listed-secret", resource: payroll}, http.StatusOK, payroll},
		{"the same target as audience and resource", exchangeCall{client: listed, secret: "listed-secret", audience: payroll, resource: payroll}, http.StatusOK, payroll},
		{"an unlisted URI", exchangeCall{client: listed, secret: "listed-secret", audience: "https://elsewhere.example.test"}, http.StatusBadRequest, ""},
		{"the subject token's own application", exchangeCall{client: listed, secret: "listed-secret", audience: app}, http.StatusBadRequest, ""},
		{"another exchange client", exchangeCall{client: listed, secret: "listed-secret", audience: unlisted}, http.StatusBadRequest, ""},
		{"two different targets", exchangeCall{client: listed, secret: "listed-secret", audience: payroll, resource: listed}, http.StatusBadRequest, ""},
		{"a client that lists nothing, for another audience", exchangeCall{client: unlisted, secret: "unlisted-secret", audience: payroll}, http.StatusBadRequest, ""},
		{"a client that lists nothing, for itself", exchangeCall{client: unlisted, secret: "unlisted-secret"}, http.StatusOK, unlisted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.call.subject, tc.call.slug = subject, orgA.Slug
			code, body := h.exchange(api, tc.call)
			if code != tc.code {
				t.Fatalf("status %d (%v), want %d", code, body, tc.code)
			}
			if tc.code != http.StatusOK {
				if body["error"] != "invalid_target" || body["access_token"] != nil {
					t.Errorf("refused with %v, want invalid_target and no token", body)
				}
				return
			}
			tok, _ := body["access_token"].(string)
			if got := claimsOf(t, tok)["aud"]; got != tc.wanted {
				t.Errorf("issued audience %v, want %s", got, tc.wanted)
			}
		})
	}
}

// THE ISSUED TOKEN NEVER CARRIES MORE THAN ITS SUBJECT TOKEN.
//
// Scope, organization and roles already followed the subject token. Its life
// did not: every exchange minted the client's full access-token lifetime from
// now, and an exchanged token is an access token that can be exchanged again,
// so a user's token could be kept alive forever. Nor did its revocation: a
// token revoked by /oauth/revoke, a sign-out or a sign-out everywhere was
// exchanged for a fresh one that nothing had revoked. Here:
//
//   - the issued token has the subject's subject, roles and organization, the
//     part of the requested scope the subject holds, no OpenIDX API access
//     unless both the subject token and the client had it, and expires no
//     later than the subject token -- also when it is exchanged again;
//   - a subject token of another organization is refused, in either
//     organization, and so is an ID token;
//   - a subject or actor token revoked on its own, or by the user's cutoff,
//     is refused and nothing is issued;
//   - the issued token dates from its subject token's grant, so a cutoff
//     between the two, which revokes the subject token, revokes it too.
func TestAnExchangedTokenNeverCarriesMoreThanItsSubjectToken(t *testing.T) {
	h := newTokenHarness(t)
	ctx := context.Background()
	orgA, orgB := h.seedOrg("te-more-a"), h.seedOrg("te-more-b")
	api := h.oauthRouteTable(nil)
	alice := h.seedUser(orgA.ID, "te-more-alice", "admin", "auditor")
	carol := h.seedUser(orgA.ID, "te-more-carol")
	bob := h.seedUser(orgB.ID, "te-more-bob", "admin")
	exchangeOnly := []string{grantTypeTokenExchange}
	client := h.exchangeClient(orgA, "te-more", "confidential", "more-secret", exchangeOnly, nil, false)
	apiClient := h.exchangeClient(orgA, "te-more-api", "confidential", "api-secret", exchangeOnly, nil, true)
	clientB := h.exchangeClient(orgB, "te-more-b", "confidential", "b-secret", exchangeOnly, nil, false)
	consoleA := h.consoleClient(orgA) // allowed to call the API
	subject := h.tokenFor(orgA, alice, consoleA)
	subjectClaims := claimsOf(t, subject)

	call := exchangeCall{client: client, secret: "more-secret", subject: subject, slug: orgA.Slug, scope: "openid email payroll:write"}
	code, body := h.exchange(api, call)
	if code != http.StatusOK {
		t.Fatalf("exchange: %d %v", code, body)
	}
	issued := claimsOf(t, body["access_token"].(string))
	if issued["sub"] != alice || issued[middleware.OrgIDClaim] != orgA.ID {
		t.Errorf("issued sub %v org %v, want %s in %s", issued["sub"], issued[middleware.OrgIDClaim], alice, orgA.ID)
	}
	if issued["scope"] != "openid email" || body["scope"] != "openid email" {
		t.Errorf("issued scope %v (answer %v), want the requested part the subject holds: openid email", issued["scope"], body["scope"])
	}
	if roles, _ := json.Marshal(issued["roles"]); string(roles) != mustJSON(subjectClaims["roles"]) {
		t.Errorf("issued roles %s, want the subject token's %s", roles, mustJSON(subjectClaims["roles"]))
	}
	if middleware.HasAPIAccess(issued) {
		t.Error("a client without API access was issued a token that may call the API")
	}
	subjectExp, _ := subjectClaims.GetExpirationTime()
	if exp, _ := issued.GetExpirationTime(); exp == nil || exp.After(subjectExp.Time) {
		t.Errorf("issued token expires %v, after its subject token (%v)", exp, subjectExp)
	}
	if in, _ := body["expires_in"].(float64); in <= 0 || in > 300 {
		t.Errorf("expires_in %v, want no more than the subject token's 300 seconds", body["expires_in"])
	}
	if got, want := issued[revocation.GrantedAtClaim], float64(tokenIssuedAt(subjectClaims).EarliestMicros()); got != want {
		t.Errorf("issued %s = %v, want the subject token's %v", revocation.GrantedAtClaim, got, want)
	}

	// Exchanged again, it still ends when the first subject token does.
	code, body = h.exchange(api, exchangeCall{client: client, secret: "more-secret", subject: body["access_token"].(string), slug: orgA.Slug})
	if code != http.StatusOK {
		t.Fatalf("second exchange: %d %v", code, body)
	}
	if exp, _ := claimsOf(t, body["access_token"].(string)).GetExpirationTime(); exp == nil || exp.After(subjectExp.Time) {
		t.Errorf("a re-exchanged token expires %v, after the original subject token (%v)", exp, subjectExp)
	}

	// OpenIDX API access: only when the client and the subject token both had it.
	code, body = h.exchange(api, exchangeCall{client: apiClient, secret: "api-secret", subject: subject, slug: orgA.Slug})
	if code != http.StatusOK || !middleware.HasAPIAccess(claimsOf(t, body["access_token"].(string))) {
		t.Errorf("a client with API access, exchanging a token with it: %d, API access %v", code, body)
	}
	thirdParty := h.tokenFor(orgA, alice, h.registerClient(orgA, "te-more-3p", false))
	code, body = h.exchange(api, exchangeCall{client: apiClient, secret: "api-secret", subject: thirdParty, slug: orgA.Slug})
	if code != http.StatusOK || middleware.HasAPIAccess(claimsOf(t, body["access_token"].(string))) {
		t.Errorf("a client with API access, exchanging a token without it: %d, the issued token may call the API", code)
	}

	// Another organization's subject token: refused in A, and B's client in B
	// cannot use A's token either.
	for _, tc := range []exchangeCall{
		{client: client, secret: "more-secret", subject: h.tokenFor(orgB, bob, h.consoleClient(orgB)), slug: orgA.Slug},
		{client: clientB, secret: "b-secret", subject: subject, slug: orgB.Slug},
		{client: client, secret: "more-secret", subject: h.idToken(orgA, alice), slug: orgA.Slug},
	} {
		if code, body := h.exchange(api, tc); code != http.StatusBadRequest || body["error"] != ErrorInvalidGrant {
			t.Errorf("a subject token of another organization, or an ID token: %d %v, want 400 invalid_grant", code, body)
		}
	}

	// A subject or actor token revoked on its own. Each is minted for a client
	// of its own: two tokens minted with the same claims in the same second
	// are the same string, and revoking one would revoke the other.
	revokedSubject := h.tokenFor(orgA, alice, h.registerClient(orgA, "te-more-revoked", false))
	if err := h.issuer.MarkAccessTokenRevoked(ctx, revokedSubject, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	actor := h.tokenFor(orgA, carol, client)
	revokedActor := h.tokenFor(orgA, carol, apiClient)
	if err := h.issuer.MarkAccessTokenRevoked(ctx, revokedActor, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]exchangeCall{
		"a revoked subject token": {client: client, secret: "more-secret", subject: revokedSubject, slug: orgA.Slug},
		"a revoked actor token":   {client: client, secret: "more-secret", subject: subject, actor: revokedActor, slug: orgA.Slug},
	} {
		if code, body := h.exchange(api, tc); code != http.StatusBadRequest || body["error"] != ErrorInvalidGrant || body["access_token"] != nil {
			t.Errorf("%s: %d %v, want 400 invalid_grant and no token", name, code, body)
		}
	}
	// A live actor is recorded in act.
	code, body = h.exchange(api, exchangeCall{client: client, secret: "more-secret", subject: subject, actor: actor, slug: orgA.Slug})
	if code != http.StatusOK {
		t.Fatalf("delegation: %d %v", code, body)
	}
	if act, _ := claimsOf(t, body["access_token"].(string))["act"].(map[string]interface{}); act["sub"] != carol {
		t.Errorf("act %v, want carol", act)
	}

	// The user's cutoff. A token minted in one second and exchanged in a later
	// one; a cutoff written between them revokes the subject token, and the
	// exchanged token with it, although it was minted after the cutoff.
	early := h.tokenFor(orgA, alice, consoleA)
	earlyAt := tokenIssuedAt(claimsOf(t, early))
	for time.Now().Unix() <= earlyAt.Seconds {
		time.Sleep(50 * time.Millisecond)
	}
	code, body = h.exchange(api, exchangeCall{client: client, secret: "more-secret", subject: early, slug: orgA.Slug})
	if code != http.StatusOK {
		t.Fatalf("exchange of the early token: %d %v", code, body)
	}
	exchanged := body["access_token"].(string)
	exchangedClaims := claimsOf(t, exchanged)
	if iat := tokenIssuedAt(exchangedClaims).Seconds; iat <= earlyAt.Seconds {
		t.Fatalf("the exchange was minted in the subject token's second (%d); the test needs a later one", iat)
	}
	cutoff := time.UnixMicro(earlyAt.EarliestMicros()).Add(500 * time.Millisecond)
	if err := h.issuer.redis.RevocationDB().Set(ctx, revocation.UserTokensRevokedAtKey(alice),
		revocation.MarkerValue(cutoff), revocation.MarkerTTL).Err(); err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{"the subject token": early, "the token exchanged from it": exchanged} {
		c := claimsOf(t, tok)
		if revoked, err := h.issuer.IsAccessTokenRevoked(ctx, tok, alice, tokenIssuedAt(c)); err != nil || !revoked {
			t.Errorf("%s is not revoked by a cutoff after its subject token's grant (%v)", name, err)
		}
	}
	if code, body := h.exchange(api, exchangeCall{client: client, secret: "more-secret", subject: early, slug: orgA.Slug}); code != http.StatusBadRequest || body["error"] != ErrorInvalidGrant {
		t.Errorf("a subject token under the user's cutoff: %d %v, want 400 invalid_grant", code, body)
	}
	// A token minted after the cutoff still exchanges.
	if code, body := h.exchange(api, exchangeCall{client: client, secret: "more-secret", subject: h.tokenFor(orgA, alice, consoleA), slug: orgA.Slug}); code != http.StatusOK {
		t.Errorf("a token minted after the cutoff: %d %v, want 200", code, body)
	}
}

// Dynamic registration refuses a public client for the grant it could never
// use, and registers the confidential one. The request names no organization,
// so it lands in the default one.
func TestDynamicRegistrationRefusesAPublicTokenExchangeClient(t *testing.T) {
	h := newTokenHarness(t)
	h.issuer.dcrInitialAccessToken = "iat-" + h.suffix
	api := h.oauthRouteTable(nil)
	register := func(authMethod string) int {
		body := `{"client_name":"agent","grant_types":["` + grantTypeTokenExchange + `"],"token_endpoint_auth_method":"` + authMethod + `"}`
		return serve(api, http.MethodPost, "/oauth/register", "application/json", body,
			"Authorization", "Bearer "+h.issuer.dcrInitialAccessToken).Code
	}
	if code := register("none"); code != http.StatusBadRequest {
		t.Errorf("a public client for token exchange: %d, want 400", code)
	}
	if code := register("client_secret_basic"); code != http.StatusCreated {
		t.Errorf("a confidential client for token exchange: %d, want 201", code)
	}
}

// The management API carries the audience list, and a write that leaves it out
// leaves it alone.
func TestTheClientAPISetsTheExchangeAudiences(t *testing.T) {
	h := newTokenHarness(t)
	org := h.seedOrg("te-mgmt")
	api := h.oauthRouteTable(nil)
	admin := h.accessToken(org, h.seedUser(org.ID, "te-mgmt-admin", "admin"))
	send := func(method, path, body string) (int, map[string]interface{}) {
		w := serve(api, method, path, "application/json", body, "Authorization", "Bearer "+admin, "X-Org-Slug", org.Slug)
		var out map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	code, created := send(http.MethodPost, "/api/v1/oauth/clients",
		`{"name":"agent","type":"service","grant_types":["`+grantTypeTokenExchange+`"],"token_exchange_audiences":["https://payroll.example.test"]}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, created)
	}
	id, _ := created["client_id"].(string)
	stored := func() string {
		return h.scalar(`SELECT COALESCE(token_exchange_audiences::text, '<null>') FROM oauth_clients WHERE client_id = $1`, id)
	}
	if got := stored(); got != `["https://payroll.example.test"]` {
		t.Fatalf("stored audiences %s", got)
	}
	if code, _ := send(http.MethodPut, "/api/v1/oauth/clients/"+id, `{"name":"agent renamed","type":"service","grant_types":["`+grantTypeTokenExchange+`"]}`); code != http.StatusOK {
		t.Fatalf("update without the list: %d", code)
	}
	if got := stored(); got != `["https://payroll.example.test"]` {
		t.Errorf("an update that left the list out changed it: %s", got)
	}
	if code, got := send(http.MethodGet, "/api/v1/oauth/clients/"+id, ""); code != http.StatusOK || mustJSON(got["token_exchange_audiences"]) != `["https://payroll.example.test"]` {
		t.Errorf("read back: %d %v", code, got["token_exchange_audiences"])
	}
	if code, _ := send(http.MethodPut, "/api/v1/oauth/clients/"+id, `{"name":"agent","type":"service","token_exchange_audiences":[]}`); code != http.StatusOK {
		t.Fatalf("update clearing the list: %d", code)
	}
	if got := stored(); got != `[]` {
		t.Errorf("an update clearing the list left %s", got)
	}
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}
