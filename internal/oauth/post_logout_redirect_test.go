package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"

	"github.com/openidx/openidx/internal/common/validation"
)

// OpenID Connect RP-Initiated Logout 1.0 §2, measured at the handler.
//
// Three things were missing and each is a separate promise to the relying
// party: `state` came back (it did not), `client_id` identified the caller
// (only the id_token_hint's audience did), and "registered" meant the list
// the spec names rather than the origin of some other list.

const plrClientID = "rp-logout"

// plrClient is a relying party whose OAuth callback lives at /callback and
// whose logout landing page is a different path on the same host — the shape
// the registered list exists for.
func plrClient(postLogout ...string) *OAuthClient {
	return &OAuthClient{
		ClientID:               plrClientID,
		RedirectURIs:           []string{"https://rp.example.test/callback"},
		PostLogoutRedirectURIs: postLogout,
	}
}

// logoutRequest drives handleLogout with query parameters and no cookie, so
// the browser-session half is a no-op and what is measured is the redirect.
func logoutRequest(t *testing.T, svc *Service, q url.Values) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/oauth/logout?"+q.Encode(), nil)
	c.Request = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: ssoTestOrg}))
	svc.handleLogout(c)
	return w
}

// §2: "If included in the logout request, the OP MUST pass this value back to
// the RP using the state query parameter." A relying party that tells its own
// logout callback from a forged one by that value could not, before this.
func TestLogoutReturnsTheRelyingPartysState(t *testing.T) {
	svc := newLoginUITestService(t, "", plrClient("https://rp.example.test/signed-out"))

	w := logoutRequest(t, svc, url.Values{
		"client_id":                {plrClientID},
		"post_logout_redirect_uri": {"https://rp.example.test/signed-out"},
		"state":                    {"opaque-value-42"},
	})

	if w.Code != http.StatusFound {
		t.Fatalf("logout answered %d, want 302: %s", w.Code, w.Body.String())
	}
	got, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if got.Query().Get("state") != "opaque-value-42" {
		t.Fatalf("Location = %s, want the request's state back", got)
	}
	if got.Path != "/signed-out" {
		t.Fatalf("Location path = %s, want the registered landing page", got.Path)
	}
}

// The state rides alongside whatever the registered page already carries; it
// does not replace the query the relying party wrote down.
func TestLogoutStateIsAddedToTheRegisteredQueryRatherThanReplacingIt(t *testing.T) {
	const landing = "https://rp.example.test/signed-out?from=idp"
	svc := newLoginUITestService(t, "", plrClient(landing))

	w := logoutRequest(t, svc, url.Values{
		"client_id":                {plrClientID},
		"post_logout_redirect_uri": {landing},
		"state":                    {"s1"},
	})
	got, _ := url.Parse(w.Header().Get("Location"))
	if got.Query().Get("from") != "idp" || got.Query().Get("state") != "s1" {
		t.Fatalf("Location = %s, want both from=idp and state=s1", got)
	}
}

// A logout with no state is byte-for-byte the destination that was
// registered: nothing is appended to a URL the RP may be matching itself.
func TestLogoutWithoutStateRedirectsToTheRegisteredValueUnchanged(t *testing.T) {
	const landing = "https://rp.example.test/signed-out?from=idp"
	svc := newLoginUITestService(t, "", plrClient(landing))

	w := logoutRequest(t, svc, url.Values{
		"client_id":                {plrClientID},
		"post_logout_redirect_uri": {landing},
	})
	if loc := w.Header().Get("Location"); loc != landing {
		t.Fatalf("Location = %q, want the registered value unchanged (%q)", loc, landing)
	}
}

// §2: client_id identifies the RP. Without it being read, a relying party
// that no longer holds the ID token — expired, discarded at sign-out, never
// stored — had no way to be recognised and its registered landing page was
// refused.
func TestLogoutIdentifiesTheRelyingPartyByClientIDWhenNoIDTokenHint(t *testing.T) {
	svc := newLoginUITestService(t, "", plrClient("https://rp.example.test/signed-out"))

	w := logoutRequest(t, svc, url.Values{
		"client_id":                {plrClientID},
		"post_logout_redirect_uri": {"https://rp.example.test/signed-out"},
	})
	if w.Code != http.StatusFound {
		t.Fatalf("logout answered %d, want 302 for a client_id-identified RP: %s", w.Code, w.Body.String())
	}
}

// Naming no client at all still refuses: an unidentified caller has no
// registered list, so there is nothing the redirect could be checked against.
func TestLogoutWithoutAnyClientIdentityRefusesTheRedirect(t *testing.T) {
	svc := newLoginUITestService(t, "", plrClient("https://rp.example.test/signed-out"))

	w := logoutRequest(t, svc, url.Values{
		"post_logout_redirect_uri": {"https://rp.example.test/signed-out"},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("logout answered %d, want 400 when no client is identified", w.Code)
	}
}

// THE POINT OF THE REGISTERED LIST. Both of these are the same origin as the
// client's OAuth callback, so the pre-v199 origin rule said yes to both. Only
// the registered one is a destination now.
func TestARegisteredListIsMatchedExactlyNotByOrigin(t *testing.T) {
	svc := newLoginUITestService(t, "", plrClient("https://rp.example.test/signed-out"))

	allowed := logoutRequest(t, svc, url.Values{
		"client_id":                {plrClientID},
		"post_logout_redirect_uri": {"https://rp.example.test/signed-out"},
	})
	if allowed.Code != http.StatusFound {
		t.Fatalf("the registered page answered %d, want 302", allowed.Code)
	}

	// Any other path on the RP's own host: an open redirector, a
	// user-content page, a half-finished route.
	refused := logoutRequest(t, svc, url.Values{
		"client_id":                {plrClientID},
		"post_logout_redirect_uri": {"https://rp.example.test/go?to=https://evil.example"},
	})
	if refused.Code != http.StatusBadRequest {
		t.Fatalf("an unregistered path on the same host answered %d, want 400", refused.Code)
	}
}

// BACKWARD COMPATIBILITY IS THE OTHER HALF OF THE DECISION. A client that has
// registered nothing keeps the origin rule, because every client in every
// existing install is that client on the upgrade that adds the column.
func TestAClientThatRegisteredNothingKeepsTheOriginRule(t *testing.T) {
	svc := newLoginUITestService(t, "", plrClient())

	w := logoutRequest(t, svc, url.Values{
		"client_id":                {plrClientID},
		"post_logout_redirect_uri": {"https://rp.example.test/signed-out"},
	})
	if w.Code != http.StatusFound {
		t.Fatalf("the origin fallback answered %d, want 302: %s", w.Code, w.Body.String())
	}

	// The fallback is a fallback, not an absence of rules: another host is
	// still refused, which is what PR #82 was for.
	other := logoutRequest(t, svc, url.Values{
		"client_id":                {plrClientID},
		"post_logout_redirect_uri": {"https://evil.example/signed-out"},
	})
	if other.Code != http.StatusBadRequest {
		t.Fatalf("another host answered %d, want 400", other.Code)
	}
}

// A registered list is exhaustive: registering one page does not make a
// sibling page on the same host legal by falling back.
func TestARegisteredListDoesNotFallBackToTheOriginRule(t *testing.T) {
	svc := newLoginUITestService(t, "", plrClient("https://rp.example.test/signed-out"))

	w := logoutRequest(t, svc, url.Values{
		"client_id":                {plrClientID},
		"post_logout_redirect_uri": {"https://rp.example.test/callback"}, // its own OAuth callback
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("an unregistered sibling answered %d, want 400 — a registered list is the whole list", w.Code)
	}
}

// §2: "If both client_id and id_token_hint are present, the OP MUST verify
// that the Client Identifier matches." Resolving the disagreement either way
// would let a caller aim one client's session at another client's page —
// which is exactly the shape here: the hint names a REAL other client, and
// that client has registered the very page the request asks for. Without the
// check the handler redirects; with it, the request is refused.
func TestLogoutRefusesAClientIDThatDisagreesWithTheIDTokenHint(t *testing.T) {
	svc := plrServiceWithDB(t, plrClient("https://rp.example.test/signed-out"))
	hint := mintPLRIDTokenHint(t, svc, plrOtherClientID)

	w := logoutRequest(t, svc, url.Values{
		"client_id":                {plrClientID},
		"id_token_hint":            {hint},
		"post_logout_redirect_uri": {"https://rp.example.test/signed-out"},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a mismatched client_id answered %d, want 400: %s", w.Code, w.Body.String())
	}
}

// Agreement is not a mismatch: the same pair goes through.
func TestLogoutAcceptsAClientIDThatMatchesTheIDTokenHint(t *testing.T) {
	svc := plrServiceWithDB(t, plrClient("https://rp.example.test/signed-out"))
	hint := mintPLRIDTokenHint(t, svc, plrClientID)

	w := logoutRequest(t, svc, url.Values{
		"client_id":                {plrClientID},
		"id_token_hint":            {hint},
		"post_logout_redirect_uri": {"https://rp.example.test/signed-out"},
		"state":                    {"agreed"},
	})
	if w.Code != http.StatusFound {
		t.Fatalf("a matching pair answered %d, want 302: %s", w.Code, w.Body.String())
	}
	got, _ := url.Parse(w.Header().Get("Location"))
	if got.Query().Get("state") != "agreed" {
		t.Fatalf("Location = %s, want the state back", got)
	}
}

// twoClientStore holds both relying parties, which is what makes the
// client_id/audience test measure the rule it names. With a one-client store
// the mismatch case is refused because the OTHER client does not exist — the
// same 400 for a different reason, and removing the rule leaves the test
// green. Here the hint's client is real and has its own registered landing
// page, so without the check the handler would redirect to it.
type twoClientStore struct{ clients map[string]*OAuthClient }

func (f *twoClientStore) GetByClientID(_ context.Context, clientID string) (*OAuthClient, error) {
	if c, ok := f.clients[clientID]; ok {
		return c, nil
	}
	return nil, ErrOAuthClientNotFound
}
func (f *twoClientStore) List(_ context.Context, _, _ int) ([]OAuthClient, int, error) {
	return nil, 0, nil
}
func (f *twoClientStore) Create(_ context.Context, _ *OAuthClient) error           { return nil }
func (f *twoClientStore) Update(_ context.Context, _ string, _ *OAuthClient) error { return nil }
func (f *twoClientStore) Delete(_ context.Context, _ string) error                 { return nil }

const plrOtherClientID = "rp-other"

// plrServiceWithDB is the same in-memory-client service plus the tables the
// revocation half of handleLogout touches, for the two cases that carry a
// valid id_token_hint (a hint names a user, and naming a user is what makes
// the handler revoke).
func plrServiceWithDB(t *testing.T, client *OAuthClient) *Service {
	t.Helper()
	db, cleanup := ssfSetupTestDB(t)
	t.Cleanup(cleanup)
	for _, stmt := range []string{
		`CREATE TABLE sessions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			client_id VARCHAR(255) NOT NULL DEFAULT '',
			expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + interval '1 hour',
			org_id UUID NOT NULL,
			revoked BOOLEAN DEFAULT false,
			revoked_at TIMESTAMPTZ)`,
		`CREATE TABLE oauth_refresh_tokens (
			token VARCHAR(500) PRIMARY KEY,
			client_id VARCHAR(255) NOT NULL,
			user_id UUID NOT NULL,
			session_id UUID,
			expires_at TIMESTAMPTZ NOT NULL,
			org_id UUID NOT NULL)`,
		`CREATE TABLE oauth_clients (
			client_id VARCHAR(255) NOT NULL,
			org_id UUID NOT NULL,
			back_channel_logout_uri VARCHAR(500),
			post_logout_redirect_uris JSONB)`,
	} {
		if _, err := db.Pool.Exec(context.Background(), stmt); err != nil {
			t.Fatalf("schema: %v\n%s", err, stmt)
		}
	}
	svc := newLoginUITestService(t, "", client)
	svc.db = db
	svc.clients = &twoClientStore{clients: map[string]*OAuthClient{
		client.ClientID: client,
		plrOtherClientID: {
			ClientID:               plrOtherClientID,
			RedirectURIs:           []string{"https://other.example.test/callback"},
			PostLogoutRedirectURIs: []string{"https://rp.example.test/signed-out"},
		},
	}}
	return svc
}

// mintPLRIDTokenHint signs an ID token for aud, so the handler's own
// signature check is what accepts it. A forged hint is already covered by
// TestHandleLogout_ForgedIDTokenHintSkipsRevocation; what is measured here is
// the client_id / audience comparison.
func mintPLRIDTokenHint(t *testing.T, svc *Service, aud string) string {
	t.Helper()
	if svc.privateKey == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		svc.privateKey = key
		svc.publicKey = &key.PublicKey
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": svc.issuer,
		"sub": uuid.New().String(),
		"aud": aud,
		"iat": time.Now().Add(-time.Hour).Unix(),
		"exp": time.Now().Add(-time.Minute).Unix(), // expired on purpose: §2 accepts it
	})
	signed, err := tok.SignedString(svc.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestValidatePostLogoutRedirectURIs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		uris  []string
		valid bool
	}{
		{"none registered", nil, true},
		{"https page", []string{"https://rp.example.test/signed-out"}, true},
		{"native scheme", []string{"openidx://signed-out"}, true},
		{"several", []string{"https://a.example/x", "https://b.example/y"}, true},
		{"relative", []string{"/signed-out"}, false},
		{"no host", []string{"https:///signed-out"}, false},
		{"credentials in the URI", []string{"https://user:pw@rp.example.test/x"}, false},
		{"empty string", []string{""}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePostLogoutRedirectURIs(tc.uris)
			if tc.valid && err != nil {
				t.Fatalf("validate(%v) = %v, want nil", tc.uris, err)
			}
			if !tc.valid && err == nil {
				t.Fatalf("validate(%v) = nil, want a refusal", tc.uris)
			}
		})
	}

	long := make([]string, validation.MaxPostLogoutRedirectURIs+1)
	for i := range long {
		long[i] = "https://rp.example.test/x"
	}
	if validatePostLogoutRedirectURIs(long) == nil {
		t.Fatal("a list past the bound must be refused")
	}
}

// An empty list is stored as NULL, because the column's whole job is to tell
// "registered nothing" from "registered something".
func TestMarshalPostLogoutRedirectURIsStoresNothingAsNULL(t *testing.T) {
	if got := marshalPostLogoutRedirectURIs(nil); got != nil {
		t.Fatalf("nil marshalled to %q, want SQL NULL", got)
	}
	if got := marshalPostLogoutRedirectURIs([]string{"  ", ""}); got != nil {
		t.Fatalf("a list of blanks marshalled to %q, want SQL NULL", got)
	}
	if got := marshalPostLogoutRedirectURIs([]string{" https://rp.example.test/x "}); string(got) != `["https://rp.example.test/x"]` {
		t.Fatalf("marshalled to %q, want the trimmed value", got)
	}
}

// The column is only worth having if it survives the round trip the console
// and dynamic registration both make: write, read, change, clear.
func TestClientStoreRoundTripsPostLogoutRedirectURIs(t *testing.T) {
	_, db, _ := bclSetup(t)
	store := NewPostgresOAuthClientStore(db)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: ssoTestOrg})

	client := &OAuthClient{
		ID: uuid.New().String(), ClientID: "plr-store", Name: "A", Type: "confidential",
		RedirectURIs:           []string{"https://a.example/cb"},
		PostLogoutRedirectURIs: []string{"https://a.example/bye", "https://a.example/bye-2"},
	}
	if err := store.Create(ctx, client); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetByClientID(ctx, "plr-store")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.PostLogoutRedirectURIs) != 2 || got.PostLogoutRedirectURIs[0] != "https://a.example/bye" {
		t.Fatalf("read back %v, want both registered pages in order", got.PostLogoutRedirectURIs)
	}

	client.PostLogoutRedirectURIs = []string{"https://a.example/bye-3"}
	if err := store.Update(ctx, "plr-store", client); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.GetByClientID(ctx, "plr-store"); len(got.PostLogoutRedirectURIs) != 1 ||
		got.PostLogoutRedirectURIs[0] != "https://a.example/bye-3" {
		t.Fatalf("update not persisted: %v", got.PostLogoutRedirectURIs)
	}

	// Clearing must persist as "registered nothing", which is what puts the
	// client back on the origin rule rather than leaving it matched against a
	// list it no longer has.
	client.PostLogoutRedirectURIs = nil
	if err := store.Update(ctx, "plr-store", client); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.GetByClientID(ctx, "plr-store"); len(got.PostLogoutRedirectURIs) != 0 {
		t.Fatalf("clearing must persist, got %v", got.PostLogoutRedirectURIs)
	}

	bad := &OAuthClient{
		ID: uuid.New().String(), ClientID: "plr-store-bad", Name: "B", Type: "confidential",
		PostLogoutRedirectURIs: []string{"/relative"},
	}
	if err := store.Create(ctx, bad); err == nil {
		t.Fatal("a relative entry must be refused at registration, not discovered at logout")
	}
}

// Dynamic registration is the other door onto the same field: a client that
// registers itself must be able to register where it may be sent afterwards,
// and get it back.
func TestDCRCarriesPostLogoutRedirectURIs(t *testing.T) {
	svc := &Service{logger: zap.NewNop()}
	client, err := svc.buildClientFromMetadata(&clientMetadata{
		RedirectURIs:           []string{"https://dcr.example/cb"},
		PostLogoutRedirectURIs: []string{"https://dcr.example/bye"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(client.PostLogoutRedirectURIs) != 1 || client.PostLogoutRedirectURIs[0] != "https://dcr.example/bye" {
		t.Fatalf("registration dropped the list: %v", client.PostLogoutRedirectURIs)
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/oauth/register", nil)
	resp := svc.registrationResponse(c, client, "")
	if len(resp.PostLogoutRedirectURIs) != 1 || resp.PostLogoutRedirectURIs[0] != "https://dcr.example/bye" {
		t.Fatalf("the registration response dropped the list: %v", resp.PostLogoutRedirectURIs)
	}

	if _, err := svc.buildClientFromMetadata(&clientMetadata{
		RedirectURIs:           []string{"https://dcr.example/cb"},
		PostLogoutRedirectURIs: []string{"/relative"},
	}); err == nil {
		t.Fatal("registration must refuse an entry that could never be matched")
	}
}
