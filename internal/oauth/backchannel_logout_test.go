package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The discovery document has said backchannel_logout_supported: true since it
// was written, oauth_clients has carried back_channel_logout_uri since v63,
// and no logout token was ever sent. These tests, against a real PostgreSQL
// and a real HTTP receiver, pin the capability the advertisement promises.

// receivedLogout is one logout token a fake relying party received.
type receivedLogout struct {
	path  string
	token string
}

// relyingParty is an httptest server standing in for an RP's
// back_channel_logout_uri. It records every token it is POSTed.
type relyingParty struct {
	srv    *httptest.Server
	mu     sync.Mutex
	got    []receivedLogout
	status int
}

func newRelyingParty(t *testing.T, status int) *relyingParty {
	t.Helper()
	rp := &relyingParty{status: status}
	rp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		rp.mu.Lock()
		rp.got = append(rp.got, receivedLogout{path: r.URL.Path, token: r.FormValue("logout_token")})
		rp.mu.Unlock()
		w.WriteHeader(rp.status)
	}))
	t.Cleanup(rp.srv.Close)
	return rp
}

func (rp *relyingParty) tokens() []receivedLogout {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	out := make([]receivedLogout, len(rp.got))
	copy(out, rp.got)
	return out
}

// outcomeBox collects the observer's per-session reports. Sessions are
// announced concurrently, so a report may arrive before the test asks for
// it; a channel that dropped non-matching reports lost exactly those.
type outcomeBox struct {
	mu sync.Mutex
	m  map[string][2]int
}

func (o *outcomeBox) record(sessionID string, delivered, failed int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.m[sessionID] = [2]int{delivered, failed}
}

func (o *outcomeBox) get(sessionID string) ([2]int, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	v, ok := o.m[sessionID]
	return v, ok
}

// bclSetup builds the tables the fan-out reads and a service with a signing
// key and an observer that records each session's outcome.
func bclSetup(t *testing.T) (*Service, *database.PostgresDB, *outcomeBox) {
	t.Helper()
	db, cleanup := ssfSetupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	for _, stmt := range []string{
		`CREATE TABLE sessions (
			id UUID PRIMARY KEY,
			user_id UUID NOT NULL,
			client_id VARCHAR(255) NOT NULL DEFAULT '',
			ip_address VARCHAR(45),
			user_agent TEXT,
			started_at TIMESTAMPTZ DEFAULT NOW(),
			last_seen_at TIMESTAMPTZ DEFAULT NOW(),
			expires_at TIMESTAMPTZ NOT NULL,
			org_id UUID NOT NULL,
			revoked BOOLEAN DEFAULT false,
			revoked_at TIMESTAMPTZ,
			auth_methods TEXT[]
		)`,
		`CREATE TABLE oauth_clients (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			client_id VARCHAR(255) NOT NULL,
			client_secret VARCHAR(255),
			name VARCHAR(255) NOT NULL DEFAULT 'c',
			description TEXT,
			type VARCHAR(50) NOT NULL DEFAULT 'confidential',
			redirect_uris JSONB,
			grant_types JSONB,
			response_types JSONB,
			scopes JSONB,
			logo_uri VARCHAR(500),
			policy_uri VARCHAR(500),
			tos_uri VARCHAR(500),
			pkce_required BOOLEAN DEFAULT false,
			allow_refresh_token BOOLEAN DEFAULT true,
			access_token_lifetime INTEGER DEFAULT 3600,
			refresh_token_lifetime INTEGER DEFAULT 86400,
			refresh_token_max_lifetime INTEGER,
			back_channel_logout_uri VARCHAR(500),
			post_logout_redirect_uris JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW(),
			org_id UUID NOT NULL,
			UNIQUE (client_id, org_id)
		)`,
		`CREATE TABLE oauth_refresh_tokens (
			token VARCHAR(500) PRIMARY KEY,
			client_id VARCHAR(255) NOT NULL,
			user_id UUID NOT NULL,
			scope TEXT,
			session_id UUID,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			org_id UUID NOT NULL
		)`,
	} {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v\n%s", err, stmt)
		}
	}
	svc := newLoginUITestService(t, "", ssoTestClient())
	svc.db = db
	svc.config = &config.Config{ABACEnforce: "off"}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	svc.privateKey = key
	outcomes := &outcomeBox{m: map[string][2]int{}}
	svc.backchannelObserver = outcomes.record
	return svc, db, outcomes
}

// registerRP inserts an oauth_clients row for clientID in org with the URI.
func registerRP(t *testing.T, db *database.PostgresDB, org, clientID, uri string) {
	t.Helper()
	var u interface{}
	if uri != "" {
		u = uri
	}
	if _, err := db.Pool.Exec(context.Background(),
		`INSERT INTO oauth_clients (client_id, org_id, back_channel_logout_uri) VALUES ($1, $2, $3)`,
		clientID, org, u); err != nil {
		t.Fatal(err)
	}
}

// liveSession inserts a live session for user created through clientID.
func liveSession(t *testing.T, db *database.PostgresDB, org, userID, clientID string) string {
	t.Helper()
	id := uuid.New().String()
	if _, err := db.Pool.Exec(context.Background(),
		`INSERT INTO sessions (id, user_id, client_id, expires_at, org_id) VALUES ($1, $2, $3, NOW() + interval '1 hour', $4)`,
		id, userID, clientID, org); err != nil {
		t.Fatal(err)
	}
	return id
}

func bindRefreshToken(t *testing.T, db *database.PostgresDB, org, userID, clientID, sessionID string) {
	t.Helper()
	if _, err := db.Pool.Exec(context.Background(),
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, session_id, expires_at, org_id)
		 VALUES ($1, $2, $3, $4, NOW() + interval '1 day', $5)`,
		GenerateRandomToken(16), clientID, userID, sessionID, org); err != nil {
		t.Fatal(err)
	}
}

// awaitOutcome waits for the observer's report for sessionID.
func awaitOutcome(t *testing.T, outcomes *outcomeBox, sessionID string) (delivered, failed int) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if v, ok := outcomes.get(sessionID); ok {
			return v[0], v[1]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no back-channel outcome for session %s", sessionID)
	return 0, 0
}

// parseLogoutToken verifies the token with the service's key and returns
// its header and claims.
func parseLogoutToken(t *testing.T, svc *Service, raw string) (map[string]interface{}, jwt.MapClaims) {
	t.Helper()
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(raw, claims, svc.verificationKeyfunc, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !tok.Valid {
		t.Fatalf("logout token does not verify: %v", err)
	}
	return tok.Header, claims
}

func TestLogoutTokenIsShapedPerBackChannelLogout10(t *testing.T) {
	svc, db, outcomes := bclSetup(t)
	rp := newRelyingParty(t, http.StatusOK)
	userID := uuid.New().String()
	registerRP(t, db, ssoTestOrg, "rp-a", rp.srv.URL+"/bcl")
	sid := liveSession(t, db, ssoTestOrg, userID, "rp-a")

	if err := svc.revokeSessionWithRedis(context.Background(), sid); err != nil {
		t.Fatal(err)
	}
	if d, f := awaitOutcome(t, outcomes, sid); d != 1 || f != 0 {
		t.Fatalf("delivered=%d failed=%d, want 1/0", d, f)
	}
	got := rp.tokens()
	if len(got) != 1 || got[0].path != "/bcl" {
		t.Fatalf("relying party received %v, want one token at /bcl", got)
	}
	header, claims := parseLogoutToken(t, svc, got[0].token)
	if header["typ"] != logoutTokenType || header["kid"] == "" {
		t.Fatalf("header=%v: want typ=logout+jwt and a kid", header)
	}
	if claims["iss"] != svc.issuer || claims["aud"] != "rp-a" || claims["sub"] != userID || claims["sid"] != sid {
		t.Fatalf("claims=%v", claims)
	}
	events, _ := claims["events"].(map[string]interface{})
	if _, ok := events[backchannelLogoutEvent]; !ok {
		t.Fatalf("events claim lacks %s: %v", backchannelLogoutEvent, claims["events"])
	}
	if jti, _ := claims["jti"].(string); jti == "" {
		t.Fatal("jti missing")
	}
	if _, has := claims["nonce"]; has {
		t.Fatal("a logout token MUST NOT carry a nonce (§2.4)")
	}
	iat, exp := claims["iat"].(float64), claims["exp"].(float64)
	if exp-iat != logoutTokenTTL.Seconds() {
		t.Fatalf("exp-iat=%v, want %v", exp-iat, logoutTokenTTL.Seconds())
	}
}

// With pairwise subjects on, sub is the subject the relying party saw in
// its ID token — never the raw user id (§2.4: "sub ... as in the ID Token").
func TestLogoutTokenSubjectIsThePairwiseSubjectTheRelyingPartySaw(t *testing.T) {
	svc, db, outcomes := bclSetup(t)
	svc.config = &config.Config{ABACEnforce: "off", OIDCPairwiseSubjects: true, EncryptionKey: "pairwise-test-key-32-bytes-long!!"}
	rp := newRelyingParty(t, http.StatusOK)
	userID := uuid.New().String()
	registerRP(t, db, ssoTestOrg, "rp-a", rp.srv.URL+"/bcl")
	sid := liveSession(t, db, ssoTestOrg, userID, "rp-a")

	if err := svc.revokeSessionWithRedis(context.Background(), sid); err != nil {
		t.Fatal(err)
	}
	awaitOutcome(t, outcomes, sid)
	_, claims := parseLogoutToken(t, svc, rp.tokens()[0].token)
	want := svc.subjectFor(userID, "rp-a")
	if want == userID {
		t.Fatal("test setup: pairwise subjects are not in effect")
	}
	if claims["sub"] != want {
		t.Fatalf("sub=%v, want the pairwise subject %s (raw user id %s must never appear)", claims["sub"], want, userID)
	}
}

// Every relying party the session reached is told exactly once: the client
// the session was created for and every client holding a refresh token bound
// to it; a client without a URI is not; a client with both roles gets one.
func TestSessionRevocationTellsEveryRelyingPartyOfTheSessionOnce(t *testing.T) {
	svc, db, outcomes := bclSetup(t)
	rpA, rpB := newRelyingParty(t, http.StatusOK), newRelyingParty(t, http.StatusOK)
	userID := uuid.New().String()
	registerRP(t, db, ssoTestOrg, "rp-a", rpA.srv.URL+"/a")
	registerRP(t, db, ssoTestOrg, "rp-b", rpB.srv.URL+"/b")
	registerRP(t, db, ssoTestOrg, "rp-c", "") // no back-channel URI
	sid := liveSession(t, db, ssoTestOrg, userID, "rp-a")
	bindRefreshToken(t, db, ssoTestOrg, userID, "rp-a", sid) // also holds a token: still one message
	bindRefreshToken(t, db, ssoTestOrg, userID, "rp-b", sid)
	bindRefreshToken(t, db, ssoTestOrg, userID, "rp-c", sid)
	// Another session of the same user, reaching rp-b too: untouched.
	other := liveSession(t, db, ssoTestOrg, userID, "rp-b")

	if err := svc.revokeSessionWithRedis(context.Background(), sid); err != nil {
		t.Fatal(err)
	}
	if d, f := awaitOutcome(t, outcomes, sid); d != 2 || f != 0 {
		t.Fatalf("delivered=%d failed=%d, want 2/0", d, f)
	}
	if a, b := rpA.tokens(), rpB.tokens(); len(a) != 1 || len(b) != 1 {
		t.Fatalf("rp-a got %d, rp-b got %d tokens; want one each", len(a), len(b))
	}
	_, ca := parseLogoutToken(t, svc, rpA.tokens()[0].token)
	_, cb := parseLogoutToken(t, svc, rpB.tokens()[0].token)
	if ca["aud"] != "rp-a" || cb["aud"] != "rp-b" || ca["sid"] != sid || cb["sid"] != sid {
		t.Fatalf("aud/sid wrong: %v / %v", ca, cb)
	}
	// The sibling session is still live and was not announced.
	var revoked bool
	_ = db.Pool.QueryRow(context.Background(), `SELECT revoked FROM sessions WHERE id=$1`, other).Scan(&revoked)
	if revoked {
		t.Fatal("the other session must stay live")
	}
}

// /oauth/logout with nothing but the cookie ends the browser session — and
// the relying party that session was created for hears about it.
func TestLogoutWithOnlyTheCookieTellsTheRelyingParty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db, outcomes := bclSetup(t)
	rp := newRelyingParty(t, http.StatusOK)
	userID := uuid.New().String()
	registerRP(t, db, ssoTestOrg, "rp-a", rp.srv.URL+"/logout")
	sid := liveSession(t, db, ssoTestOrg, userID, "rp-a")
	token := GenerateRandomToken(32)
	if err := svc.redis.Client.Set(context.Background(), ssoRedisPrefix+token, sid, time.Hour).Err(); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/oauth/logout", nil)
	req.AddCookie(&http.Cookie{Name: ssoCookieName, Value: token})
	c.Request = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: ssoTestOrg}))
	svc.handleLogout(c)
	if w.Code != http.StatusOK {
		t.Fatalf("logout: %d %s", w.Code, w.Body.String())
	}
	if d, f := awaitOutcome(t, outcomes, sid); d != 1 || f != 0 {
		t.Fatalf("delivered=%d failed=%d, want 1/0", d, f)
	}
	_, claims := parseLogoutToken(t, svc, rp.tokens()[0].token)
	if claims["sid"] != sid || claims["sub"] != userID {
		t.Fatalf("claims=%v", claims)
	}
}

// revokeAllUserSessions announces each of the user's sessions with its own
// sid, and nothing for another user's session.
func TestRevokeAllUserSessionsAnnouncesEachSession(t *testing.T) {
	svc, db, outcomes := bclSetup(t)
	rp := newRelyingParty(t, http.StatusOK)
	userID, otherUser := uuid.New().String(), uuid.New().String()
	registerRP(t, db, ssoTestOrg, "rp-a", rp.srv.URL+"/x")
	s1 := liveSession(t, db, ssoTestOrg, userID, "rp-a")
	s2 := liveSession(t, db, ssoTestOrg, userID, "rp-a")
	liveSession(t, db, ssoTestOrg, otherUser, "rp-a")

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: ssoTestOrg})
	if err := svc.revokeAllUserSessions(ctx, userID); err != nil {
		t.Fatal(err)
	}
	awaitOutcome(t, outcomes, s1)
	awaitOutcome(t, outcomes, s2)
	got := rp.tokens()
	if len(got) != 2 {
		t.Fatalf("got %d tokens, want 2", len(got))
	}
	sids := map[string]bool{}
	for _, g := range got {
		_, claims := parseLogoutToken(t, svc, g.token)
		if claims["sub"] != userID {
			t.Fatalf("token for %v, want %s", claims["sub"], userID)
		}
		sids[claims["sid"].(string)] = true
	}
	if !sids[s1] || !sids[s2] {
		t.Fatalf("sids announced %v, want %s and %s", sids, s1, s2)
	}
}

// A relying party that fails (or is down) never fails the revocation; the
// outcome is recorded as a failure.
func TestRelyingPartyFailureNeverFailsTheRevocation(t *testing.T) {
	svc, db, outcomes := bclSetup(t)
	rp := newRelyingParty(t, http.StatusInternalServerError)
	userID := uuid.New().String()
	registerRP(t, db, ssoTestOrg, "rp-a", rp.srv.URL+"/x")
	registerRP(t, db, ssoTestOrg, "rp-down", "http://127.0.0.1:1/nothing-listens")
	sid := liveSession(t, db, ssoTestOrg, userID, "rp-a")
	bindRefreshToken(t, db, ssoTestOrg, userID, "rp-down", sid)

	if err := svc.revokeSessionWithRedis(context.Background(), sid); err != nil {
		t.Fatalf("revocation must not report the relying party's failure: %v", err)
	}
	if d, f := awaitOutcome(t, outcomes, sid); d != 0 || f != 2 {
		t.Fatalf("delivered=%d failed=%d, want 0/2", d, f)
	}
	var revoked bool
	_ = db.Pool.QueryRow(context.Background(), `SELECT revoked FROM sessions WHERE id=$1`, sid).Scan(&revoked)
	if !revoked {
		t.Fatal("the session must be revoked whatever the relying party did")
	}
}

// Targets are the session's tenant's clients only: a client with the same
// client_id registered in another tenant, with a URI, is not told.
func TestBackchannelTargetsAreTenantScoped(t *testing.T) {
	svc, db, outcomes := bclSetup(t)
	rp := newRelyingParty(t, http.StatusOK)
	userID := uuid.New().String()
	registerRP(t, db, ssoOtherOrg, "rp-a", rp.srv.URL+"/other-tenant")
	sid := liveSession(t, db, ssoTestOrg, userID, "rp-a")

	if err := svc.revokeSessionWithRedis(context.Background(), sid); err != nil {
		t.Fatal(err)
	}
	if d, f := awaitOutcome(t, outcomes, sid); d != 0 || f != 0 {
		t.Fatalf("delivered=%d failed=%d, want 0/0", d, f)
	}
	if got := rp.tokens(); len(got) != 0 {
		t.Fatalf("another tenant's client received %v", got)
	}
}

// The client store carries the URI both ways, and refuses one that is not
// https (http only on loopback).
func TestClientStoreRoundTripsBackChannelLogoutURI(t *testing.T) {
	_, db, _ := bclSetup(t)
	store := NewPostgresOAuthClientStore(db)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: ssoTestOrg})
	client := &OAuthClient{ID: uuid.New().String(), ClientID: "store-a", Name: "A", Type: "confidential",
		RedirectURIs: []string{"https://a.example/cb"}, BackChannelLogoutURI: "https://a.example/bcl"}
	if err := store.Create(ctx, client); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetByClientID(ctx, "store-a")
	if err != nil || got.BackChannelLogoutURI != "https://a.example/bcl" {
		t.Fatalf("got %+v err=%v", got, err)
	}
	client.BackChannelLogoutURI = "https://a.example/bcl-v2"
	if err := store.Update(ctx, "store-a", client); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.GetByClientID(ctx, "store-a"); got.BackChannelLogoutURI != "https://a.example/bcl-v2" {
		t.Fatalf("update not persisted: %q", got.BackChannelLogoutURI)
	}
	client.BackChannelLogoutURI = ""
	if err := store.Update(ctx, "store-a", client); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.GetByClientID(ctx, "store-a"); got.BackChannelLogoutURI != "" {
		t.Fatalf("clearing must persist, got %q", got.BackChannelLogoutURI)
	}
	client.BackChannelLogoutURI = "http://evil.example/bcl"
	if err := store.Update(ctx, "store-a", client); err == nil {
		t.Fatal("an http URI off loopback must be refused")
	}
	bad := &OAuthClient{ID: uuid.New().String(), ClientID: "store-b", Name: "B", Type: "confidential", BackChannelLogoutURI: "not a url"}
	if err := store.Create(ctx, bad); err == nil {
		t.Fatal("a relative value must be refused")
	}
}

func TestValidateBackChannelLogoutURI(t *testing.T) {
	for uri, ok := range map[string]bool{
		"":                             true,
		"https://rp.example/logout":    true,
		"http://localhost:3000/logout": true,
		"http://127.0.0.1:8080/logout": true,
		"http://rp.example/logout":     false,
		"/relative":                    false,
		"rp.example/logout":            false,
		"ftp://rp.example/logout":      false,
		"https://":                     false,
		"com.example.app:/logout":      false,
	} {
		if err := validateBackChannelLogoutURI(uri); (err == nil) != ok {
			t.Errorf("validateBackChannelLogoutURI(%q) err=%v, want ok=%v", uri, err, ok)
		}
	}
}

// Dynamic client registration carries backchannel_logout_uri (§2.2) into the
// client and echoes it, and refuses an insecure one.
func TestDCRCarriesBackchannelLogoutURI(t *testing.T) {
	svc := &Service{}
	client, err := svc.buildClientFromMetadata(&clientMetadata{
		ClientName: "x", GrantTypes: []string{"authorization_code"},
		RedirectURIs: []string{"https://rp.example/cb"}, BackchannelLogoutURI: "https://rp.example/bcl",
	})
	if err != nil || client.BackChannelLogoutURI != "https://rp.example/bcl" {
		t.Fatalf("client=%+v err=%v", client, err)
	}
	if _, err := svc.buildClientFromMetadata(&clientMetadata{
		ClientName: "x", GrantTypes: []string{"authorization_code"},
		RedirectURIs: []string{"https://rp.example/cb"}, BackchannelLogoutURI: "http://rp.example/bcl",
	}); err == nil {
		t.Fatal("an http backchannel_logout_uri off loopback must be refused")
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "https://issuer.example/oauth/register", nil)
	resp := svc.registrationResponse(c, client, "reg")
	raw, _ := json.Marshal(resp)
	if !strings.Contains(string(raw), `"backchannel_logout_uri":"https://rp.example/bcl"`) {
		t.Fatalf("registration response must echo the URI: %s", raw)
	}
}

// The advertisement and the capability now agree.
func TestDiscoveryAdvertisesBackchannelLogoutThatIsImplemented(t *testing.T) {
	doc, _ := serveDiscovery(t, "https://test.openidx.org")
	if doc["backchannel_logout_supported"] != true || doc["backchannel_logout_session_supported"] != true {
		t.Fatalf("discovery must advertise back-channel logout with sid: %v", doc)
	}
}
