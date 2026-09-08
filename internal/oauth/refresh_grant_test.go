package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// handleRefreshTokenGrant had no test that named it.
//
// The machinery UNDER it is well covered: refresh_reuse_test.go proves the
// database state machine — tombstone, family revocation, the race loser, tenant
// confinement. What nothing proved is that the handler consults any of it. Six
// decisions sit between the request and those helpers, each one a control with
// a comment in the source explaining why it exists, and each one silently
// removable:
//
//	1. the client is authenticated, and its secret compared in constant time;
//	2. the token was issued TO THAT CLIENT (RFC 6749 §10.4) -- a leaked token
//	   must not be exchangeable by a different registered client;
//	3. a replayed token triggers the family revocation, not just a refusal;
//	4. the user still exists and is enabled -- this is the actual kill-switch
//	   behind disable/delete/SCIM-deprovision, because a refresh token outlives
//	   the access token it minted;
//	5. the linked session has not been revoked;
//	6. rotation happens only when the scope still carries offline_access.
//
// Delete any one of them and every test in this package still passes. That is
// what these cases are for. They run against a real Postgres because the
// decisions read rows; the assertions are on the HTTP answer and on the row
// state afterwards, which is what a client and an attacker respectively see.
//
// Not covered here: the 503-not-500 brownout path for a Redis or Postgres
// outage. Reaching isDependencyUnavailable needs a connection failure rather
// than a query error, and faking one poisons the shared container for the
// cases after it. The last case below covers the half that matters for
// security -- a broken user lookup must DENY, not mint.

const refreshGrantSchema = `
CREATE TABLE oauth_clients (
    id                     UUID PRIMARY KEY,
    client_id              VARCHAR(255) NOT NULL,
    client_secret          VARCHAR(255),
    name                   VARCHAR(255) NOT NULL,
    description            TEXT,
    type                   VARCHAR(32) NOT NULL DEFAULT 'confidential',
    redirect_uris          JSONB NOT NULL DEFAULT '[]'::jsonb,
    grant_types            JSONB NOT NULL DEFAULT '[]'::jsonb,
    response_types         JSONB NOT NULL DEFAULT '[]'::jsonb,
    scopes                 JSONB NOT NULL DEFAULT '[]'::jsonb,
    logo_uri               TEXT,
    policy_uri             TEXT,
    tos_uri                TEXT,
    pkce_required          BOOLEAN NOT NULL DEFAULT false,
    allow_refresh_token    BOOLEAN NOT NULL DEFAULT true,
    access_token_lifetime  INT NOT NULL DEFAULT 3600,
    refresh_token_lifetime INT NOT NULL DEFAULT 2592000,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    org_id                 UUID NOT NULL,
    UNIQUE (org_id, client_id)
);

CREATE TABLE users (
    id         UUID PRIMARY KEY,
    email      TEXT,
    first_name TEXT,
    last_name  TEXT,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    org_id     UUID NOT NULL
);`

const (
	grantOrg   = "88888888-0000-0000-0000-00000000000c"
	grantUser  = "99999999-0000-0000-0000-000000000001"
	grantOther = "99999999-0000-0000-0000-000000000002"
)

type refreshGrantFixture struct {
	svc   *Service
	db    *database.PostgresDB
	redis *miniredis.Miniredis
	ctx   context.Context
	key   *rsa.PrivateKey
}

// newRefreshGrantFixture builds the smallest service that can answer a refresh
// grant: a real Postgres for the rows the decisions read, miniredis for the
// session-revocation check, and an RSA key so the minted token is a real
// signature rather than a stub. identityService is deliberately left nil --
// every case below either has no session id or has a REVOKED one, and the
// handler returns before the debounced activity update on both paths. A case
// that needs a live session must set one rather than discover this in a
// goroutine panic.
func newRefreshGrantFixture(t *testing.T) *refreshGrantFixture {
	t.Helper()

	db, cleanup := ssfSetupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: grantOrg})
	for _, ddl := range []string{refreshReuseSchema, refreshGrantSchema} {
		if _, err := db.Pool.Exec(ctx, ddl); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}

	mini := miniredis.RunT(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	svc := &Service{
		db:         db,
		redis:      &database.RedisClient{Client: redis.NewClient(&redis.Options{Addr: mini.Addr()})},
		config:     &config.Config{},
		logger:     zap.NewNop(),
		privateKey: key,
		publicKey:  &key.PublicKey,
		issuer:     "https://refresh-grant.test",
		clients:    NewPostgresOAuthClientStore(db),
	}

	f := &refreshGrantFixture{svc: svc, db: db, redis: mini, ctx: ctx, key: key}
	f.seedClient(t, "app", "s3cret", true)
	f.seedClient(t, "other-app", "other-secret", true)
	f.seedClient(t, "no-refresh", "no-refresh-secret", false)
	f.seedUser(t, grantUser, true)
	return f
}

func (f *refreshGrantFixture) seedClient(t *testing.T, clientID, secret string, allowRefresh bool) {
	t.Helper()
	if _, err := f.db.Pool.Exec(f.ctx, `
		INSERT INTO oauth_clients (id, client_id, client_secret, name, allow_refresh_token, org_id)
		VALUES (gen_random_uuid(), $1, $2, $1, $3, $4)`,
		clientID, secret, allowRefresh, grantOrg); err != nil {
		t.Fatalf("seed client %s: %v", clientID, err)
	}
}

func (f *refreshGrantFixture) seedUser(t *testing.T, userID string, enabled bool) {
	t.Helper()
	if _, err := f.db.Pool.Exec(f.ctx, `
		INSERT INTO users (id, email, first_name, last_name, enabled, org_id)
		VALUES ($1, 'grant@test.local', 'Grant', 'Tester', $2, $3)
		ON CONFLICT (id) DO UPDATE SET enabled = EXCLUDED.enabled`,
		userID, enabled, grantOrg); err != nil {
		t.Fatalf("seed user %s: %v", userID, err)
	}
}

// mintRefresh writes a refresh token straight to the table, which is how the
// authorization-code grant leaves one behind.
func (f *refreshGrantFixture) mintRefresh(t *testing.T, tok, clientID, userID, scope, family, session string, expires time.Time) {
	t.Helper()
	rt := &RefreshToken{
		Token:     tok,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		SessionID: session,
		FamilyID:  family,
		ExpiresAt: expires,
		CreatedAt: time.Now(),
	}
	if err := f.svc.CreateRefreshToken(f.ctx, rt); err != nil {
		t.Fatalf("mint refresh token %s: %v", tok, err)
	}
}

// post drives handleRefreshTokenGrant the way the token endpoint does, with the
// org on the request context that the routing middleware would have put there.
func (f *refreshGrantFixture) post(t *testing.T, form url.Values, basic ...string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basic) == 2 {
		req.SetBasicAuth(basic[0], basic[1])
	}
	c.Request = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: grantOrg}))

	f.svc.handleRefreshTokenGrant(c)

	body := map[string]interface{}{}
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("response is not JSON (%d): %s", w.Code, w.Body.String())
		}
	}
	return w, body
}

func (f *refreshGrantFixture) tokenState(t *testing.T, tok string) (used, revoked bool) {
	t.Helper()
	if err := f.db.Pool.QueryRow(f.ctx,
		"SELECT used_at IS NOT NULL, revoked_at IS NOT NULL FROM oauth_refresh_tokens WHERE token = $1",
		tok).Scan(&used, &revoked); err != nil {
		t.Fatalf("read token state for %s: %v", tok, err)
	}
	return used, revoked
}

func creds(clientID, secret string, extra ...string) url.Values {
	v := url.Values{"client_id": {clientID}, "client_secret": {secret}}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

func TestRefreshTokenGrant(t *testing.T) {
	f := newRefreshGrantFixture(t)
	hour := time.Now().Add(time.Hour)

	t.Run("an unknown client is refused", func(t *testing.T) {
		w, body := f.post(t, creds("ghost", "whatever", "refresh_token", "anything"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body %v", w.Code, body)
		}
		if body["error"] != "invalid_client" {
			t.Errorf("error = %v, want invalid_client", body["error"])
		}
	})

	t.Run("a wrong secret is refused", func(t *testing.T) {
		f.mintRefresh(t, "tok-wrong-secret", "app", grantUser, "openid offline_access", "", "", hour)
		w, body := f.post(t, creds("app", "not-the-secret", "refresh_token", "tok-wrong-secret"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body %v", w.Code, body)
		}
		// A refusal must not consume the token: a client that mistypes its
		// secret would otherwise burn the user's session.
		if used, revoked := f.tokenState(t, "tok-wrong-secret"); used || revoked {
			t.Errorf("a failed client auth spent the token (used=%v revoked=%v)", used, revoked)
		}
	})

	t.Run("two client authentication methods are refused", func(t *testing.T) {
		w, body := f.post(t, creds("app", "s3cret", "refresh_token", "anything"), "app", "s3cret")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body %v", w.Code, body)
		}
		if body["error"] != "invalid_request" {
			t.Errorf("error = %v, want invalid_request", body["error"])
		}
	})

	t.Run("an unknown refresh token is invalid_grant", func(t *testing.T) {
		w, body := f.post(t, creds("app", "s3cret", "refresh_token", "never-issued"))
		if w.Code != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Fatalf("status = %d error = %v, want 400 invalid_grant", w.Code, body["error"])
		}
	})

	t.Run("an expired refresh token is invalid_grant", func(t *testing.T) {
		f.mintRefresh(t, "tok-expired", "app", grantUser, "openid offline_access", "",
			"", time.Now().Add(-time.Minute))
		w, body := f.post(t, creds("app", "s3cret", "refresh_token", "tok-expired"))
		if w.Code != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Fatalf("status = %d error = %v, want 400 invalid_grant", w.Code, body["error"])
		}
	})

	// RFC 6749 §10.4. Without this check a refresh token that leaks to any
	// other registered client -- a second first-party app, a client whose
	// registration an attacker obtained -- is exchangeable by it.
	t.Run("a token issued to another client is refused", func(t *testing.T) {
		f.mintRefresh(t, "tok-bound-to-app", "app", grantUser, "openid offline_access", "", "", hour)
		w, body := f.post(t, creds("other-app", "other-secret", "refresh_token", "tok-bound-to-app"))
		if w.Code != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Fatalf("status = %d error = %v, want 400 invalid_grant", w.Code, body["error"])
		}
		if _, ok := body["access_token"]; ok {
			t.Fatal("the wrong client was handed an access token")
		}
		if used, revoked := f.tokenState(t, "tok-bound-to-app"); used || revoked {
			t.Errorf("the rightful owner's token was spent by another client's attempt (used=%v revoked=%v)", used, revoked)
		}
	})

	// The store test proves revokeRefreshTokenFamily works. This proves the
	// handler calls it -- the half that a refactor drops.
	t.Run("a replayed token revokes the whole family", func(t *testing.T) {
		const family = "aaaaaaaa-1111-1111-1111-111111111111"
		f.mintRefresh(t, "tok-replayed", "app", grantUser, "openid offline_access", family, "", hour)
		f.mintRefresh(t, "tok-successor", "app", grantUser, "openid offline_access", family, "", hour)
		if _, err := f.db.Pool.Exec(f.ctx,
			"UPDATE oauth_refresh_tokens SET used_at = NOW() WHERE token = 'tok-replayed'"); err != nil {
			t.Fatalf("tombstone the replayed token: %v", err)
		}

		w, body := f.post(t, creds("app", "s3cret", "refresh_token", "tok-replayed"))
		if w.Code != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Fatalf("status = %d error = %v, want 400 invalid_grant", w.Code, body["error"])
		}
		desc, _ := body["error_description"].(string)
		if !strings.Contains(desc, "reuse detected") {
			t.Errorf("error_description = %q, want it to name the reuse", desc)
		}
		if _, revoked := f.tokenState(t, "tok-successor"); !revoked {
			t.Error("the successor still works after a replay — the handler answered but revoked nothing, " +
				"which leaves whoever holds the newest token (plausibly the attacker) with a working chain")
		}
	})

	// The case above does NOT pin the pre-mint detector on its own: the
	// rotation block carries a second one (the !claimed branch), so neutering
	// the first still produces the same refusal by a longer route. That second
	// detector fires only when rotation is ATTEMPTED. A spent token whose scope
	// no longer carries offline_access reaches neither the rotation block nor
	// anything else -- the check before the mint is all there is, and without it
	// that token mints a fresh access token on every replay, for as long as it
	// has left to live. This is the case that fails when the first detector goes.
	t.Run("a replayed token is refused even when nothing would rotate", func(t *testing.T) {
		f.mintRefresh(t, "tok-replayed-no-offline", "app", grantUser, "openid", "", "", hour)
		if _, err := f.db.Pool.Exec(f.ctx,
			"UPDATE oauth_refresh_tokens SET used_at = NOW() WHERE token = 'tok-replayed-no-offline'"); err != nil {
			t.Fatalf("tombstone: %v", err)
		}
		w, body := f.post(t, creds("app", "s3cret", "refresh_token", "tok-replayed-no-offline"))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; a spent token minted %v", w.Code, body["access_token"])
		}
		if body["error"] != "invalid_grant" {
			t.Errorf("error = %v, want invalid_grant", body["error"])
		}
		desc, _ := body["error_description"].(string)
		if !strings.Contains(desc, "reuse detected") {
			t.Errorf("error_description = %q, want it to name the reuse", desc)
		}
	})

	// A refresh token outlives the access token it mints, so without this the
	// disable button in the console stops nothing until the refresh token
	// expires on its own -- up to refresh_token_lifetime later.
	t.Run("a disabled user cannot mint a new access token", func(t *testing.T) {
		f.seedUser(t, grantOther, false)
		f.mintRefresh(t, "tok-disabled-user", "app", grantOther, "openid offline_access", "", "", hour)
		w, body := f.post(t, creds("app", "s3cret", "refresh_token", "tok-disabled-user"))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body %v", w.Code, body)
		}
		if body["error_description"] != "user_inactive" {
			t.Errorf("error_description = %v, want user_inactive", body["error_description"])
		}
		if _, ok := body["access_token"]; ok {
			t.Fatal("a disabled user was handed a fresh access token")
		}
	})

	t.Run("a deleted user cannot mint a new access token", func(t *testing.T) {
		const ghost = "99999999-0000-0000-0000-0000000000ff"
		f.mintRefresh(t, "tok-deleted-user", "app", ghost, "openid offline_access", "", "", hour)
		w, body := f.post(t, creds("app", "s3cret", "refresh_token", "tok-deleted-user"))
		if w.Code != http.StatusBadRequest || body["error_description"] != "user_inactive" {
			t.Fatalf("status = %d description = %v, want 400 user_inactive", w.Code, body["error_description"])
		}
	})

	t.Run("a revoked session is refused", func(t *testing.T) {
		const sid = "session-revoked-1"
		f.redis.Set("revoked_session:"+sid, "admin_kill_switch")
		f.mintRefresh(t, "tok-revoked-session", "app", grantUser, "openid offline_access", "", sid, hour)
		w, body := f.post(t, creds("app", "s3cret", "refresh_token", "tok-revoked-session"))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body %v", w.Code, body)
		}
		if body["error_description"] != "session_revoked" {
			t.Errorf("error_description = %v, want session_revoked", body["error_description"])
		}
	})

	t.Run("the happy path mints a token and rotates the refresh token", func(t *testing.T) {
		f.mintRefresh(t, "tok-happy", "app", grantUser, "openid offline_access", "", "", hour)
		w, body := f.post(t, creds("app", "s3cret", "refresh_token", "tok-happy"))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %v", w.Code, body)
		}

		access, _ := body["access_token"].(string)
		if access == "" {
			t.Fatal("no access_token in the response")
		}
		parsed, err := jwt.Parse(access, f.svc.verificationKeyfunc, jwt.WithValidMethods([]string{"RS256"}))
		if err != nil || !parsed.Valid {
			t.Fatalf("the minted access token does not verify: %v", err)
		}
		claims := parsed.Claims.(jwt.MapClaims)
		if claims["sub"] != grantUser {
			t.Errorf("sub = %v, want %s", claims["sub"], grantUser)
		}
		if claims["client_id"] != "app" {
			t.Errorf("client_id = %v, want app", claims["client_id"])
		}
		if claims["scope"] != "openid offline_access" {
			t.Errorf("scope = %v, want the token's own scope", claims["scope"])
		}

		rotated, _ := body["refresh_token"].(string)
		if rotated == "" {
			t.Fatal("offline_access was granted but no refresh_token came back — a client storing " +
				"the old one long-term would be holding a spent secret")
		}
		if rotated == "tok-happy" {
			t.Fatal("the same refresh token came back; rotation did not happen")
		}
		if used, _ := f.tokenState(t, "tok-happy"); !used {
			t.Error("the presented token was not tombstoned, so a replay of it would not be detected")
		}

		// The successor inherits the family, so a later replay anywhere in the
		// chain still revokes the whole thing.
		var oldFamily, newFamily string
		_ = f.db.Pool.QueryRow(f.ctx,
			"SELECT family_id::text FROM oauth_refresh_tokens WHERE token = 'tok-happy'").Scan(&oldFamily)
		_ = f.db.Pool.QueryRow(f.ctx,
			"SELECT family_id::text FROM oauth_refresh_tokens WHERE token = $1", rotated).Scan(&newFamily)
		if oldFamily == "" || newFamily != oldFamily {
			t.Errorf("family_id %q -> %q; the successor left the family, so a replay would revoke only part of the chain",
				oldFamily, newFamily)
		}
	})

	t.Run("a token without offline_access is not rotated", func(t *testing.T) {
		f.mintRefresh(t, "tok-no-offline", "app", grantUser, "openid", "", "", hour)
		w, body := f.post(t, creds("app", "s3cret", "refresh_token", "tok-no-offline"))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %v", w.Code, body)
		}
		if _, ok := body["refresh_token"]; ok {
			t.Error("a refresh token was issued for a scope that does not carry offline_access")
		}
		if used, _ := f.tokenState(t, "tok-no-offline"); used {
			t.Error("the token was tombstoned without a successor being issued, which strands the client")
		}
	})

	t.Run("a client that may not hold refresh tokens gets none back", func(t *testing.T) {
		f.mintRefresh(t, "tok-no-refresh-client", "no-refresh", grantUser, "openid offline_access", "", "", hour)
		w, body := f.post(t, creds("no-refresh", "no-refresh-secret", "refresh_token", "tok-no-refresh-client"))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %v", w.Code, body)
		}
		if _, ok := body["refresh_token"]; ok {
			t.Error("allow_refresh_token is false for this client and it was handed one anyway")
		}
	})

	// LAST, because it drops the users table. A user lookup that fails must
	// deny; the alternative is that any breakage in that query turns the
	// kill-switch off for everyone at once.
	t.Run("a broken user lookup denies rather than mints", func(t *testing.T) {
		f.mintRefresh(t, "tok-broken-lookup", "app", grantUser, "openid offline_access", "", "", hour)
		if _, err := f.db.Pool.Exec(f.ctx, "DROP TABLE users"); err != nil {
			t.Fatalf("drop users: %v", err)
		}
		w, body := f.post(t, creds("app", "s3cret", "refresh_token", "tok-broken-lookup"))
		if w.Code == http.StatusOK {
			t.Fatalf("a failed user lookup minted a token anyway: %v", body)
		}
		if _, ok := body["access_token"]; ok {
			t.Fatal("a failed user lookup still returned an access token")
		}
		if used, _ := f.tokenState(t, "tok-broken-lookup"); used {
			t.Error("the token was spent on a request that was refused")
		}
	})
}
