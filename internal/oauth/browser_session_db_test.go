package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The session-backed half of the SSO fast path, against a real PostgreSQL
// (OPENIDX_TEST_DATABASE_URL, or a testcontainer). The schema is the subset
// of the real one these paths touch; ssfSetupTestDB drops schema public first,
// so point the URL at a scratch database.

const ssoOtherOrg = "33333333-3333-3333-3333-333333333333"

func ssoSetupDB(t *testing.T) (*Service, *database.PostgresDB) {
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
		`CREATE TABLE oauth_authorization_codes (
			code VARCHAR(255) PRIMARY KEY,
			client_id VARCHAR(255) NOT NULL,
			user_id UUID NOT NULL,
			redirect_uri TEXT NOT NULL,
			scope TEXT,
			state TEXT,
			nonce TEXT,
			code_challenge TEXT,
			code_challenge_method VARCHAR(10),
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			org_id UUID NOT NULL
		)`,
		`CREATE TABLE applications (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			client_id VARCHAR(255) NOT NULL,
			org_id UUID NOT NULL,
			name VARCHAR(255) NOT NULL DEFAULT 'app',
			require_assignment BOOLEAN DEFAULT false,
			enabled BOOLEAN DEFAULT true
		)`,
		`CREATE TABLE application_sso_settings (
			application_id UUID PRIMARY KEY,
			require_consent BOOLEAN DEFAULT false
		)`,
		`CREATE TABLE user_application_assignments (
			application_id UUID NOT NULL,
			user_id UUID NOT NULL,
			org_id UUID NOT NULL
		)`,
		`CREATE TABLE group_application_assignments (
			application_id UUID NOT NULL,
			group_id UUID NOT NULL,
			org_id UUID NOT NULL
		)`,
		`CREATE TABLE group_memberships (
			group_id UUID NOT NULL,
			user_id UUID NOT NULL
		)`,
		`CREATE TABLE oauth_user_consents (
			org_id UUID NOT NULL,
			user_id UUID NOT NULL,
			client_id VARCHAR(255) NOT NULL,
			scopes TEXT NOT NULL,
			granted_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE (org_id, user_id, client_id)
		)`,
	} {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v\n%s", err, stmt)
		}
	}
	svc := newLoginUITestService(t, "", ssoTestClient())
	svc.db = db
	svc.config = &config.Config{ABACEnforce: "off"}
	return svc, db
}

// ssoSession inserts a session row and binds a fresh cookie token to it,
// returning the token. startedAgo shifts started_at into the past.
func ssoSession(t *testing.T, svc *Service, db *database.PostgresDB, orgID, userID string, startedAgo, ttl time.Duration, revoked bool) (sessionID, token string) {
	t.Helper()
	sessionID = uuid.New().String()
	_, err := db.Pool.Exec(context.Background(),
		`INSERT INTO sessions (id, user_id, started_at, last_seen_at, expires_at, org_id, revoked)
		 VALUES ($1, $2, NOW() - $3::interval, NOW(), NOW() + $4::interval, $5, $6)`,
		sessionID, userID, startedAgo.String(), ttl.String(), orgID, revoked)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	token = GenerateRandomToken(32)
	if err := svc.redis.Client.Set(context.Background(), ssoRedisPrefix+token, sessionID, time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	return sessionID, token
}

// mintedCode asserts the response is a redirect to the client carrying a code
// that exists in oauth_authorization_codes for userID, and returns the code.
func mintedCode(t *testing.T, db *database.PostgresDB, w *httptest.ResponseRecorder, userID string) string {
	t.Helper()
	u := locationOf(t, w)
	if u.Host != "app.example.test" || u.Path != "/callback" {
		t.Fatalf("expected the client's redirect_uri, got %s", u)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", u)
	}
	if u.Query().Get("state") != "st-1" {
		t.Fatalf("state not echoed: %s", u)
	}
	var gotUser string
	if err := db.Pool.QueryRow(context.Background(),
		`SELECT user_id::text FROM oauth_authorization_codes WHERE code = $1 AND org_id = $2`,
		code, ssoTestOrg).Scan(&gotUser); err != nil {
		t.Fatalf("code row: %v", err)
	}
	if gotUser != userID {
		t.Fatalf("code minted for %s, want %s", gotUser, userID)
	}
	return code
}

func expectLogin(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if u := locationOf(t, w); u.Path != "/login" || u.Query().Get("login_session") == "" {
		t.Fatalf("expected the login UI, got %s", u)
	}
}

func TestSSOLiveSessionMintsCodeWithoutLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	userID := uuid.New().String()
	sessionID, token := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, false)

	w := ssoAuthorize(t, svc, token, url.Values{"nonce": {"n-1"}})
	code := mintedCode(t, db, w, userID)

	// The token endpoint's session binding (authcode_session) is written
	// exactly as the login flow writes it.
	if got, _ := svc.redis.Client.Get(context.Background(), "authcode_session:"+code).Result(); got != sessionID {
		t.Fatalf("authcode_session=%q, want %q", got, sessionID)
	}
	var nonce string
	_ = db.Pool.QueryRow(context.Background(), `SELECT nonce FROM oauth_authorization_codes WHERE code=$1`, code).Scan(&nonce)
	if nonce != "n-1" {
		t.Fatalf("nonce not carried: %q", nonce)
	}
	if clearedSSOCookie(w) {
		t.Fatal("a live session's cookie must not be cleared")
	}
	// prompt=none rides the same session.
	mintedCode(t, db, ssoAuthorize(t, svc, token, url.Values{"prompt": {"none"}}), userID)
}

// Every shape of "not a live session of this tenant" goes to the login UI
// with the cookie cleared, and never mints.
func TestSSOStaleSessionsFallBackToLoginAndClearCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	userID := uuid.New().String()
	ctx := context.Background()

	cases := map[string]func() string{
		"revoked": func() string {
			_, tok := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, true)
			return tok
		},
		"expired": func() string {
			_, tok := ssoSession(t, svc, db, ssoTestOrg, userID, 2*time.Hour, -time.Minute, false)
			return tok
		},
		"deleted (terminated / offboarded)": func() string {
			id, tok := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, false)
			if _, err := db.Pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id); err != nil {
				t.Fatal(err)
			}
			return tok
		},
		"another tenant's session": func() string {
			_, tok := ssoSession(t, svc, db, ssoOtherOrg, userID, time.Minute, time.Hour, false)
			return tok
		},
		"token Redis has forgotten": func() string {
			return GenerateRandomToken(32)
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			token := mk()
			w := ssoAuthorize(t, svc, token, nil)
			expectLogin(t, w)
			if !clearedSSOCookie(w) {
				t.Fatal("stale cookie must be cleared")
			}
			if n, _ := svc.redis.Client.Exists(ctx, ssoRedisPrefix+token).Result(); n != 0 {
				t.Fatal("stale sso_session mapping must be deleted")
			}
			w = ssoAuthorize(t, svc, token, url.Values{"prompt": {"none"}})
			if u := locationOf(t, w); u.Query().Get("error") != ErrorLoginRequired {
				t.Fatalf("prompt=none must be login_required, got %s", u)
			}
		})
	}
	var n int
	_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM oauth_authorization_codes`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d codes minted from stale sessions", n)
	}
}

func TestSSOMaxAgeAndPromptLoginForceReauthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	userID := uuid.New().String()
	_, token := ssoSession(t, svc, db, ssoTestOrg, userID, 2*time.Hour, 20*time.Hour, false)

	// Older than max_age: re-authenticate; the cookie stays (another client
	// may accept a two-hour-old authentication).
	w := ssoAuthorize(t, svc, token, url.Values{"max_age": {"3600"}})
	expectLogin(t, w)
	if clearedSSOCookie(w) {
		t.Fatal("max_age does not invalidate the session; the cookie must stay")
	}
	w = ssoAuthorize(t, svc, token, url.Values{"max_age": {"3600"}, "prompt": {"none"}})
	if u := locationOf(t, w); u.Query().Get("error") != ErrorLoginRequired {
		t.Fatalf("prompt=none over max_age must be login_required, got %s", u)
	}
	// Within max_age: minted.
	mintedCode(t, db, ssoAuthorize(t, svc, token, url.Values{"max_age": {"86400"}}), userID)

	// prompt=login: the session is live and ignored.
	w = ssoAuthorize(t, svc, token, url.Values{"prompt": {"login"}})
	expectLogin(t, w)
	if clearedSSOCookie(w) {
		t.Fatal("prompt=login must not clear the cookie")
	}
	// prompt=consent and select_account need a UI: interactive path.
	expectLogin(t, ssoAuthorize(t, svc, token, url.Values{"prompt": {"consent"}}))
	expectLogin(t, ssoAuthorize(t, svc, token, url.Values{"prompt": {"select_account"}}))
}

func TestSSOConsentRequiredTakesTheInteractivePath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	ctx := context.Background()
	userID := uuid.New().String()
	_, token := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, false)

	var appID string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO applications (client_id, org_id) VALUES ('c', $1) RETURNING id::text`, ssoTestOrg).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO application_sso_settings (application_id, require_consent) VALUES ($1, true)`, appID); err != nil {
		t.Fatal(err)
	}

	// No consent on record: the login page (which renders the consent screen).
	w := ssoAuthorize(t, svc, token, nil)
	expectLogin(t, w)
	if clearedSSOCookie(w) {
		t.Fatal("a live session needing consent keeps its cookie")
	}
	// prompt=none cannot show it: consent_required.
	w = ssoAuthorize(t, svc, token, url.Values{"prompt": {"none"}})
	if u := locationOf(t, w); u.Query().Get("error") != ErrorConsentRequired {
		t.Fatalf("expected consent_required, got %s", u)
	}
	// Consent recorded for the requested scopes: minted.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO oauth_user_consents (org_id, user_id, client_id, scopes) VALUES ($1, $2, 'c', 'openid profile')`,
		ssoTestOrg, userID); err != nil {
		t.Fatal(err)
	}
	mintedCode(t, db, ssoAuthorize(t, svc, token, nil), userID)
	// A wider scope than granted: back to consent.
	expectLogin(t, ssoAuthorize(t, svc, token, url.Values{"scope": {"openid email"}}))
}

// The login flow's code issuance sets the cookie, and that cookie then
// authorizes the next request end to end.
func TestIssueAuthorizationCodeSetsSSOCookieThatAuthorizesNextRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	ctx := context.Background()
	userID := uuid.New().String()
	sessionID := uuid.New().String()
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO sessions (id, user_id, expires_at, org_id) VALUES ($1, $2, NOW() + interval '1 hour', $3)`,
		sessionID, userID, ssoTestOrg); err != nil {
		t.Fatal(err)
	}

	issue := func(svc *Service) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodPost, "/oauth/login", nil)
		c.Request = req.WithContext(orgctx.With(ctx, orgctx.Org{ID: ssoTestOrg}))
		svc.issueAuthorizationCode(c, map[string]string{
			"client_id": "c", "redirect_uri": ssoTestRedirect, "scope": "openid",
			"state": "st-1", "session_id": sessionID,
		}, userID)
		if w.Code != http.StatusOK {
			t.Fatalf("issue: %d %s", w.Code, w.Body.String())
		}
		return w
	}

	w := issue(svc)
	ck := setSSOCookie(w)
	if ck == nil {
		t.Fatalf("issueAuthorizationCode must set %s; Set-Cookie=%v", ssoCookieName, w.Header().Values("Set-Cookie"))
	}
	if !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" || ck.MaxAge != int(ssoCookieTTL/time.Second) {
		t.Fatalf("cookie attributes: HttpOnly=%v SameSite=%v Path=%q MaxAge=%d", ck.HttpOnly, ck.SameSite, ck.Path, ck.MaxAge)
	}
	if ck.Secure {
		t.Fatal("Secure must follow the environment; this config is not production")
	}
	if ck.Value == sessionID {
		t.Fatal("the cookie must carry an opaque token, not the session id")
	}
	if got, _ := svc.redis.Client.Get(ctx, ssoRedisPrefix+ck.Value).Result(); got != sessionID {
		t.Fatalf("sso_session mapping=%q, want %q", got, sessionID)
	}

	// Round trip: the cookie authorizes the next /authorize for the same user.
	mintedCode(t, db, ssoAuthorize(t, svc, ck.Value, nil), userID)

	// Production: Secure.
	svc.config = &config.Config{ABACEnforce: "off", Environment: "production"}
	if ck := setSSOCookie(issue(svc)); ck == nil || !ck.Secure {
		t.Fatal("in production the cookie must be Secure")
	}

	// No session_id (session creation failed at login): no cookie.
	w = httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/oauth/login", nil).WithContext(orgctx.With(ctx, orgctx.Org{ID: ssoTestOrg}))
	svc.issueAuthorizationCode(c, map[string]string{"client_id": "c", "redirect_uri": ssoTestRedirect, "scope": "openid"}, userID)
	if setSSOCookie(w) != nil {
		t.Fatal("no session, no cookie")
	}
}

// Logout revokes the cookie's session in the database and the revocation
// marker, deletes the mapping, clears the cookie — and the same cookie no
// longer authorizes anything.
func TestLogoutRevokesTheBrowserSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	ctx := context.Background()
	userID := uuid.New().String()
	sessionID, token := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, false)
	mintedCode(t, db, ssoAuthorize(t, svc, token, nil), userID) // it works before logout

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/oauth/logout", nil)
	req.AddCookie(&http.Cookie{Name: ssoCookieName, Value: token})
	c.Request = req.WithContext(orgctx.With(ctx, orgctx.Org{ID: ssoTestOrg}))
	svc.handleLogout(c)
	if w.Code != http.StatusOK {
		t.Fatalf("logout: %d %s", w.Code, w.Body.String())
	}
	if !clearedSSOCookie(w) {
		t.Fatal("logout must clear the SSO cookie")
	}

	var revoked bool
	if err := db.Pool.QueryRow(ctx, `SELECT revoked FROM sessions WHERE id = $1`, sessionID).Scan(&revoked); err != nil || !revoked {
		t.Fatalf("session not revoked in DB (revoked=%v err=%v)", revoked, err)
	}
	if n, _ := svc.redis.Client.Exists(ctx, "revoked_session:"+sessionID).Result(); n != 1 {
		t.Fatal("revocation marker not written")
	}
	if n, _ := svc.redis.Client.Exists(ctx, ssoRedisPrefix+token).Result(); n != 0 {
		t.Fatal("sso_session mapping must be deleted")
	}

	// The browser that ignores Set-Cookie and replays the token gets a login page.
	expectLogin(t, ssoAuthorize(t, svc, token, nil))
	var n int
	_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM oauth_authorization_codes`).Scan(&n)
	if n != 1 {
		t.Fatalf("expected exactly the pre-logout code, found %d", n)
	}
}

// The SSO path runs the assignment gate: an application with
// require_assignment=true refuses an unassigned user's live session under
// enforcement and mints nothing; assigning the user makes the same cookie work.
// TestEveryMintSiteCallsAssignmentGate checks the wiring in source; this
// checks the behaviour.
func TestSSOSessionIsSubjectToTheAssignmentGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	svc.config = &config.Config{ABACEnforce: "off", AccessAssignmentEnforce: true}
	ctx := context.Background()
	userID := uuid.New().String()
	_, token := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, false)

	var appID string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO applications (client_id, org_id, require_assignment) VALUES ('c', $1, true) RETURNING id::text`,
		ssoTestOrg).Scan(&appID); err != nil {
		t.Fatal(err)
	}

	w := ssoAuthorize(t, svc, token, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unassigned user with a live session: expected 403, got %d %s (Location=%s)", w.Code, w.Body.String(), w.Header().Get("Location"))
	}
	var n int
	_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM oauth_authorization_codes`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d codes minted for an unassigned user", n)
	}

	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO user_application_assignments (application_id, user_id, org_id) VALUES ($1, $2, $3)`,
		appID, userID, ssoTestOrg); err != nil {
		t.Fatal(err)
	}
	mintedCode(t, db, ssoAuthorize(t, svc, token, nil), userID)
}
