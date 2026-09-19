package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Single sign-on stopped one screen short. A browser with a live openidx_sso
// session that reached an application still needing consent (or a request
// with prompt=consent) was sent to the login page, and the login page knew
// one way to the consent screen: a password. These tests pin the two halves
// that close the gap — /oauth/authorize marks such a redirect with resume=1,
// and POST /oauth/login/resume completes the pending request from the
// session, refusing exactly what the fast path refuses.

// requireConsent registers client "c" as an application that requires consent.
func requireConsent(t *testing.T, db *database.PostgresDB) {
	t.Helper()
	ctx := context.Background()
	var appID string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO applications (client_id, org_id) VALUES ('c', $1) RETURNING id::text`, ssoTestOrg).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO application_sso_settings (application_id, require_consent) VALUES ($1, true)`, appID); err != nil {
		t.Fatal(err)
	}
}

// loginSessionOf returns the login_session /oauth/authorize put on the login
// URL, and whether it carried the resume hint.
func loginSessionOf(t *testing.T, w *httptest.ResponseRecorder) (loginSession string, resume bool) {
	t.Helper()
	u := locationOf(t, w)
	if u.Path != "/login" {
		t.Fatalf("expected the login UI, got %s", u)
	}
	ls := u.Query().Get("login_session")
	if ls == "" {
		t.Fatalf("no login_session on %s", u)
	}
	return ls, u.Query().Get("resume") == "1"
}

// resumeLogin performs POST /oauth/login/resume under tenant ssoTestOrg.
func resumeLogin(t *testing.T, svc *Service, cookie string, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/oauth/login/resume", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: ssoCookieName, Value: cookie})
	}
	c.Request = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: ssoTestOrg}))
	svc.handleLoginResume(c)
	return w
}

func resumeBody(loginSession string) string {
	raw, _ := json.Marshal(map[string]string{"login_session": loginSession})
	return string(raw)
}

func stashOf(t *testing.T, svc *Service, loginSession string) map[string]string {
	t.Helper()
	raw, err := svc.redis.Client.Get(context.Background(), "login_session:"+loginSession).Result()
	if err != nil {
		t.Fatalf("stash %s: %v", loginSession, err)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// The hint appears exactly when a live session exists and the login page has
// a screen to show; the stash carries prompt/max_age and never the session.
func TestAuthorizeHintsResumeOnlyWhenASessionCanCarryTheUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	requireConsent(t, db)
	userID := uuid.New().String()
	_, live := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, false)
	_, revoked := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, true)

	ls, resume := loginSessionOf(t, ssoAuthorize(t, svc, live, nil))
	if !resume {
		t.Fatal("live session + consent outstanding: the login URL must carry resume=1")
	}
	stash := stashOf(t, svc, ls)
	if stash[resumeHintKey] != "1" || stash["session_id"] != "" {
		t.Fatalf("stash must carry the hint and never the session: %v", stash)
	}

	// Control: no cookie, and a cookie that resolves to nothing, get no hint.
	if _, resume := loginSessionOf(t, ssoAuthorize(t, svc, "", nil)); resume {
		t.Fatal("no cookie: nothing to resume")
	}
	if _, resume := loginSessionOf(t, ssoAuthorize(t, svc, revoked, nil)); resume {
		t.Fatal("revoked session: nothing to resume")
	}
	// prompt=login and select_account ask for the form itself.
	for _, p := range []string{"login", "select_account"} {
		ls, resume := loginSessionOf(t, ssoAuthorize(t, svc, live, url.Values{"prompt": {p}}))
		if resume {
			t.Fatalf("prompt=%s with a live session must not be resumed", p)
		}
		if got := stashOf(t, svc, ls)["prompt"]; got != p {
			t.Fatalf("stash must carry prompt=%s, got %q", p, got)
		}
	}
	// max_age travels too.
	ls, _ = loginSessionOf(t, ssoAuthorize(t, svc, live, url.Values{"max_age": {"60"}}))
	if got := stashOf(t, svc, ls)["max_age"]; got != "60" {
		t.Fatalf("stash must carry max_age=60, got %q", got)
	}

	var n int
	_ = db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM oauth_authorization_codes`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d codes minted while consent was outstanding", n)
	}
}

// prompt=consent with a live session and consent ON RECORD: no mint, resume
// hint — the screen is shown again, the password is not asked again.
func TestAuthorizePromptConsentResumesInsteadOfMintingOrReauthenticating(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	requireConsent(t, db)
	userID := uuid.New().String()
	_, live := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, false)
	if _, err := db.Pool.Exec(context.Background(),
		`INSERT INTO oauth_user_consents (org_id, user_id, client_id, scopes) VALUES ($1, $2, 'c', 'openid profile email')`,
		ssoTestOrg, userID); err != nil {
		t.Fatal(err)
	}
	// Consent recorded: the plain request mints.
	mintedCode(t, db, ssoAuthorize(t, svc, live, nil), userID)

	ls, resume := loginSessionOf(t, ssoAuthorize(t, svc, live, url.Values{"prompt": {"consent"}}))
	if !resume {
		t.Fatal("prompt=consent with a live session must be resumed, not re-authenticated")
	}
	// Resume shows the consent screen although consent is on record.
	w := resumeLogin(t, svc, live, resumeBody(ls))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"consent_required":true`) {
		t.Fatalf("prompt=consent resume: want the consent challenge, got %d %s", w.Code, w.Body.String())
	}
	var n int
	_ = db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM oauth_authorization_codes`).Scan(&n)
	if n != 1 {
		t.Fatalf("prompt=consent must not mint before the decision: %d codes", n)
	}
}

// The resume completes the pending request from the session: the consent
// challenge, then — through the ordinary decision — the code bound to that
// session; the login_session is consumed on the way.
func TestLoginResumeCompletesFromTheBrowserSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	requireConsent(t, db)
	ctx := context.Background()
	userID := uuid.New().String()
	sessionID, live := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, false)

	ls, _ := loginSessionOf(t, ssoAuthorize(t, svc, live, nil))
	w := resumeLogin(t, svc, live, resumeBody(ls))
	if w.Code != http.StatusOK {
		t.Fatalf("resume: %d %s", w.Code, w.Body.String())
	}
	var challenge struct {
		ConsentRequired bool     `json:"consent_required"`
		ConsentSession  string   `json:"consent_session"`
		ClientID        string   `json:"client_id"`
		Scopes          []string `json:"scopes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &challenge); err != nil || !challenge.ConsentRequired || challenge.ConsentSession == "" || challenge.ClientID != "c" {
		t.Fatalf("want a consent challenge for client c, got %s", w.Body.String())
	}
	if len(challenge.Scopes) != 1 || challenge.Scopes[0] != "openid" {
		t.Fatalf("scopes=%v, want [openid]", challenge.Scopes)
	}
	// The stash behind the challenge names the SESSION's user — nobody else.
	raw, _ := svc.redis.Client.Get(ctx, "oauth_consent:"+challenge.ConsentSession).Result()
	if !strings.Contains(raw, `"user_id":"`+userID+`"`) || !strings.Contains(raw, `"session_id":"`+sessionID+`"`) {
		t.Fatalf("consent stash must carry the session's user and the session: %s", raw)
	}
	// The pending login is consumed: a second resume finds nothing.
	if w := resumeLogin(t, svc, live, resumeBody(ls)); w.Code != http.StatusBadRequest {
		t.Fatalf("second resume of a consumed login_session: want 400, got %d %s", w.Code, w.Body.String())
	}

	// Approve through the ordinary decision endpoint: the code is minted for
	// the session's user and bound to the session, no password anywhere.
	dw := httptest.NewRecorder()
	dc, _ := gin.CreateTestContext(dw)
	dreq := httptest.NewRequest(http.MethodPost, "/oauth/consent",
		strings.NewReader(`{"consent_session":"`+challenge.ConsentSession+`","approve":true}`))
	dreq.Header.Set("Content-Type", "application/json")
	dc.Request = dreq.WithContext(orgctx.With(ctx, orgctx.Org{ID: ssoTestOrg}))
	svc.handleConsentDecision(dc)
	if dw.Code != http.StatusOK {
		t.Fatalf("consent decision: %d %s", dw.Code, dw.Body.String())
	}
	var decision struct {
		RedirectURL string `json:"redirect_url"`
	}
	_ = json.Unmarshal(dw.Body.Bytes(), &decision)
	ru, err := url.Parse(decision.RedirectURL)
	if err != nil || ru.Host != "app.example.test" || ru.Query().Get("code") == "" || ru.Query().Get("state") != "st-1" {
		t.Fatalf("redirect_url=%q: want the client's redirect_uri with code and state", decision.RedirectURL)
	}
	code := ru.Query().Get("code")
	var gotUser string
	if err := db.Pool.QueryRow(ctx, `SELECT user_id::text FROM oauth_authorization_codes WHERE code=$1 AND org_id=$2`, code, ssoTestOrg).Scan(&gotUser); err != nil || gotUser != userID {
		t.Fatalf("code user=%q err=%v, want %s", gotUser, err, userID)
	}
	if got, _ := svc.redis.Client.Get(ctx, "authcode_session:"+code).Result(); got != sessionID {
		t.Fatalf("authcode_session=%q, want the browser session %q", got, sessionID)
	}
}

// No consent outstanding (the client never required it): the resume mints
// directly — the shape a client that turned consent OFF between the
// redirect and the resume would see — bound to the session, cookie refreshed.
func TestLoginResumeMintsWhenNothingIsOutstanding(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	requireConsent(t, db)
	ctx := context.Background()
	userID := uuid.New().String()
	sessionID, live := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, false)
	ls, _ := loginSessionOf(t, ssoAuthorize(t, svc, live, nil))
	// Consent recorded meanwhile (another tab approved it).
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO oauth_user_consents (org_id, user_id, client_id, scopes) VALUES ($1, $2, 'c', 'openid')`,
		ssoTestOrg, userID); err != nil {
		t.Fatal(err)
	}

	w := resumeLogin(t, svc, live, resumeBody(ls))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"redirect_url"`) {
		t.Fatalf("resume with consent on record: want redirect_url, got %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		RedirectURL string `json:"redirect_url"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	ru, _ := url.Parse(resp.RedirectURL)
	code := ru.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", resp.RedirectURL)
	}
	if got, _ := svc.redis.Client.Get(ctx, "authcode_session:"+code).Result(); got != sessionID {
		t.Fatalf("authcode_session=%q, want %q", got, sessionID)
	}
	if setSSOCookie(w) == nil {
		t.Fatal("a completion refreshes the openidx_sso cookie like every other")
	}
}

// Everything the fast path refuses, the resume refuses: no cookie, a stale
// cookie (cleared), another tenant's session, a request that asked for the
// form, a session older than max_age, and a login_session nobody wrote.
func TestLoginResumeRefusesWhatTheFastPathRefuses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	requireConsent(t, db)
	ctx := context.Background()
	userID := uuid.New().String()
	_, live := ssoSession(t, svc, db, ssoTestOrg, userID, 2*time.Hour, 20*time.Hour, false)
	_, revoked := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, true)
	_, elsewhere := ssoSession(t, svc, db, ssoOtherOrg, userID, time.Minute, time.Hour, false)

	expectLoginRequired := func(t *testing.T, w *httptest.ResponseRecorder, what string) {
		t.Helper()
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), ErrorLoginRequired) {
			t.Fatalf("%s: want 401 login_required, got %d %s", what, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: a refusal is not cacheable", what)
		}
	}

	ls, _ := loginSessionOf(t, ssoAuthorize(t, svc, live, nil))
	expectLoginRequired(t, resumeLogin(t, svc, "", resumeBody(ls)), "no cookie")
	w := resumeLogin(t, svc, revoked, resumeBody(ls))
	expectLoginRequired(t, w, "revoked session")
	if !clearedSSOCookie(w) {
		t.Fatal("a cookie that resolves to nothing is cleared")
	}
	w = resumeLogin(t, svc, elsewhere, resumeBody(ls))
	expectLoginRequired(t, w, "another tenant's session")
	// The refusals did not consume the pending login: the form can still use it.
	stashOf(t, svc, ls)

	// The request asked for the form itself.
	for _, p := range []string{"login", "select_account"} {
		ls, _ := loginSessionOf(t, ssoAuthorize(t, svc, live, url.Values{"prompt": {p}}))
		expectLoginRequired(t, resumeLogin(t, svc, live, resumeBody(ls)), "prompt="+p)
	}
	// The session (2h old) is older than the request's max_age.
	ls, _ = loginSessionOf(t, ssoAuthorize(t, svc, live, url.Values{"max_age": {"60"}}))
	expectLoginRequired(t, resumeLogin(t, svc, live, resumeBody(ls)), "max_age exceeded")

	// A login_session nobody wrote, a malformed one, and no body at all.
	if w := resumeLogin(t, svc, live, resumeBody(GenerateRandomToken(32))); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown login_session: want 400, got %d %s", w.Code, w.Body.String())
	}
	if w := resumeLogin(t, svc, live, resumeBody("not a token")); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed login_session: want 400, got %d %s", w.Code, w.Body.String())
	}
	if w := resumeLogin(t, svc, live, `{}`); w.Code != http.StatusBadRequest {
		t.Fatalf("missing login_session: want 400, got %d %s", w.Code, w.Body.String())
	}

	var n int
	_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM oauth_authorization_codes`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d codes minted across refused resumes", n)
	}
	if keys, _ := svc.redis.Client.Keys(ctx, "oauth_consent:*").Result(); len(keys) != 0 {
		t.Fatalf("consent challenges issued across refused resumes: %v", keys)
	}
}

// The v2 endpoint stashes the same way, so its login page can resume too.
func TestAuthorizeV2HintsResumeAndStashesPrompt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	requireConsent(t, db)
	userID := uuid.New().String()
	_, live := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, false)

	ls, resume := loginSessionOf(t, v2Authorize(t, svc, live, nil))
	if !resume {
		t.Fatal("v2: live session + consent outstanding must carry resume=1")
	}
	if stash := stashOf(t, svc, ls); stash[resumeHintKey] != "1" || stash["session_id"] != "" || stash["client_id"] != "c" {
		t.Fatalf("v2 stash: %v", stash)
	}
	ls, resume = loginSessionOf(t, v2Authorize(t, svc, live, url.Values{"prompt": {"login"}, "max_age": {"30"}}))
	if resume {
		t.Fatal("v2 prompt=login must not be resumed")
	}
	if stash := stashOf(t, svc, ls); stash["prompt"] != "login" || stash["max_age"] != "30" {
		t.Fatalf("v2 stash must carry prompt and max_age: %v", stash)
	}
	// And the resume endpoint completes a v2-originated request the same way.
	ls, _ = loginSessionOf(t, v2Authorize(t, svc, live, nil))
	if w := resumeLogin(t, svc, live, resumeBody(ls)); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"consent_required":true`) {
		t.Fatalf("v2 resume: want the consent challenge, got %d %s", w.Code, w.Body.String())
	}
}
