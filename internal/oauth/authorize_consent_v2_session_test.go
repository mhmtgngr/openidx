package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// POST /oauth/authorize/v2 accepts a client-supplied session_id "for
// linkage". Until this file existed that id was bound to the code unverified,
// and the token endpoint then read sid, amr and auth_time from whatever
// session row it named — scoped to the tenant, not to the user. The access
// service trusts amr to decide whether MFA happened, so an authenticated user
// who knew another user's session id could mint tokens for themselves that
// said so. Only the caller's own live session may be bound; anything else is
// refused, loudly.

// consentV2 posts to the handler as the authenticated user X, with a stored
// auth request, and the given session_id (empty means omitted).
func consentV2(t *testing.T, svc *Service, userID, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: ssoTestOrg})
	svc.authorizeHandler = NewAuthorizeHandler(svc, zap.NewNop())
	authSession := GenerateRandomToken(32)
	if err := svc.authorizeHandler.storeAuthorizationRequest(ctx, authSession, &AuthorizeRequest{
		ClientID: "c", RedirectURI: ssoTestRedirect, ResponseType: "code", Scope: "openid", State: "st-1",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod: "S256",
	}, ssoTestClient()); err != nil {
		t.Fatal(err)
	}
	body := map[string]string{"auth_session": authSession}
	if sessionID != "" {
		body["session_id"] = sessionID
	}
	raw, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize/v2", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req.WithContext(ctx)
	c.Set("user_id", userID) // what flowAuth binds from the bearer
	svc.handleAuthorizeConsentV2(c)
	return w
}

func codesMinted(t *testing.T, svc *Service) int {
	t.Helper()
	var n int
	if err := svc.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM oauth_authorization_codes`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestConsentV2RefusesAnotherUsersSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	x, y := uuid.New().String(), uuid.New().String()
	ySession, _ := ssoSession(t, svc, db, ssoTestOrg, y, time.Minute, time.Hour, false)

	w := consentV2(t, svc, x, ySession)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "not a live session of the authenticated user") {
		t.Fatalf("X binding Y's session: want 400 invalid_request, got %d %s", w.Code, w.Body.String())
	}
	if n := codesMinted(t, svc); n != 0 {
		t.Fatalf("%d codes minted for a refused request", n)
	}
	if keys, _ := svc.redis.Client.Keys(context.Background(), "authcode_session:*").Result(); len(keys) != 0 {
		t.Fatalf("a session binding was written for a refused request: %v", keys)
	}

	// The same shape for X's own session once it is revoked, and for an id
	// that is not a session at all.
	revoked, _ := ssoSession(t, svc, db, ssoTestOrg, x, time.Minute, time.Hour, true)
	if w := consentV2(t, svc, x, revoked); w.Code != http.StatusBadRequest {
		t.Fatalf("revoked own session: want 400, got %d %s", w.Code, w.Body.String())
	}
	if w := consentV2(t, svc, x, uuid.New().String()); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown session id: want 400, got %d %s", w.Code, w.Body.String())
	}
	if w := consentV2(t, svc, x, "not a session id"); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed session id: want 400, got %d %s", w.Code, w.Body.String())
	}
	// X's own live session in ANOTHER tenant is not X's session here: the
	// check is tenant-scoped like every other session read.
	elsewhere, _ := ssoSession(t, svc, db, ssoOtherOrg, x, time.Minute, time.Hour, false)
	if w := consentV2(t, svc, x, elsewhere); w.Code != http.StatusBadRequest {
		t.Fatalf("own session in another tenant: want 400, got %d %s", w.Code, w.Body.String())
	}
	if n := codesMinted(t, svc); n != 0 {
		t.Fatalf("%d codes minted across refused requests", n)
	}
}

// The caller's own live session binds as before, and a request with no
// session_id is unchanged.
func TestConsentV2BindsOnlyTheCallersOwnLiveSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	x := uuid.New().String()
	own, _ := ssoSession(t, svc, db, ssoTestOrg, x, time.Minute, time.Hour, false)

	w := consentV2(t, svc, x, own)
	if w.Code != http.StatusOK {
		t.Fatalf("own live session: want 200, got %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		RedirectURL string `json:"redirect_url"`
		Code        string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Code == "" {
		t.Fatalf("response: %v %s", err, w.Body.String())
	}
	if got, _ := svc.redis.Client.Get(context.Background(), "authcode_session:"+resp.Code).Result(); got != own {
		t.Fatalf("authcode_session=%q, want the caller's session %q", got, own)
	}
	// The success path used to re-read the stored request AFTER the mint had
	// consumed it and answer 500 every time; the redirect must carry the code.
	if !strings.HasPrefix(resp.RedirectURL, ssoTestRedirect+"?") || !strings.Contains(resp.RedirectURL, "code="+resp.Code) || !strings.Contains(resp.RedirectURL, "state=st-1") {
		t.Fatalf("redirect_url=%q: want the client's redirect_uri with the code and state", resp.RedirectURL)
	}

	// No session_id: the code is issued with no binding, exactly as before.
	w = consentV2(t, svc, x, "")
	if w.Code != http.StatusOK {
		t.Fatalf("no session_id: want 200, got %d %s", w.Code, w.Body.String())
	}
	if n := codesMinted(t, svc); n != 2 {
		t.Fatalf("want 2 codes, got %d", n)
	}
}

// Nil-safe: no database, no tenant, blank ids all answer false.
func TestSessionBelongsToGuards(t *testing.T) {
	s := &Service{}
	ctx := context.Background()
	for _, tc := range [][2]string{{"", "u"}, {uuid.New().String(), ""}, {"garbage", "u"}, {uuid.New().String(), "u"}} {
		if s.sessionBelongsTo(ctx, tc[0], tc[1]) {
			t.Errorf("sessionBelongsTo(%q,%q) = true without a database", tc[0], tc[1])
		}
	}
}
