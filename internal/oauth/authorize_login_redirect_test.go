package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// fakeOAuthClientStoreForLoginUI is a minimal in-memory OAuthClientStore for
// exercising handleAuthorize's branch selection without a database.
type fakeOAuthClientStoreForLoginUI struct {
	client *OAuthClient
}

func (f *fakeOAuthClientStoreForLoginUI) GetByClientID(_ context.Context, clientID string) (*OAuthClient, error) {
	if f.client == nil || f.client.ClientID != clientID {
		return nil, ErrOAuthClientNotFound
	}
	return f.client, nil
}
func (f *fakeOAuthClientStoreForLoginUI) List(_ context.Context, _, _ int) ([]OAuthClient, int, error) {
	return nil, 0, nil
}
func (f *fakeOAuthClientStoreForLoginUI) Create(_ context.Context, _ *OAuthClient) error { return nil }
func (f *fakeOAuthClientStoreForLoginUI) Update(_ context.Context, _ string, _ *OAuthClient) error {
	return nil
}
func (f *fakeOAuthClientStoreForLoginUI) Delete(_ context.Context, _ string) error { return nil }

// newLoginUITestService builds a handleAuthorize-capable Service with no
// database, backed by miniredis, for one test case. loginURL is
// OAUTH_LOGIN_URL; empty means "derive it from the issuer".
func newLoginUITestService(t *testing.T, loginURL string, client *OAuthClient) *Service {
	t.Helper()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() {
		rdb.Close()
		mini.Close()
	})

	return &Service{
		issuer:  "https://openidx.tdv.org",
		redis:   &database.RedisClient{Client: rdb},
		clients: &fakeOAuthClientStoreForLoginUI{client: client},
		config:  &config.Config{OAuthLoginURL: loginURL},
		logger:  zap.NewNop(),
	}
}

// TestHandleAuthorizeRedirectsEveryClientToTheOneLoginUI replaces
// TestHandleAuthorizeBranchSelection, which pinned the branch this deletes.
//
// That test asserted that the default and any unrecognised OAUTH_LOGIN_UI
// value served a server-rendered HTML login form to a public client, and that
// a confidential client was redirected BACK to its own redirect_uri with
// ?login_session= — a shape only a client hosting its own login page could
// use. Both are gone: there is one login UI, every client goes to it, and a
// native client with a custom-scheme redirect_uri (which cannot host a page at
// all) is the reason that has to be true.
func TestHandleAuthorizeRedirectsEveryClientToTheOneLoginUI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const nativeRedirect = "openidx://oauth-callback"
	const webRedirect = "https://app.example.test/callback"

	cases := []struct {
		name        string
		loginURL    string // OAUTH_LOGIN_URL; empty derives from the issuer
		client      *OAuthClient
		redirectURI string
		accept      string
		wantHost    string
		wantPath    string
	}{
		{
			name:        "public browser client",
			client:      &OAuthClient{ClientID: "c", Type: "public", RedirectURIs: []string{webRedirect}},
			redirectURI: webRedirect,
			wantHost:    "openidx.tdv.org", wantPath: "/login",
		},
		{
			name:        "confidential client",
			client:      &OAuthClient{ClientID: "c", Type: "confidential", RedirectURIs: []string{webRedirect}},
			redirectURI: webRedirect,
			wantHost:    "openidx.tdv.org", wantPath: "/login",
		},
		{
			// The case the server-rendered page existed for. It must NOT be
			// sent to openidx://oauth-callback?login_session= — nothing serves
			// a page there.
			name:        "native client with a custom-scheme redirect_uri",
			client:      &OAuthClient{ClientID: "c", Type: "public", RedirectURIs: []string{nativeRedirect}},
			redirectURI: nativeRedirect,
			wantHost:    "openidx.tdv.org", wantPath: "/login",
		},
		{
			// An Accept: application/json header used to select a different
			// branch. It selects nothing now.
			name:        "Accept: application/json is not a branch",
			client:      &OAuthClient{ClientID: "c", Type: "public", RedirectURIs: []string{webRedirect}},
			redirectURI: webRedirect,
			accept:      "application/json",
			wantHost:    "openidx.tdv.org", wantPath: "/login",
		},
		{
			// The compose reference deployment: console and issuer on
			// different origins, so the login page cannot be derived from the
			// issuer.
			name:        "OAUTH_LOGIN_URL overrides the issuer-derived default",
			loginURL:    "http://localhost:3000/login",
			client:      &OAuthClient{ClientID: "c", Type: "public", RedirectURIs: []string{webRedirect}},
			redirectURI: webRedirect,
			wantHost:    "localhost:3000", wantPath: "/login",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newLoginUITestService(t, tc.loginURL, tc.client)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			q := url.Values{
				"client_id":     {tc.client.ClientID},
				"redirect_uri":  {tc.redirectURI},
				"response_type": {"code"},
			}
			c.Request = httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
			if tc.accept != "" {
				c.Request.Header.Set("Accept", tc.accept)
			}

			svc.handleAuthorize(c)

			if w.Code != http.StatusFound {
				t.Fatalf("expected a 302 to the login UI, got %d body=%s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "<form") {
				t.Fatalf("a server-rendered login form came back; the page must stay deleted:\n%s", w.Body.String())
			}
			loc, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatalf("Location is not a URL: %v", err)
			}
			if loc.Host != tc.wantHost || loc.Path != tc.wantPath {
				t.Errorf("redirected to %s%s, want %s%s", loc.Host, loc.Path, tc.wantHost, tc.wantPath)
			}
			session := loc.Query().Get("login_session")
			if session == "" {
				t.Fatalf("redirect carries no login_session: %q", w.Header().Get("Location"))
			}
			// The session the login endpoint will read must exist, or the
			// redirect sends the user to a page that immediately fails.
			if _, err := svc.redis.Client.Get(c.Request.Context(), "login_session:"+session).Result(); err != nil {
				t.Errorf("login_session:%s was not written before the redirect: %v", session, err)
			}
		})
	}
}
