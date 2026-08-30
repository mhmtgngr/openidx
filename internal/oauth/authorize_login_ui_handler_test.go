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
// database, backed by miniredis, for one test case.
func newLoginUITestService(t *testing.T, oauthLoginUI string, client *OAuthClient) *Service {
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
		config:  &config.Config{OAuthLoginUI: oauthLoginUI},
		logger:  zap.NewNop(),
	}
}

// TestHandleAuthorizeBranchSelection runs handleAuthorize end-to-end (not
// source inspection — the reason "the full suite passes" wasn't evidence
// before) across (OAuthLoginUI, client.Type, Accept header) combinations. It
// pins two things a code reading alone can get wrong:
//
//  1. The default/unset/typo'd flag value must behave EXACTLY like the
//     explicit "server" value — never like "spa" — for every client type.
//     This is what makes an env-var typo fail toward today's behaviour
//     instead of silently stranding a public client like BrowZer.
//  2. Only the literal "spa" value turns off the server-rendered page and
//     sends every client (including one with a custom-scheme redirect_uri)
//     to the issuer's own /login.
func TestHandleAuthorizeBranchSelection(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const redirectURI = "openidx://oauth-callback"
	publicClient := &OAuthClient{ClientID: "test-client", Type: "public", RedirectURIs: []string{redirectURI}}
	confidentialClient := &OAuthClient{ClientID: "test-client", Type: "confidential", RedirectURIs: []string{redirectURI}}

	cases := []struct {
		name           string
		oauthLoginUI   string
		client         *OAuthClient
		acceptHeader   string
		wantRendered   bool // server-rendered login page (200 HTML form)
		wantIssuerHost bool // 302 Location targets the issuer's own /login
	}{
		{"default(unset)+public+browser", "", publicClient, "", true, false},
		{"server+public+browser", "server", publicClient, "", true, false},
		{"typo(Server)+public+browser", "Server", publicClient, "", true, false},
		{"server+public+json", "server", publicClient, "application/json", false, false},
		{"server+confidential+browser", "server", confidentialClient, "", false, false},
		{"spa+public+browser", "spa", publicClient, "", false, true},
		{"spa+confidential+browser", "spa", confidentialClient, "", false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newLoginUITestService(t, tc.oauthLoginUI, tc.client)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			q := url.Values{
				"client_id":     {tc.client.ClientID},
				"redirect_uri":  {redirectURI},
				"response_type": {"code"},
			}
			c.Request = httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
			if tc.acceptHeader != "" {
				c.Request.Header.Set("Accept", tc.acceptHeader)
			}

			svc.handleAuthorize(c)

			if tc.wantRendered {
				if w.Code != http.StatusOK {
					t.Fatalf("expected server-rendered page (200), got %d body=%s", w.Code, w.Body.String())
				}
				if !strings.Contains(w.Body.String(), `action="/oauth/authorize/callback"`) {
					t.Errorf("expected the server-rendered login form, got body=%s", w.Body.String())
				}
				return
			}

			if w.Code != http.StatusFound {
				t.Fatalf("expected redirect (302), got %d body=%s", w.Code, w.Body.String())
			}
			location := w.Header().Get("Location")
			loc, err := url.Parse(location)
			if err != nil {
				t.Fatalf("Location not a URL: %v", err)
			}
			if loc.Query().Get("login_session") == "" {
				t.Errorf("redirect missing login_session: %q", location)
			}
			gotIssuerHost := loc.Host == "openidx.tdv.org" && loc.Path == "/login"
			if gotIssuerHost != tc.wantIssuerHost {
				t.Errorf("issuer-host redirect = %v, want %v (Location=%q)", gotIssuerHost, tc.wantIssuerHost, location)
			}
			if !tc.wantIssuerHost {
				// Must go back to the CLIENT's own redirect_uri (custom scheme
				// preserved), never to the issuer's /login.
				if loc.Scheme != "openidx" || loc.Host != "oauth-callback" {
					t.Errorf("expected redirect back to client's own redirect_uri, got %q", location)
				}
			}
		})
	}
}
