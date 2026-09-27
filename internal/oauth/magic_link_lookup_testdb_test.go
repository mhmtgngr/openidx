package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/identity"
)

// A MAGIC LINK IS FOUND BY ITS DIGEST, IN THE ORGANIZATION OF ITS SIGN-IN.
//
// GET /oauth/magic-link-verify is unauthenticated. It read every pending link
// of every organization and bcrypt-compared the token with each, so every
// request cost a quarter of a second of CPU per pending link in the install,
// and a link was accepted from whichever organization had minted it, to finish
// a sign-in started for any organization's application. The link is now found
// by the SHA-256 of its token (migration v208), in the organization the
// request resolved to, and the pending sign-in must be for an application of
// that organization too; POST /oauth/magic-link sends the link to the
// organization's own host, where the request resolves to it.
//
// Driven through RegisterRoutes as cmd/oauth-service wires it -- the tenant
// resolver in front, reading the X-Org-Slug the gateway derives from a
// tenant's host -- over a migrated database, with the real identity service.

// linkMailer stands in for the SMTP service and keeps the sign-in links it is
// asked to send.
type linkMailer struct {
	mu    sync.Mutex
	links []string
}

func (m *linkMailer) SendVerificationEmail(context.Context, string, string, string, string) error {
	return nil
}
func (m *linkMailer) SendInvitationEmail(context.Context, string, string, string, string) error {
	return nil
}
func (m *linkMailer) SendPasswordResetEmail(context.Context, string, string, string, string) error {
	return nil
}
func (m *linkMailer) SendWelcomeEmail(context.Context, string, string, string) error { return nil }
func (m *linkMailer) SendAsync(_ context.Context, _, _, _ string, data map[string]interface{}) error {
	if link, ok := data["MagicLinkURL"].(string); ok {
		m.mu.Lock()
		m.links = append(m.links, link)
		m.mu.Unlock()
	}
	return nil
}

func (m *linkMailer) last() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.links) == 0 {
		return ""
	}
	return m.links[len(m.links)-1]
}

type magicLinkHarness struct {
	*tokenHarness
	api    *gin.Engine
	mailer *linkMailer
}

func newMagicLinkHarness(t *testing.T) *magicLinkHarness {
	h := newTokenHarness(t)
	idSvc := identity.NewService(h.db, h.issuer.redis, &config.Config{
		Environment: "production", OAuthIssuer: h.issuer.issuer, OAuthJWKSURL: h.jwksURL,
	}, zap.NewNop())
	mailer := &linkMailer{}
	idSvc.SetEmailService(mailer)
	h.issuer.identityService = idSvc
	// Subdomain tenancy: each organization's host is <slug>.idp.test.
	h.issuer.tenantBaseDomain = "idp.test"
	return &magicLinkHarness{tokenHarness: h, api: h.oauthRouteTable(nil), mailer: mailer}
}

// loginSession starts a pending sign-in to clientID, as /oauth/authorize does.
func (m *magicLinkHarness) loginSession(clientID string) string {
	m.t.Helper()
	id := GenerateRandomToken(32)
	params, _ := json.Marshal(map[string]string{
		"client_id": clientID, "redirect_uri": "https://app.example.test/callback",
		"response_type": "code", "scope": "openid", "state": "st-1",
	})
	if err := m.issuer.redis.Client.Set(context.Background(), "login_session:"+id, params, 10*time.Minute).Err(); err != nil {
		m.t.Fatalf("seed login session: %v", err)
	}
	return id
}

// requestLink asks for a sign-in link on the host of the organization slug
// names ("" for the default), and returns the link that was emailed.
func (m *magicLinkHarness) requestLink(email, loginSession, slug string) *url.URL {
	m.t.Helper()
	before := m.mailer.last()
	body, _ := json.Marshal(map[string]string{"email": email, "login_session": loginSession})
	req := httptest.NewRequest(http.MethodPost, "/oauth/magic-link", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if slug != "" {
		req.Header.Set("X-Org-Slug", slug)
	}
	w := httptest.NewRecorder()
	m.api.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		m.t.Fatalf("request a link: status %d %s", w.Code, w.Body.String())
	}
	sent := m.mailer.last()
	if sent == "" || sent == before {
		m.t.Fatal("no link was emailed")
	}
	u, err := url.Parse(sent)
	if err != nil {
		m.t.Fatalf("parse the link %q: %v", sent, err)
	}
	return u
}

// follow opens a verify URL on the host of the organization slug names, and
// returns where it redirects.
func (m *magicLinkHarness) follow(token, loginSession, slug string) *url.URL {
	m.t.Helper()
	q := url.Values{"token": {token}, "login_session": {loginSession}}
	req := httptest.NewRequest(http.MethodGet, "/oauth/magic-link-verify?"+q.Encode(), nil)
	if slug != "" {
		req.Header.Set("X-Org-Slug", slug)
	}
	w := httptest.NewRecorder()
	m.api.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		m.t.Fatalf("verify: status %d %s, want a redirect", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		m.t.Fatalf("bad Location %q: %v", w.Header().Get("Location"), err)
	}
	return loc
}

func (m *magicLinkHarness) codes(userID string) int {
	m.t.Helper()
	var n int
	if err := m.db.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM oauth_authorization_codes WHERE user_id = $1::uuid`, userID).Scan(&n); err != nil {
		m.t.Fatalf("count codes: %v", err)
	}
	return n
}

func (m *magicLinkHarness) linkStatus(userID string) string {
	m.t.Helper()
	return m.scalar(`SELECT string_agg(status, ',' ORDER BY created_at) FROM magic_links WHERE user_id = $1::uuid`, userID)
}

func refusedLink(t *testing.T, loc *url.URL) {
	t.Helper()
	if loc.Path != "/login" || loc.Query().Get("error") != "invalid_magic_link" {
		t.Fatalf("want the login page with error=invalid_magic_link, got %s", loc)
	}
}

func TestAMagicLinkWorksOnlyInTheOrganizationOfItsSignIn(t *testing.T) {
	m := newMagicLinkHarness(t)
	orgB := m.seedOrg("links")
	clientB := m.registerClient(orgB, "links-app", false)
	userB := m.seedUser(orgB.ID, "link-b")
	emailB := m.scalar(`SELECT email FROM users WHERE id = $1::uuid`, userB)

	sessionB := m.loginSession(clientB)
	link := m.requestLink(emailB, sessionB, orgB.Slug)
	if want := orgB.Slug + ".idp.test"; link.Host != want {
		t.Fatalf("the link goes to %q, want its organization's own host %q", link.Host, want)
	}
	token := link.Query().Get("token")
	if token == "" || link.Query().Get("login_session") != sessionB {
		t.Fatalf("the link does not carry the token and the pending sign-in: %s", link)
	}

	// On the default organization's host, completing a sign-in to one of its
	// applications: the link is not found there.
	refusedLink(t, m.follow(token, m.loginSession("admin-console"), ""))
	// On its own host, completing a sign-in to another organization's
	// application: refused before the link is looked at.
	refusedLink(t, m.follow(token, m.loginSession("admin-console"), orgB.Slug))
	// With its own sign-in, on another organization's host.
	refusedLink(t, m.follow(token, sessionB, ""))

	if n := m.codes(userB); n != 0 {
		t.Fatalf("%d authorization codes minted by refused links, want 0", n)
	}
	if st := m.linkStatus(userB); st != "pending" {
		t.Fatalf("the link is %q after the refusals, want pending: a link presented in the wrong place is not spent", st)
	}

	// The other side: its own host, its own sign-in.
	loc := m.follow(token, sessionB, orgB.Slug)
	if loc.Host != "app.example.test" || loc.Query().Get("code") == "" {
		t.Fatalf("want a code for the application, got %s", loc)
	}
	if n := m.codes(userB); n != 1 {
		t.Fatalf("%d authorization codes minted, want 1", n)
	}
	if client := m.scalar(`SELECT client_id FROM oauth_authorization_codes WHERE user_id = $1::uuid`, userB); client != clientB {
		t.Fatalf("the code was minted for %q, want %q", client, clientB)
	}
}

func TestAMagicLinkIsFoundByItsDigestNotBySearching(t *testing.T) {
	m := newMagicLinkHarness(t)
	ctx := context.Background()
	user := m.seedUser(middleware.DefaultOrgID, "link-legacy")
	email := m.scalar(`SELECT email FROM users WHERE id = $1::uuid`, user)

	// A link minted before v208: a bcrypt hash and no digest. The search found
	// it; the lookup does not, and it is left alone.
	const legacyToken = "a-link-minted-before-the-lookup-existed-0123456789"
	hash, err := bcrypt.GenerateFromPassword([]byte(legacyToken), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	m.exec(`INSERT INTO magic_links (org_id, user_id, email, token_hash, purpose, status, expires_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, 'login', 'pending', NOW() + INTERVAL '15 minutes')`,
		middleware.DefaultOrgID, user, email, string(hash))
	refusedLink(t, m.follow(legacyToken, m.loginSession("admin-console"), ""))
	if n := m.codes(user); n != 0 {
		t.Fatalf("a link with no digest signed in (%d codes)", n)
	}
	if st := m.linkStatus(user); st != "pending" {
		t.Fatalf("the link minted before v208 is %q after the refusal, want pending (untouched)", st)
	}

	// The cost of a refusal does not grow with the pending links in the
	// install. Forty links of another organization, each with a real cost-12
	// bcrypt hash: a verifier that compared the token with each would spend
	// forty comparisons on one request.
	other := m.seedOrg("pending-links")
	otherUser := m.seedUser(other.ID, "pending-owner")
	costly, err := bcrypt.GenerateFromPassword([]byte("some other token"), 12)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	for i := 0; i < 40; i++ {
		m.exec(`INSERT INTO magic_links (org_id, user_id, email, token_hash, purpose, status, expires_at)
			VALUES ($1::uuid, $2::uuid, 'pending-owner@example.test', $3, 'login', 'pending', NOW() + INTERVAL '15 minutes')`,
			other.ID, otherUser, string(costly))
	}
	start := time.Now()
	_ = bcrypt.CompareHashAndPassword(costly, []byte("a guess"))
	one := time.Since(start)

	start = time.Now()
	refusedLink(t, m.follow("a-guessed-token-that-matches-nothing-0123456789", m.loginSession("admin-console"), ""))
	if took := time.Since(start); took > 10*one {
		t.Fatalf("an unknown token took %v to refuse; one bcrypt comparison takes %v, so it was compared with the pending links", took, one)
	}

	// And a link minted now is found and signs in; minting it retired the
	// old one, as a new link always retires the outstanding ones.
	sessionID := m.loginSession("admin-console")
	link := m.requestLink(email, sessionID, "")
	if loc := m.follow(link.Query().Get("token"), sessionID, ""); loc.Query().Get("code") == "" {
		t.Fatalf("a link minted after v208 did not sign in: %s", loc)
	}
	var lookup string
	if err := m.db.Pool.QueryRow(ctx, `SELECT token_lookup FROM magic_links WHERE user_id = $1::uuid AND status = 'used'`,
		user).Scan(&lookup); err != nil || len(lookup) != 64 {
		t.Fatalf("the link minted after v208 stored lookup %q (%v), want a SHA-256 digest", lookup, err)
	}
}

func TestConcurrentUsesOfOneMagicLinkSignInOnce(t *testing.T) {
	m := newMagicLinkHarness(t)
	user := m.seedUser(middleware.DefaultOrgID, "link-race")
	email := m.scalar(`SELECT email FROM users WHERE id = $1::uuid`, user)
	sessionID := m.loginSession("admin-console")
	link := m.requestLink(email, sessionID, "")
	token := link.Query().Get("token")

	const n = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	signedIn := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			q := url.Values{"token": {token}, "login_session": {sessionID}}
			req := httptest.NewRequest(http.MethodGet, "/oauth/magic-link-verify?"+q.Encode(), nil)
			w := httptest.NewRecorder()
			m.api.ServeHTTP(w, req)
			if loc, err := url.Parse(w.Header().Get("Location")); err == nil && loc.Query().Get("code") != "" {
				mu.Lock()
				signedIn++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if signedIn != 1 {
		t.Fatalf("%d concurrent uses of one link: %d signed in, want exactly 1", n, signedIn)
	}
	if codes := m.codes(user); codes != 1 {
		t.Fatalf("%d authorization codes minted, want 1", codes)
	}
}
