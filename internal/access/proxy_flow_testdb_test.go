package access

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/organization"
)

// proxyFlow is the access service as a browser meets it: RegisterRoutes
// behind the middleware cmd/access-service mounts, on a real listener, over a
// migrated database and a Redis, with a stand-in OpenIDX OAuth service and
// external identity provider that complete the code exchange. The two
// organizations, their users and their routes are adminGateFixture's.
type proxyFlow struct {
	f      *adminGateFixture
	svc    *Service
	srv    *httptest.Server
	issuer *proxyIssuer
	client *http.Client
	// ownHost is ACCESS_PROXY_DOMAIN:port, where the external identity
	// provider's callback lands.
	ownHost string
}

const (
	proxyFlowDomain = "access.example.test"
	proxyFlowPort   = 8007
	proxyFlowKid    = "access-proxy-flow"
)

func newProxyFlow(t *testing.T) *proxyFlow {
	t.Helper()
	gin.SetMode(gin.TestMode)
	f := newAdminGateFixture(t)
	issuer := newProxyIssuer(t)
	cfg := &config.Config{
		Environment:       "production",
		OAuthIssuer:       issuer.srv.URL,
		OAuthJWKSURL:      issuer.srv.URL + "/.well-known/jwks.json",
		AccessProxyDomain: proxyFlowDomain,
		Port:              proxyFlowPort,
	}
	rc := proxyTestRedis(t)
	svc := NewService(f.db, rc, cfg, zap.NewNop())
	svc.SetAuditService(NewUnifiedAuditService(f.db, zap.NewNop()))
	lookup := organization.NewOrgLookup(organization.NewService(f.db, rc, cfg, zap.NewNop()))

	p := &proxyFlow{f: f, svc: svc, issuer: issuer, ownHost: fmt.Sprintf("%s:%d", proxyFlowDomain, proxyFlowPort)}
	callers := map[string]adminGateCaller{}
	var mu sync.Mutex
	p.srv = httptest.NewServer(accessMainChain(t, svc, lookup, func(c *gin.Context) {
		mu.Lock()
		cl, ok := callers[c.GetHeader("X-Test-Caller")]
		mu.Unlock()
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}
		c.Set("user_id", cl.user)
		c.Set("org_id", cl.org)
		c.Set("roles", cl.roles)
		c.Next()
	}))
	t.Cleanup(p.srv.Close)
	mu.Lock()
	callers["forward-auth"] = adminGateCaller{user: f.userA, org: f.orgA}
	mu.Unlock()
	p.client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return p
}

// proxyTestRedis is the Redis proxy sessions live in: the server
// TEST_REDIS_ADDR names when it is set (its database 13, which nothing is
// flushed from: every key these tests write is random), an in-process one
// otherwise.
func proxyTestRedis(t *testing.T) *database.RedisClient {
	t.Helper()
	if addr := os.Getenv("TEST_REDIS_ADDR"); addr != "" {
		rc := goredis.NewClient(&goredis.Options{Addr: addr, DB: 13})
		if err := rc.Ping(context.Background()).Err(); err != nil {
			t.Fatalf("TEST_REDIS_ADDR=%s is set and does not answer: %v", addr, err)
		}
		t.Cleanup(func() { _ = rc.Close() })
		return &database.RedisClient{Client: rc}
	}
	mini := miniredis.RunT(t)
	rc := goredis.NewClient(&goredis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	return &database.RedisClient{Client: rc}
}

// flowResponse is what a browser sees of one response.
type flowResponse struct {
	status   int
	location string
	body     string
	cookies  []*http.Cookie
}

// get sends a GET for path to the access service as a browser addressing
// host, carrying the given cookie header value when it is not empty.
func (p *proxyFlow) get(t *testing.T, host, path, cookie string, header http.Header) flowResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, p.srv.URL+path, nil)
	if err != nil {
		t.Fatalf("build GET %s: %v", path, err)
	}
	req.Host = host
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatalf("GET %s (Host %s): %v", path, host, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return flowResponse{status: resp.StatusCode, location: resp.Header.Get("Location"), body: string(body), cookies: resp.Cookies()}
}

// startSignIn opens /access/.auth/login on host with the given query and
// returns the state the proxy sent to the identity provider.
func (p *proxyFlow) startSignIn(t *testing.T, host string, query url.Values) string {
	t.Helper()
	r := p.get(t, host, "/access/.auth/login?"+query.Encode(), "", nil)
	if r.status != http.StatusFound {
		t.Fatalf("login on %s (%s): %d %s", host, query.Encode(), r.status, r.body)
	}
	u, err := url.Parse(r.location)
	if err != nil || u.Query().Get("state") == "" {
		t.Fatalf("login on %s went to %q, want an authorize URL carrying a state", host, r.location)
	}
	return u.Query().Get("state")
}

// finishSignIn is the identity provider sending the browser back to the
// callback on host with a code for state.
func (p *proxyFlow) finishSignIn(t *testing.T, host, state string) flowResponse {
	t.Helper()
	r := p.get(t, host, "/access/.auth/callback?code=code-"+state+"&state="+url.QueryEscape(state), "", nil)
	if r.status != http.StatusFound {
		t.Fatalf("callback on %s: %d %s", host, r.status, r.body)
	}
	return r
}

// signIn runs the OpenIDX sign-in on host for the issuer's current subject
// and returns the session cookie it set and where it sent the browser.
func (p *proxyFlow) signIn(t *testing.T, host, redirectURL string) (cookie *http.Cookie, location string) {
	t.Helper()
	q := url.Values{}
	if redirectURL != "" {
		q.Set("redirect_url", redirectURL)
	}
	r := p.finishSignIn(t, host, p.startSignIn(t, host, q))
	for _, ck := range r.cookies {
		if ck.Name == "_openidx_proxy_session" && ck.Value != "" {
			cookie = ck
		}
	}
	if cookie == nil {
		t.Fatalf("the callback on %s set no session cookie", host)
	}
	return cookie, r.location
}

// storedRedirect reads the redirect_url the login stored under state.
func (p *proxyFlow) storedRedirect(t *testing.T, state string) string {
	t.Helper()
	raw, err := p.svc.redis.Client.Get(context.Background(), "access_oauth_state:"+state).Bytes()
	if err != nil {
		t.Fatalf("read the stored login state: %v", err)
	}
	var st map[string]string
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("decode the stored login state: %v", err)
	}
	return st["redirect_url"]
}

// proxyIssuer stands in for the OpenIDX OAuth service (/oauth/token and the
// JWKS) and for an external identity provider (/token). Both token endpoints
// answer any code with a token for the current subject.
type proxyIssuer struct {
	srv *httptest.Server
	mu  sync.Mutex
	sub map[string]interface{}
}

func newProxyIssuer(t *testing.T) *proxyIssuer {
	t.Helper()
	i := &proxyIssuer{}
	pub := &bearerKey.PublicKey
	jwks := middleware.JWKS{Keys: []middleware.JWKSKey{{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: proxyFlowKid,
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
	i.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(jwks)
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": i.unsigned(), "token_type": "Bearer"})
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "opaque", "id_token": i.unsigned()})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(i.srv.Close)
	return i
}

// as makes user the subject of the next tokens the issuer hands out.
func (i *proxyIssuer) as(user, email string, roles ...string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	rs := make([]interface{}, 0, len(roles))
	for _, r := range roles {
		rs = append(rs, r)
	}
	i.sub = map[string]interface{}{"sub": user, "email": email, "name": "Someone", "roles": rs}
}

// unsigned is the token the code exchange returns. The proxy reads a token it
// got from its own back channel without verifying it, so it needs no
// signature here.
func (i *proxyIssuer) unsigned() string {
	i.mu.Lock()
	claims := i.sub
	i.mu.Unlock()
	payload, _ := json.Marshal(claims)
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(payload) + ".x"
}

// bearer signs an access token for user in org, allowed to call OpenIDX's own
// APIs: the only kind the proxy accepts as a bearer.
func (i *proxyIssuer) bearer(t *testing.T, user, org string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": user, "email": user + "@example.test", "name": "Bearer Holder", "roles": []interface{}{"staff"},
		"client_id": "admin-console", middleware.APIAccessClaim: true, middleware.OrgIDClaim: org,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = proxyFlowKid
	tok.Header["typ"] = middleware.AccessTokenType
	signed, err := tok.SignedString(bearerKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// seedIDP registers an external identity provider in org whose token endpoint
// is the stand-in issuer's /token.
func (p *proxyFlow) seedIDP(t *testing.T, org string) string {
	t.Helper()
	var id string
	if err := p.f.db.Pool.QueryRow(p.f.ctx, `
		INSERT INTO identity_providers (name, provider_type, issuer_url, client_id, client_secret, scopes, enabled, org_id)
		VALUES ($1, 'oidc', $2, 'proxy-client', 'proxy-secret', '["openid"]', true, $3::uuid)
		RETURNING id::text`, "idp-"+p.f.suffix, p.issuer.srv.URL, org).Scan(&id); err != nil {
		t.Fatalf("seed identity provider: %v", err)
	}
	return id
}

// recordingUpstream is an application behind the proxy that records every
// request it is sent.
type recordingUpstream struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []*http.Request
}

func newRecordingUpstream(t *testing.T) *recordingUpstream {
	t.Helper()
	u := &recordingUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.seen = append(u.seen, r.Clone(context.Background()))
		u.mu.Unlock()
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	t.Cleanup(u.srv.Close)
	return u
}

// last is the most recent request the upstream received.
func (u *recordingUpstream) last(t *testing.T) *http.Request {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.seen) == 0 {
		t.Fatal("the upstream received nothing")
	}
	return u.seen[len(u.seen)-1]
}

func (u *recordingUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.seen)
}

// routeHost is a fresh host name for a route in this run.
func (p *proxyFlow) routeHost(name string) string {
	return strings.ToLower(name) + "-" + p.f.suffix + ".example.test"
}
