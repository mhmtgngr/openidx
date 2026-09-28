package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// THE PROXY SENDS A BROWSER ONLY TO ITS OWN HOSTS AFTER SIGN-IN AND SIGN-OUT.
//
// redirect_url is read from public links: /access/.auth/login stores it and
// the callback follows it once the browser has signed in, through OpenIDX or
// an external identity provider, and /access/.auth/logout follows it at once,
// with no session needed. All three followed whatever the link said. Each is
// driven here through the real route table behind the middleware
// cmd/access-service mounts, with a stand-in identity provider completing the
// code exchange, so the Location asserted is the one the browser follows.

// redirectCases is the table every entry point is held to: a refused target
// lands on the entry point's own default, an allowed one is followed as
// written.
type redirectCases struct {
	refused, allowed []string
}

func (p *proxyFlow) redirectCases(t *testing.T) (routeHost string, cases redirectCases) {
	t.Helper()
	upstream := newRecordingUpstream(t)
	hostA := p.routeHost("payroll")
	hostA2 := p.routeHost("wiki")
	hostB := p.routeHost("other-tenant")
	hostOff := p.routeHost("retired")
	p.f.seedProxyRoute(t, p.f.orgA, hostA, upstream.srv.URL)
	p.f.seedProxyRoute(t, p.f.orgA, hostA2, upstream.srv.URL)
	p.f.seedProxyRoute(t, p.f.orgB, hostB, upstream.srv.URL)
	off := p.f.seedProxyRoute(t, p.f.orgA, hostOff, upstream.srv.URL)
	if _, err := p.f.db.Pool.Exec(p.f.ctx, `UPDATE proxy_routes SET enabled = false WHERE id = $1::uuid`, off); err != nil {
		t.Fatalf("disable a route: %v", err)
	}
	mixedCase := strings.ToUpper(hostA[:1]) + hostA[1:]
	return hostA, redirectCases{
		refused: []string{
			"https://evil.example/landing",
			"//evil.example/landing",
			`/\evil.example/landing`,
			"https:evil.example/landing",
			"javascript:alert(document.cookie)",
			"data:text/html,<script>alert(1)</script>",
			"https://" + hostA + "@evil.example/landing",
			"https://" + hostA + "%40evil.example/landing",
			"https://evil.example@" + hostA + "/landing",
			"https://" + mixedCase + "/landing",
			"https://" + hostA + "./landing",
			"HTTPS://EVIL.EXAMPLE/landing",
			"https://evil.example./landing",
			"/landing\r\nSet-Cookie: planted=1",
			"/\t/evil.example/landing",
			"/landing\x00",
			"https://" + hostB + "/landing",   // another organization's route
			"https://" + hostOff + "/landing", // the organization's disabled route
			"ftp://" + hostA + "/landing",
		},
		allowed: []string{
			"/",
			"/landing?tab=payslips#latest",
			"https://" + hostA + "/landing?tab=payslips",
			"http://" + hostA + "/landing",
			"https://" + hostA2 + "/pages/home",
			"https://" + proxyFlowDomain + "/access/.auth/session",
			"https://" + proxyFlowDomain + ":8007/access/.auth/session",
		},
	}
}

// /access/.auth/login with OpenIDX: the target is checked when it is stored
// and again when the callback follows it after sign-in.
func TestTheProxySignInRedirectsOnlyToItsOwnHosts(t *testing.T) {
	p := newProxyFlow(t)
	host, cases := p.redirectCases(t)
	p.issuer.as(p.f.userA, "user-a@example.test")

	for _, target := range cases.refused {
		state := p.startSignIn(t, host, url.Values{"redirect_url": {target}})
		if stored := p.storedRedirect(t, state); stored != "/access/.auth/session" {
			t.Errorf("login stored %q for redirect_url %q, want the session page", stored, target)
		}
		if r := p.finishSignIn(t, host, state); r.location != "/access/.auth/session" {
			t.Errorf("after sign-in with redirect_url %q the browser went to %q, want the session page", target, r.location)
		}
	}
	for _, target := range cases.allowed {
		if _, location := p.signIn(t, host, target); location != target {
			t.Errorf("after sign-in with redirect_url %q the browser went to %q, want the target", target, location)
		}
	}
	// No redirect_url at all keeps its old landing page.
	if _, location := p.signIn(t, host, ""); location != "/access/.auth/session" {
		t.Errorf("after sign-in with no redirect_url the browser went to %q", location)
	}
}

// /access/.auth/login?idp=: the external identity provider's flow stores the
// target, and its callback, on the access service's own host, follows it.
func TestTheProxySignInThroughAnIdentityProviderRedirectsOnlyToItsOwnHosts(t *testing.T) {
	p := newProxyFlow(t)
	host, cases := p.redirectCases(t)
	idp := p.seedIDP(t, p.f.orgA)
	p.issuer.as(p.f.userA, "user-a@example.test")

	run := func(target string) (stored, location string) {
		t.Helper()
		state := p.startSignIn(t, host, url.Values{"idp": {idp}, "redirect_url": {target}})
		stored = p.storedRedirect(t, state)
		return stored, p.finishSignIn(t, p.ownHost, state).location
	}
	for _, target := range cases.refused {
		if stored, location := run(target); stored != "/" || location != "/" {
			t.Errorf("redirect_url %q through the identity provider: stored %q, followed to %q, want /", target, stored, location)
		}
	}
	for _, target := range cases.allowed {
		if _, location := run(target); location != target {
			t.Errorf("redirect_url %q through the identity provider: followed to %q, want the target", target, location)
		}
	}
}

// /access/.auth/logout needs no session, so its redirect_url is anybody's to
// write; it is held to the same rule.
func TestTheProxySignOutRedirectsOnlyToItsOwnHosts(t *testing.T) {
	p := newProxyFlow(t)
	host, cases := p.redirectCases(t)
	p.issuer.as(p.f.userA, "user-a@example.test")
	cookie, _ := p.signIn(t, host, "/")

	logout := func(target, cookieHeader string) flowResponse {
		t.Helper()
		r := p.get(t, host, "/access/.auth/logout?redirect_url="+url.QueryEscape(target), cookieHeader, nil)
		if r.status != http.StatusFound {
			t.Fatalf("logout with redirect_url %q: %d %s", target, r.status, r.body)
		}
		return r
	}
	for _, target := range cases.refused {
		if r := logout(target, ""); r.location != "/access/.auth/login" {
			t.Errorf("sign-out with redirect_url %q went to %q, want the login page", target, r.location)
		}
	}
	for _, target := range cases.allowed {
		if r := logout(target, ""); r.location != target {
			t.Errorf("sign-out with redirect_url %q went to %q, want the target", target, r.location)
		}
	}
	// Signing out with a session still ends it and still follows an allowed
	// target.
	if r := logout("/signed-out", cookie.Name+"="+cookie.Value); r.location != "/signed-out" {
		t.Errorf("sign-out with a session went to %q", r.location)
	}
	if r := p.get(t, host, "/access/.auth/session", cookie.Name+"="+cookie.Value, nil); r.status != http.StatusUnauthorized {
		t.Errorf("the signed-out session still answers: %d %s", r.status, r.body)
	}
}

// The callback checks the target again where it follows it: a login state
// holding a target the login would now refuse, as one written before this
// check existed does, is not followed.
func TestTheProxyCallbackChecksTheStoredTargetItFollows(t *testing.T) {
	p := newProxyFlow(t)
	host, _ := p.redirectCases(t)
	idp := p.seedIDP(t, p.f.orgA)
	p.issuer.as(p.f.userA, "user-a@example.test")
	ctx := context.Background()

	plant := func(state string, blob map[string]string) {
		t.Helper()
		raw, _ := json.Marshal(blob)
		if err := p.svc.redis.Client.Set(ctx, "access_oauth_state:"+state, raw, time.Minute).Err(); err != nil {
			t.Fatalf("plant a login state: %v", err)
		}
	}
	plant("planted-openidx", map[string]string{"verifier": "v", "redirect_url": "https://evil.example/landing"})
	if r := p.finishSignIn(t, host, "planted-openidx"); r.location != "/" {
		t.Errorf("the callback followed a stored target to %q, want /", r.location)
	}
	plant("planted-idp", map[string]string{"verifier": "v", "redirect_url": "//evil.example/landing",
		"idp_id": idp, "idp_issuer": p.issuer.srv.URL})
	if r := p.finishSignIn(t, p.ownHost, "planted-idp"); r.location != "/" {
		t.Errorf("the identity provider's callback followed a stored target to %q, want /", r.location)
	}
}

// The proxy's own trip to the login page names the path the browser asked
// for, never a scheme and host taken from a request line in absolute form.
func TestTheProxySendsTheBrowserToSignInWithAPathOnly(t *testing.T) {
	p := newProxyFlow(t)
	host, _ := p.redirectCases(t)
	h := p.srv.Config.Handler

	req := httptest.NewRequest(http.MethodGet, "http://evil.example/payslips?month=9", nil)
	req.Host = host
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	want := "/access/.auth/login?redirect_url=" + url.QueryEscape("/payslips?month=9")
	if w.Code != http.StatusFound || w.Header().Get("Location") != want {
		t.Errorf("an absolute-form request to a route needing sign-in: %d %q, want 302 %q", w.Code, w.Header().Get("Location"), want)
	}
}
