package access

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// THE PROXY KEEPS ITS OWN CREDENTIALS FROM THE APPLICATIONS BEHIND IT.
//
// The proxy forwarded its session cookie, _openidx_proxy_session, to every
// upstream in the Cookie header, and, where it had authenticated the request
// with a bearer, the OpenIDX access token in Authorization as well. The
// session was looked up by its token alone, so an application, or anyone
// reading its logs, could present a user's cookie on another route and be
// that user there; the bearer is a token that may call OpenIDX's own APIs.
//
// Every request here goes through the real route table behind the middleware
// cmd/access-service mounts, to httptest upstreams that record what they
// receive, over a migrated Postgres and a Redis. Sessions are made by the
// real sign-in: the login redirect, the callback and the code exchange.

// credentialRoutes is the application a browser signs in to, a second route
// of the same organization, another organization's route, and a route that
// needs no sign-in, each with a recording upstream.
type credentialRoutes struct {
	app, sibling, other, open                     string
	appUp, siblingUp, otherUp, openUp             *recordingUpstream
	appRoute, siblingRoute, otherRoute, openRoute string
}

func (p *proxyFlow) credentialRoutes(t *testing.T) credentialRoutes {
	t.Helper()
	r := credentialRoutes{
		app: p.routeHost("payroll"), sibling: p.routeHost("wiki"),
		other: p.routeHost("tenant-b-crm"), open: p.routeHost("status"),
		appUp: newRecordingUpstream(t), siblingUp: newRecordingUpstream(t),
		otherUp: newRecordingUpstream(t), openUp: newRecordingUpstream(t),
	}
	r.appRoute = p.f.seedProxyRoute(t, p.f.orgA, r.app, r.appUp.srv.URL)
	r.siblingRoute = p.f.seedProxyRoute(t, p.f.orgA, r.sibling, r.siblingUp.srv.URL)
	r.otherRoute = p.f.seedProxyRoute(t, p.f.orgB, r.other, r.otherUp.srv.URL)
	r.openRoute = p.f.seedProxyRoute(t, p.f.orgA, r.open, r.openUp.srv.URL)
	if _, err := p.f.db.Pool.Exec(p.f.ctx, `UPDATE proxy_routes SET require_auth = false WHERE id = $1::uuid`, r.openRoute); err != nil {
		t.Fatalf("open a route: %v", err)
	}
	return r
}

// send is one request to the access service as a browser addressing host.
func (p *proxyFlow) send(t *testing.T, method, host, path string, header http.Header, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, p.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	req.Host = host
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s (Host %s): %v", method, path, host, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func signedIn(ck *http.Cookie) string { return ck.Name + "=" + ck.Value }

// (a) and (b): the proxy's session cookie never reaches the application, and
// neither does a bearer the proxy consumed; the application's own cookies and
// its own Authorization header go through as the browser sent them.
func TestTheProxyKeepsItsOwnCredentialsFromTheApplication(t *testing.T) {
	p := newProxyFlow(t)
	r := p.credentialRoutes(t)
	p.issuer.as(p.f.userA, "user-a@example.test", "staff")
	session, _ := p.signIn(t, r.app, "/")

	// A cookie session, the application's own cookies around it, and the
	// application's own Authorization header.
	resp, body := p.send(t, http.MethodGet, r.app, "/payslips", http.Header{
		"Cookie":        {"theme=dark; " + signedIn(session) + "; app_session=s3cr3t"},
		"Authorization": {"Basic YXBwOmFwcC1wYXNzd29yZA=="},
	}, "")
	if resp.StatusCode != http.StatusOK || body != "upstream-ok" {
		t.Fatalf("a signed-in request: %d %q", resp.StatusCode, body)
	}
	seen := r.appUp.last(t)
	if got := strings.Join(seen.Header.Values("Cookie"), "; "); got != "theme=dark; app_session=s3cr3t" {
		t.Errorf("the application received Cookie %q, want its own two cookies and not the proxy's", got)
	}
	if strings.Contains(strings.Join(seen.Header.Values("Cookie"), ";"), session.Value) {
		t.Error("the proxy's session token reached the application")
	}
	if got := seen.Header.Get("Authorization"); got != "Basic YXBwOmFwcC1wYXNzd29yZA==" {
		t.Errorf("the application's own Authorization header arrived as %q", got)
	}
	if got := seen.Header.Get("X-Forwarded-User"); got != p.f.userA {
		t.Errorf("X-Forwarded-User = %q, want the session's user", got)
	}

	// The proxy's cookie alone: no Cookie header at all reaches the upstream.
	p.send(t, http.MethodGet, r.app, "/payslips", http.Header{"Cookie": {signedIn(session)}}, "")
	if got := r.appUp.last(t).Header.Values("Cookie"); len(got) != 0 {
		t.Errorf("the application received Cookie %q from a request carrying only the proxy's", got)
	}

	// A bearer the proxy authenticated the request with is removed; the
	// application's cookies stay.
	bearer := "Bearer " + p.issuer.bearer(t, p.f.operatorA, p.f.orgA, "staff")
	resp, body = p.send(t, http.MethodGet, r.app, "/payslips", http.Header{
		"Authorization": {bearer}, "Cookie": {"theme=dark"},
	}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a bearer request: %d %q", resp.StatusCode, body)
	}
	seen = r.appUp.last(t)
	if got := seen.Header.Values("Authorization"); len(got) != 0 {
		t.Errorf("the application received the bearer the proxy consumed: %q", got)
	}
	if got := seen.Header.Get("X-Forwarded-User"); got != p.f.operatorA {
		t.Errorf("X-Forwarded-User = %q, want the bearer's subject", got)
	}
	if got := seen.Header.Get("Cookie"); got != "theme=dark" {
		t.Errorf("the application's cookie arrived as %q", got)
	}

	// A bearer the proxy did not consume -- the cookie session authenticated
	// the request -- is the application's, and goes through.
	p.send(t, http.MethodGet, r.app, "/payslips", http.Header{
		"Authorization": {bearer}, "Cookie": {signedIn(session)},
	}, "")
	if got := r.appUp.last(t).Header.Get("Authorization"); got != bearer {
		t.Errorf("an Authorization header the proxy did not use arrived as %q", got)
	}

	// On a route that needs no sign-in the proxy consumes nothing: the
	// Authorization header is the application's. Its session cookie, sent to
	// a host it was not set for, is still the proxy's and is removed.
	p.send(t, http.MethodGet, r.open, "/status", http.Header{
		"Authorization": {bearer}, "Cookie": {"lang=en; " + signedIn(session)},
	}, "")
	seen = r.openUp.last(t)
	if got := seen.Header.Get("Authorization"); got != bearer {
		t.Errorf("an open route's Authorization arrived as %q", got)
	}
	if got := seen.Header.Get("Cookie"); got != "lang=en" {
		t.Errorf("an open route received Cookie %q, want lang=en only", got)
	}
}

// (c): a session is good on the host it was issued for and nowhere else. The
// cookie is host-only, so a browser never sends it elsewhere; whoever copied it
// from an application cannot use it on another route either.
func TestAProxySessionIsGoodOnlyOnTheHostItWasIssuedFor(t *testing.T) {
	p := newProxyFlow(t)
	r := p.credentialRoutes(t)
	p.issuer.as(p.f.userA, "user-a@example.test", "staff")
	session, _ := p.signIn(t, r.app, "/")
	cookie := http.Header{"Cookie": {signedIn(session)}}

	if resp, body := p.send(t, http.MethodGet, r.app, "/payslips", cookie, ""); resp.StatusCode != http.StatusOK || body != "upstream-ok" {
		t.Fatalf("the session on its own host: %d %q", resp.StatusCode, body)
	}
	for _, other := range []struct {
		name, host string
		up         *recordingUpstream
	}{
		{"another route of the same organization", r.sibling, r.siblingUp},
		{"another organization's route", r.other, r.otherUp},
	} {
		before := other.up.count()
		resp, _ := p.send(t, http.MethodGet, other.host, "/admin", cookie, "")
		if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/access/.auth/login") {
			t.Errorf("the session replayed on %s: %d %q, want a redirect to sign in", other.name, resp.StatusCode, resp.Header.Get("Location"))
		}
		if other.up.count() != before {
			t.Errorf("the session replayed on %s reached its application", other.name)
		}
		if resp, body := p.send(t, http.MethodGet, other.host, "/access/.auth/session", cookie, ""); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("the session replayed on %s reads as a session: %d %s", other.name, resp.StatusCode, body)
		}
	}
	// The same host on another port, in another case, is the same cookie
	// scope, and the session answers there.
	if resp, body := p.send(t, http.MethodGet, strings.ToUpper(r.app)+":8443", "/access/.auth/session", cookie, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("the session on its own host with a port: %d %s", resp.StatusCode, body)
	}

	// Signing in on the sibling gives that host a session of its own.
	sibling, _ := p.signIn(t, r.sibling, "/")
	if resp, body := p.send(t, http.MethodGet, r.sibling, "/pages", http.Header{"Cookie": {signedIn(sibling)}}, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("a session issued on the sibling: %d %q", resp.StatusCode, body)
	}

	// A session written before sessions carried their host is refused, and
	// the browser is sent to sign in again.
	raw, err := p.svc.redis.Client.Get(context.Background(), "proxy_session:"+hashToken(session.Value)).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var blob map[string]interface{}
	_ = json.Unmarshal(raw, &blob)
	delete(blob, "host")
	legacy, _ := json.Marshal(blob)
	if err := p.svc.redis.Client.Set(context.Background(), "proxy_session:"+hashToken(session.Value), legacy, time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	if resp, _ := p.send(t, http.MethodGet, r.app, "/payslips", cookie, ""); resp.StatusCode != http.StatusFound {
		t.Errorf("a session with no host: %d, want a redirect to sign in", resp.StatusCode)
	}
}

// Identity headers come from the verified session and from nothing else: a
// caller's own copies never reach the application, on a route that needs no
// sign-in either, and a route's custom_headers can neither be saved with one
// nor, for a row stored before the API refused them, override one.
func TestCallerAndRouteIdentityHeadersNeverReachTheApplication(t *testing.T) {
	p := newProxyFlow(t)
	r := p.credentialRoutes(t)
	p.issuer.as(p.f.userA, "user-a@example.test", "staff")
	session, _ := p.signIn(t, r.app, "/")

	forged := http.Header{
		"X-Forwarded-User":               {"ceo"},
		"X-Forwarded-Email":              {"ceo@example.test"},
		"X-Forwarded-Name":               {"The CEO"},
		"X-Forwarded-Roles":              {"admin"},
		"X-Forwarded-Groups":             {"finance"},
		"X-Forwarded-Preferred-Username": {"ceo"},
		"X-Forwarded-Access-Token":       {"forged"},
		"X-Forwarded-Route":              {"elsewhere"},
		"X-Risk-Score":                   {"0"},
		"X-Ziti-Identity":                {"ceo"},
		"X-Auth-Request-User":            {"ceo"},
		"X-Auth-Request-Email":           {"ceo@example.test"},
		"X-Auth-Request-Groups":          {"finance"},
		"X-Auth-Request-Access-Token":    {"forged"},
	}
	assertNoForged := func(where string, h http.Header, sessionUser string) {
		t.Helper()
		for name, vals := range forged {
			for _, got := range h.Values(name) {
				if got == vals[0] {
					t.Errorf("%s: the caller's %s: %q reached the application", where, name, got)
				}
			}
		}
		if got := h.Get("X-Forwarded-User"); got != sessionUser {
			t.Errorf("%s: X-Forwarded-User = %q, want %q", where, got, sessionUser)
		}
	}

	p.send(t, http.MethodGet, r.open, "/status", forged, "")
	assertNoForged("a route needing no sign-in", r.openUp.last(t).Header, "")

	withSession := forged.Clone()
	withSession.Set("Cookie", signedIn(session))
	p.send(t, http.MethodGet, r.app, "/payslips", withSession, "")
	assertNoForged("a signed-in request", r.appUp.last(t).Header, p.f.userA)

	// The route API refuses a custom header only the proxy may write, in
	// any case, on create and on update, and keeps the others.
	admin := http.Header{"Authorization": {"Bearer " + p.issuer.bearer(t, p.f.adminA, p.f.orgA, "admin")},
		"Content-Type": {"application/json"}}
	for _, name := range []string{"X-Forwarded-User", "x-forwarded-email", "X-Auth-Request-User", "X-Ziti-Identity"} {
		payload := `{"name":"hdr-` + p.f.suffix + `","from_url":"https://hdr-` + p.f.suffix + `.example.test","to_url":"http://127.0.0.1:9/","custom_headers":{"` + name + `":"ceo"}}`
		if resp, body := p.send(t, http.MethodPost, proxyFlowDomain, "/api/v1/access/routes", admin, payload); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("create a route with custom header %s: %d %s, want 400", name, resp.StatusCode, body)
		}
		if resp, body := p.send(t, http.MethodPut, proxyFlowDomain, "/api/v1/access/routes/"+r.appRoute, admin,
			`{"custom_headers":{"`+name+`":"ceo"}}`); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("update a route with custom header %s: %d %s, want 400", name, resp.StatusCode, body)
		}
	}
	var stored string
	if err := p.f.db.Pool.QueryRow(p.f.ctx, `SELECT COALESCE(custom_headers::text, '') FROM proxy_routes WHERE id = $1::uuid`, r.appRoute).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(stored), "x-forwarded-user") {
		t.Errorf("a refused update was stored: %s", stored)
	}
	if resp, body := p.send(t, http.MethodPut, proxyFlowDomain, "/api/v1/access/routes/"+r.appRoute, admin,
		`{"custom_headers":{"X-Tenant":"acme"}}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("update a route with an ordinary custom header: %d %s", resp.StatusCode, body)
	}
	p.send(t, http.MethodGet, r.app, "/payslips", http.Header{"Cookie": {signedIn(session)}}, "")
	if got := r.appUp.last(t).Header.Get("X-Tenant"); got != "acme" {
		t.Errorf("the ordinary custom header arrived as %q", got)
	}

	// A row stored before the API refused them still cannot rename the user.
	if _, err := p.f.db.Pool.Exec(p.f.ctx, `UPDATE proxy_routes SET custom_headers = $2::jsonb WHERE id = $1::uuid`,
		r.appRoute, `{"X-Forwarded-User":"ceo","X-Auth-Request-Email":"ceo@example.test","X-Tenant":"acme"}`); err != nil {
		t.Fatal(err)
	}
	p.send(t, http.MethodGet, r.app, "/payslips", http.Header{"Cookie": {signedIn(session)}}, "")
	seen := r.appUp.last(t).Header
	if got := seen.Get("X-Forwarded-User"); got != p.f.userA {
		t.Errorf("a stored custom header renamed the user to %q", got)
	}
	if got := seen.Get("X-Auth-Request-Email"); got != "" {
		t.Errorf("a stored custom header wrote X-Auth-Request-Email: %q", got)
	}
	if got := seen.Get("X-Tenant"); got != "acme" {
		t.Errorf("the ordinary stored custom header arrived as %q", got)
	}
}

// Forward-auth: the edge copies the headers its forward-auth plugin lists from
// this endpoint's answer onto the upstream request and passes the caller's
// copy of any header the answer leaves out. So the answer carries every
// identity header, empty where there is no identity; the caller's Cookie
// without the proxy's session cookie; and an empty Authorization when the
// access service authenticated the request with it.
func TestForwardAuthAnswersInPlaceOfTheCallersCredentials(t *testing.T) {
	p := newProxyFlow(t)
	r := p.credentialRoutes(t)
	bearer := "Bearer " + p.issuer.bearer(t, p.f.operatorA, p.f.orgA, "staff")
	decide := func(host string, header http.Header) *http.Response {
		t.Helper()
		h := header.Clone()
		h.Set("X-Forwarded-Host", host)
		h.Set("X-Forwarded-Uri", "/payslips")
		resp, body := p.send(t, http.MethodGet, proxyFlowDomain, "/api/v1/access/auth/decide", h, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("decide for %s: %d %s", host, resp.StatusCode, body)
		}
		return resp
	}
	answered := func(resp *http.Response, name string) (string, bool) {
		vals, ok := resp.Header[http.CanonicalHeaderKey(name)]
		if !ok || len(vals) == 0 {
			return "", false
		}
		return vals[0], true
	}

	// A route that needs no sign-in: every identity header is answered, empty.
	resp := decide(r.open, http.Header{"Authorization": {bearer}, "X-Forwarded-User": {"ceo"}})
	for _, name := range []string{"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Name", "X-Forwarded-Roles", "X-Risk-Score"} {
		if v, ok := answered(resp, name); !ok || v != "" {
			t.Errorf("open route: %s answered %q (present=%v), want present and empty", name, v, ok)
		}
	}

	// The production bearer middleware authenticated the call with the
	// Authorization header, so it is answered empty; the caller's cookies
	// come back without the proxy's.
	p.issuer.as(p.f.userA, "user-a@example.test", "staff")
	session, _ := p.signIn(t, r.app, "/")
	resp = decide(r.app, http.Header{"Authorization": {bearer}, "Cookie": {"theme=dark; " + signedIn(session)}})
	if v, ok := answered(resp, "Authorization"); !ok || v != "" {
		t.Errorf("Authorization answered %q (present=%v), want present and empty", v, ok)
	}
	if v, _ := answered(resp, "Cookie"); v != "theme=dark" {
		t.Errorf("Cookie answered %q, want the caller's cookies without the proxy's", v)
	}
	if v, _ := answered(resp, "X-Forwarded-User"); v != p.f.userA {
		t.Errorf("X-Forwarded-User answered %q, want the session's user", v)
	}
	// No proxy cookie: the caller's Cookie is not answered, so it passes as
	// it was.
	resp = decide(r.app, http.Header{"Authorization": {bearer}, "Cookie": {"theme=dark"}})
	if v, ok := answered(resp, "Cookie"); ok {
		t.Errorf("Cookie answered %q for a request without the proxy's cookie", v)
	}
}

// Forward-auth as main.go wires it in development, where a cookie alone
// reaches the endpoint: the session is held to the forwarded host, and an
// Authorization header nobody authenticated with is the application's and is
// not answered.
func TestForwardAuthHoldsASessionToItsHost(t *testing.T) {
	p := newProxyFlowWith(t, false)
	r := p.credentialRoutes(t)
	p.issuer.as(p.f.userA, "user-a@example.test", "staff")
	session, _ := p.signIn(t, r.app, "/")

	decide := func(host string, header http.Header) *http.Response {
		t.Helper()
		h := header.Clone()
		h.Set("X-Forwarded-Host", host)
		h.Set("X-Forwarded-Uri", "/payslips")
		resp, _ := p.send(t, http.MethodGet, proxyFlowDomain, "/api/v1/access/auth/decide", h, "")
		return resp
	}
	resp := decide(r.app, http.Header{"Cookie": {signedIn(session)}, "Authorization": {"Basic YXBwOmFwcA=="}})
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Forwarded-User") != p.f.userA {
		t.Fatalf("forward-auth for the session's own host: %d user %q", resp.StatusCode, resp.Header.Get("X-Forwarded-User"))
	}
	if _, ok := resp.Header["Authorization"]; ok {
		t.Errorf("an Authorization header nobody authenticated with was answered: %q", resp.Header.Values("Authorization"))
	}
	for _, host := range []string{r.sibling, r.other} {
		resp := decide(host, http.Header{"Cookie": {signedIn(session)}})
		if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/access/.auth/login") {
			t.Errorf("forward-auth for %s with another host's session: %d %q, want a redirect to sign in",
				host, resp.StatusCode, resp.Header.Get("Location"))
		}
	}

	// Without X-Forwarded-Host the endpoint decides for the host it was
	// asked on. It used to read the Host header out of the header map, where
	// the server never puts it, and match the empty host against every route.
	resp, _ = p.send(t, http.MethodGet, r.app, "/api/v1/access/auth/decide", http.Header{"Cookie": {signedIn(session)}}, "")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Forwarded-User") != p.f.userA {
		t.Errorf("forward-auth with no X-Forwarded-Host on the session's own host: %d user %q",
			resp.StatusCode, resp.Header.Get("X-Forwarded-User"))
	}
	resp, _ = p.send(t, http.MethodGet, r.sibling, "/api/v1/access/auth/decide", http.Header{"Cookie": {signedIn(session)}}, "")
	if resp.StatusCode != http.StatusFound {
		t.Errorf("forward-auth with no X-Forwarded-Host on another host: %d, want a redirect to sign in", resp.StatusCode)
	}
}

// A request that names no host matches no route. The route lookup matches a
// host as a substring of from_url, and an empty one used to match every route
// and answer with the highest-priority one, of any organization.
func TestARequestNamingNoHostMatchesNoRoute(t *testing.T) {
	p := newProxyFlow(t)
	r := p.credentialRoutes(t)
	if _, err := p.f.db.Pool.Exec(p.f.ctx, `UPDATE proxy_routes SET priority = 1000 WHERE id = $1::uuid`, r.openRoute); err != nil {
		t.Fatal(err)
	}
	// HTTP/1.1 requires a Host header and the server refuses a request
	// without one; HTTP/1.0 does not, and reaches the handler with none.
	conn, err := net.Dial("tcp", p.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /status HTTP/1.0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read the answer to a request with no host: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || r.openUp.count() != 0 {
		t.Errorf("a request with no host: %d, and the highest-priority route's upstream saw %d requests; want 404 and none",
			resp.StatusCode, r.openUp.count())
	}
	// The same request naming the route's host is served.
	if resp, body := p.send(t, http.MethodGet, r.open, "/status", nil, ""); resp.StatusCode != http.StatusOK || r.openUp.count() != 1 {
		t.Errorf("a request naming the open route's host: %d %q, upstream saw %d", resp.StatusCode, body, r.openUp.count())
	}
}
