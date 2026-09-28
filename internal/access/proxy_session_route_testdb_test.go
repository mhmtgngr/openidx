package access

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// A PROXY SESSION BELONGS TO THE ROUTE IT WAS SIGNED IN ON.
//
// createSession recorded the organization the tenant resolver chose -- for a
// proxied host, the default organization -- and no route. Continuous
// verification joins a session to its route to find reverify_interval, so it
// never ran, and a route's reverify_interval did nothing. The session blob
// also kept the user's OpenIDX access token, which nothing read.
//
// The sign-in is the real one, through the production route table, on a host
// another organization than the default one routes.
func TestAProxySessionBelongsToItsRouteAndIsReverified(t *testing.T) {
	p := newProxyFlow(t)
	ctx := orgctx.WithBypassRLS(context.Background())
	host := p.routeHost("ledger")
	up := newRecordingUpstream(t)
	route := p.f.seedProxyRoute(t, p.f.orgB, host, up.srv.URL)
	if _, err := p.f.db.Pool.Exec(p.f.ctx, `UPDATE proxy_routes SET reverify_interval = 60 WHERE id = $1::uuid`, route); err != nil {
		t.Fatal(err)
	}
	p.issuer.as(p.f.adminB, "admin-b@example.test", "staff")
	session, _ := p.signIn(t, host, "/")

	var org, routeID string
	if err := p.f.db.Pool.QueryRow(ctx, `
		SELECT org_id::text, COALESCE(route_id::text, '') FROM proxy_sessions WHERE session_token = $1`,
		hashToken(session.Value)).Scan(&org, &routeID); err != nil {
		t.Fatalf("read the session row: %v", err)
	}
	if org != p.f.orgB || routeID != route {
		t.Fatalf("the session was recorded in organization %s on route %q, want the route's own %s and %s", org, routeID, p.f.orgB, route)
	}
	raw, err := p.svc.redis.Client.Get(context.Background(), "proxy_session:"+hashToken(session.Value)).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var blob map[string]any
	if err := json.Unmarshal(raw, &blob); err != nil {
		t.Fatal(err)
	}
	if _, kept := blob["token"]; kept {
		t.Error("the session blob keeps the user's OpenIDX access token")
	}

	cookie := http.Header{"Cookie": {signedIn(session)}}
	if resp, _ := p.send(t, http.MethodGet, host, "/books", cookie, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("a signed-in request: %d", resp.StatusCode)
	}

	// Continuous verification now finds the session through its route.
	cv := NewContinuousVerifier(p.svc, time.Minute, zap.NewNop())
	cv.verifyActiveSessions(ctx)
	var verified *time.Time
	var revoked bool
	if err := p.f.db.Pool.QueryRow(ctx, `SELECT last_verified_at, revoked FROM proxy_sessions WHERE session_token = $1`,
		hashToken(session.Value)).Scan(&verified, &revoked); err != nil {
		t.Fatal(err)
	}
	if verified == nil || revoked {
		t.Fatalf("reverification did not run on the session (last_verified_at %v, revoked %v)", verified, revoked)
	}

	// The route now requires a trusted device, and the next reverification
	// ends the session on the proxy.
	if _, err := p.f.db.Pool.Exec(ctx, `UPDATE proxy_routes SET require_device_trust = true WHERE id = $1::uuid`, route); err != nil {
		t.Fatal(err)
	}
	if _, err := p.f.db.Pool.Exec(ctx, `
		UPDATE proxy_sessions SET last_verified_at = NOW() - INTERVAL '2 minutes' WHERE session_token = $1`, hashToken(session.Value)); err != nil {
		t.Fatal(err)
	}
	cv.verifyActiveSessions(ctx)
	if err := p.f.db.Pool.QueryRow(ctx, `SELECT revoked FROM proxy_sessions WHERE session_token = $1`,
		hashToken(session.Value)).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("reverification against the route's new requirement did not revoke the session")
	}
	before := up.count()
	if resp, _ := p.send(t, http.MethodGet, host, "/books", cookie, ""); resp.StatusCode != http.StatusFound || up.count() != before {
		t.Errorf("the revoked session still reaches the application: %d", resp.StatusCode)
	}
}

// A host can pass to another organization once the one that routed it
// disables its route. A session signed in there before is still bound to the
// host, and is accepted on neither the proxy nor forward-auth for the new
// organization's route. Development wiring, so forward-auth can be asked with
// the cookie alone.
func TestAProxySessionIsNotAcceptedOnAnotherOrganizationsRoute(t *testing.T) {
	p := newProxyFlowWith(t, false)
	host := p.routeHost("handover")
	upA, upB := newRecordingUpstream(t), newRecordingUpstream(t)
	routeA := p.f.seedProxyRoute(t, p.f.orgA, host, upA.srv.URL)
	p.issuer.as(p.f.userA, "user-a@example.test", "staff")
	session, _ := p.signIn(t, host, "/")
	cookie := http.Header{"Cookie": {signedIn(session)}}
	decide := func() *http.Response {
		t.Helper()
		resp, _ := p.send(t, http.MethodGet, proxyFlowDomain, "/api/v1/access/auth/decide", http.Header{
			"Cookie": {signedIn(session)}, "X-Forwarded-Host": {host}, "X-Forwarded-Uri": {"/"},
		}, "")
		return resp
	}
	if resp, _ := p.send(t, http.MethodGet, host, "/", cookie, ""); resp.StatusCode != http.StatusOK || upA.count() != 1 {
		t.Fatalf("a signed-in request on the first organization's route: %d", resp.StatusCode)
	}
	if resp := decide(); resp.StatusCode != http.StatusOK || resp.Header.Get("X-Forwarded-User") != p.f.userA {
		t.Fatalf("forward-auth for the session on its own route: %d", resp.StatusCode)
	}

	if _, err := p.f.db.Pool.Exec(p.f.ctx, `UPDATE proxy_routes SET enabled = false WHERE id = $1::uuid`, routeA); err != nil {
		t.Fatal(err)
	}
	p.f.seedProxyRoute(t, p.f.orgB, host, upB.srv.URL)

	if resp, _ := p.send(t, http.MethodGet, host, "/", cookie, ""); resp.StatusCode != http.StatusFound || upB.count() != 0 {
		t.Errorf("the first organization's session reached the second organization's application: %d, upstream saw %d", resp.StatusCode, upB.count())
	}
	if resp := decide(); resp.StatusCode != http.StatusFound {
		t.Errorf("forward-auth accepted the first organization's session on the second's route: %d, user %q",
			resp.StatusCode, resp.Header.Get("X-Forwarded-User"))
	}
}
