package access

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// THE UNAUTHENTICATED SURFACE OF access-service, DERIVED RATHER THAN LISTED.
//
// J4 found POST /agent/report and GET /agent/config registered outside the
// tenant-JWT middleware — correctly, because an agent has no tenant JWT — and
// neither handler ever read the credential enrollment issues. One unauthenticated
// request could hand a device `device-trusted` and the Tier-2 network access
// that comes with it, or take it away from someone else's laptop. What made that
// possible to miss is that FOUR comments in this package named /agent/report as
// the pattern they copied, and the pattern did not exist. The defect class is
// not "public routes exist" — it is "a route whose comment claims a check the
// handler never performs".
//
// So this does not read a list to find the public routes. It registers every
// route with an auth middleware that aborts 418, and drives each one: a route
// that answers anything else is OUTSIDE the middleware BY CONSTRUCTION. A list
// would have missed at least one already — POST /api/v1/access/enroll, the
// Tier-0 dark-platform door, is registered on the router directly rather than
// in the `publicAgent` group with the other four.
//
// What is written down is the DECISION about each one, and the shape of its
// refusal, which the test then checks. See refusalShape.
type refusalShape int

const (
	// refusesWithoutState: an anonymous request is refused before the handler
	// reads anything. The test proves it by driving the route with a nil
	// database — a handler that touches the DB first panics, and that panic is
	// the finding: the credential check moved behind a lookup.
	refusesWithoutState refusalShape = iota

	// refusesAfterLookup: the handler resolves the subject first and answers
	// 404 for one that does not exist, so the credential check is reached only
	// for a subject that does. That is a weaker order than the line above and
	// it is recorded rather than hidden: an unknown session id is a 404 and a
	// known one is a 401, which leaks only that the id exists.
	refusesAfterLookup

	// servesAnonymously: answering an anonymous caller is the route's whole
	// job — a login redirect, an OIDC callback, a file, a link whose path IS
	// the secret. There is no refusal to assert, so what is asserted is that
	// somebody wrote down why. These are the entries to read first in a review.
	servesAnonymously
)

type publicRoute struct {
	shape refusalShape
	why   string
}

// publicAccessRoutes is the register. Every route the derivation finds outside
// the auth middleware must appear here with a reason; every entry here must
// still be outside it. Both halves are checked below.
var publicAccessRoutes = map[string]publicRoute{
	// --- the session-cookie login flow. An anonymous browser is the caller by
	// definition; these five are how it stops being anonymous.
	"GET /access/.auth/login": {servesAnonymously,
		"starts the OIDC flow for a browser that has no session yet — being reachable without one is the point"},
	"GET /access/.auth/callback": {servesAnonymously,
		"the OIDC redirect_uri; the authorization code and state in the query are what authenticate it"},
	"GET /access/.auth/logout": {servesAnonymously,
		"clears the session cookie and redirects; refusing a caller who has no session would leave them unable to log out"},
	"GET /access/.auth/idps": {servesAnonymously,
		"lists the identity providers a login page must offer before anyone has logged in"},
	"GET /access/.auth/session": {refusesWithoutState,
		"reports the current session; without a cookie there is nothing to report and it answers 401"},

	// --- the agent surface. An agent has no tenant JWT: enrollment hands it a
	// credential and it presents that. Every one of these refuses before it
	// reads anything, which is the property internal/access/agent_auth.go was
	// written to establish and this is where it is pinned.
	"POST /api/v1/access/agent/enroll": {refusesWithoutState,
		"trades an enrollment token for an agent credential; the token is checked before anything is written"},
	"POST /api/v1/access/agent/report": {refusesWithoutState,
		"posture report — verifyEnrolledAgent runs before the body is read, because the verdict grants or removes the device-trusted Ziti attribute"},
	"GET /api/v1/access/agent/config": {refusesWithoutState,
		"serves a device its check list and kiosk policy; the agent id comes from the verified credential, never from the request"},
	"POST /api/v1/access/agent/windows-apps/report": {refusesWithoutState,
		"windows-app discovery from an agent bound to a host; same X-Agent-ID + X-Auth-Token check as /agent/report"},
	"POST /api/v1/access/enroll": {refusesWithoutState,
		"the Tier-0 dark-platform door: trades a session bearer or enrollment token for a one-time Ziti enrollment JWT, and verifies it itself"},

	// --- remote support. Recorded as the weaker order because that is what it
	// is, not because it is wrong: a support session id is a UUID the operator
	// hands to the device, so 404-then-401 leaks only that the id exists.
	"GET /api/v1/access/agent/remote-support/sessions/:id/ws": {refusesAfterLookup,
		"the agent's WebSocket for a support session; fetchSession runs first, so an unknown id is 404 and a known one needs X-Agent-ID + X-Auth-Token"},
	"POST /api/v1/access/agent/remote-support/sessions/:id/consent": {refusesAfterLookup,
		"records the device owner's consent for a support session; same order — the session is resolved before the agent credential is checked"},

	// --- artefacts and secret-bearing links.
	"GET /downloads/:file": {refusesWithoutState,
		"serves agent installers to a machine that has no identity yet; the name is matched against ^[A-Za-z0-9._-]+$ and a directory is refused, so it cannot escape the downloads dir"},
	"GET /temp-access/:token": {servesAnonymously,
		"a vendor redeems a temporary access link whose path IS the secret; tempLinkGate checks expiry, revocation, use count and the IP allowlist before granting anything, and TestEveryGateTheRegisterClaims proves each one. This entry used to end \"...allowed IPs and MFA\": the handler never checked MFA — require_mfa was stored and selected back and never compared — so the field is gone rather than half-kept. Vendor MFA arrives with the identity (docs/VENDOR-ACCESS-ROADMAP.md V1), not as a flag on an anonymous URL"},
}

// buildPublicSurfaceRouter registers every access-service route with an auth
// middleware that refuses everything, and returns the router. A nil database is
// deliberate: it is what makes "did this handler read anything before refusing"
// an observable question.
//
// THE BOUNDARY OF THIS DERIVATION, stated because it is the way it could go
// quietly blind. RegisterRoutes registers two groups conditionally —
// `if svc.agentHandler != nil` and `if svc.remoteSupportHandler != nil` — and
// those two hold every public agent route there is. A configuration that left
// either nil would take seven routes out of the derivation and the guard would
// still pass, reporting on a smaller surface than the service has. So both are
// asserted below. (The other five `if svc.config != nil` / `if svc.redis != nil`
// branches in RegisterRoutes configure handlers — Play Integrity, Guacamole,
// the recording store, the TURN minter — and register no routes; checked when
// this was written.) A future group gated on a flag this config does not set
// would need the same treatment, and this is the note that says so.
func buildPublicSurfaceRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		Environment:         "production",
		AccessSessionSecret: strings.Repeat("s", 32),
		EncryptionKey:       strings.Repeat("k", 32),
	}
	svc := NewService(nil, nil, cfg, zap.NewNop())
	r := gin.New()
	RegisterRoutes(r, svc, func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusTeapot, gin.H{"stub": "the auth middleware ran"})
	})
	if svc.agentHandler == nil {
		t.Fatal("agentHandler is nil under this test configuration, so RegisterRoutes skipped the " +
			"public agent group — the derivation below would report a surface smaller than the service has")
	}
	if svc.remoteSupportHandler == nil {
		t.Fatal("remoteSupportHandler is nil under this test configuration, so the agent's remote-support " +
			"routes were never registered and the derivation below cannot see them")
	}
	return r
}

// driveAnonymously sends one credential-free request to a route and reports the
// status, or the panic if the handler reached for something that is not there.
func driveAnonymously(r *gin.Engine, method, path string) (code int, panicked any) {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		switch {
		case strings.HasPrefix(p, ":"):
			parts[i] = "00000000-0000-0000-0000-000000000000"
		case strings.HasPrefix(p, "*"):
			parts[i] = "probe/rest"
		}
	}
	defer func() { panicked = recover() }()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, strings.Join(parts, "/"), strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w.Code, nil
}

// codePanicked is what unauthenticatedRoutes records for a route whose handler
// ran and then reached for the nil database. It is still an unauthenticated
// route — more so, since it got far enough to need state.
const codePanicked = -1

func describe(code int) string {
	if code == codePanicked {
		return "the handler ran and reached the database before answering"
	}
	return fmt.Sprintf("an anonymous request answered %d", code)
}

// unauthenticatedRoutes derives the set: every route that answers something
// other than the stub middleware's 418.
func unauthenticatedRoutes(t *testing.T, r *gin.Engine) map[string]int {
	t.Helper()
	out := map[string]int{}
	routes := r.Routes()
	// A derivation over nothing would pass silently, which is the failure this
	// repository has been bitten by more than once.
	if len(routes) < 200 {
		t.Fatalf("RegisterRoutes produced only %d routes; the derivation is not seeing the service", len(routes))
	}
	for _, rt := range routes {
		code, panicked := driveAnonymously(r, rt.Method, rt.Path)
		switch {
		case panicked != nil:
			out[rt.Method+" "+rt.Path] = codePanicked
		case code != http.StatusTeapot:
			out[rt.Method+" "+rt.Path] = code
		}
	}
	return out
}

// TestEveryUnauthenticatedAccessRouteIsDeclared is the half that catches a new
// public route. Adding one without a line in publicAccessRoutes turns this red.
func TestEveryUnauthenticatedAccessRouteIsDeclared(t *testing.T) {
	found := unauthenticatedRoutes(t, buildPublicSurfaceRouter(t))

	var undeclared []string
	for key, code := range found {
		if _, ok := publicAccessRoutes[key]; !ok {
			undeclared = append(undeclared, fmt.Sprintf("%s  (%s)", key, describe(code)))
		}
	}
	sort.Strings(undeclared)
	if len(undeclared) != 0 {
		t.Errorf("route(s) reachable without the tenant-JWT middleware and not declared:\n  %s\n\n"+
			"Every one of these is part of the product's unauthenticated attack surface. Add each to "+
			"publicAccessRoutes in this file with the shape of its refusal and the reason it is safe, "+
			"or move it behind the middleware.",
			strings.Join(undeclared, "\n  "))
	}
}

// And the other half: an entry for a route that is now authenticated, or that no
// longer exists, is a decision about nothing. A register nobody prunes is a
// register nobody trusts.
func TestPublicAccessRoutesHasNoStaleEntries(t *testing.T) {
	found := unauthenticatedRoutes(t, buildPublicSurfaceRouter(t))

	var stale []string
	for key := range publicAccessRoutes {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) != 0 {
		t.Errorf("publicAccessRoutes declares route(s) that are no longer reachable without auth "+
			"(moved behind the middleware, renamed, or deleted) — delete the entries:\n  %s",
			strings.Join(stale, "\n  "))
	}
}

// TestEveryPublicAccessRouteSaysWhy keeps "add it to the register" from becoming
// the fix somebody applies without thinking about it.
func TestEveryPublicAccessRouteSaysWhy(t *testing.T) {
	for key, r := range publicAccessRoutes {
		if len(strings.TrimSpace(r.why)) < 40 {
			t.Errorf("publicAccessRoutes[%q] has no real reason (%q) — say what authenticates the "+
				"request, or why it needs no authentication", key, r.why)
		}
	}
}

// TestPublicAccessRoutesRefuseAsDeclared drives the declared shape.
//
// The interesting assertion is refusesWithoutState against a NIL DATABASE: a
// handler that refuses an anonymous caller without reading anything cannot
// panic, and one that panics has read something first — which is precisely the
// order J4 found wrong. /agent/report used to take the agent id out of the JSON
// body and write a posture row; now it refuses before the body is read, and this
// is what says so.
func TestPublicAccessRoutesRefuseAsDeclared(t *testing.T) {
	r := buildPublicSurfaceRouter(t)

	for key, decl := range publicAccessRoutes {
		method, path, ok := strings.Cut(key, " ")
		if !ok {
			t.Fatalf("publicAccessRoutes key %q is not %q", key, "METHOD /path")
		}
		t.Run(key, func(t *testing.T) {
			code, panicked := driveAnonymously(r, method, path)

			switch decl.shape {
			case refusesWithoutState:
				if panicked != nil {
					t.Fatalf("declared refusesWithoutState, but an anonymous request reached the "+
						"database before it was refused (panic with a nil pool: %v). The credential "+
						"check has moved behind a lookup — either put it back in front, or change "+
						"the entry to refusesAfterLookup and say so.", panicked)
				}
				if code < 400 || code > 499 {
					t.Errorf("declared refusesWithoutState, anonymous request answered %d; want 4xx", code)
				}
			case refusesAfterLookup:
				if panicked != nil {
					t.Fatalf("declared refusesAfterLookup, but the lookup panicked rather than "+
						"failing closed on an unreachable database: %v", panicked)
				}
				if code < 400 || code > 499 {
					t.Errorf("declared refusesAfterLookup, anonymous request answered %d; want 4xx", code)
				}
			case servesAnonymously:
				// Nothing to assert: answering is the job. The reason is the
				// decision, and TestEveryPublicAccessRouteSaysWhy checks that one
				// was written. Recorded here so the switch is exhaustive and a
				// new shape cannot be added without deciding what it means.
			default:
				t.Fatalf("unknown refusal shape %d", decl.shape)
			}
		})
	}
}
