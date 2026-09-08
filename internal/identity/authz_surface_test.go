package identity

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
	"github.com/openidx/openidx/internal/common/database"
)

// THE AUTHORIZATION SURFACE OF identity-service, DERIVED RATHER THAN LISTED.
//
// identity-service registers 182 routes and puts them in three tiers: eight are
// answered without any credential, some are open to every authenticated user
// ("self-service"), and the rest need an admin role. The tier is decided by
// requireAdminUnlessSelfService, which asks isIdentitySelfService.
//
// That predicate used to be asked about the PATH THE CALLER WROTE. gin routes on
// the registered TEMPLATE, and the two are not the same string: gin backtracks
// from a static segment to a parameter when nothing static matches, so
// POST /api/v1/identity/users/me/roles -- a path no route declares -- is served
// by /users/:id/roles, the administrative role-grant handler, while the string
// the caller wrote begins "/users/me/" and the predicate answered "self-service".
// Eleven routes collided that way and every single one leaned the same way:
// admin route, self-service answer. The gate now decides on c.FullPath().
//
// This file is the guard, and it derives rather than reads:
//
//   - the ANONYMOUS tier is derived by driving every route with no credential:
//     a route the auth middleware answers is inside it BY CONSTRUCTION, and one
//     that reaches its handler is not;
//   - the SELF-SERVICE tier is derived by driving every route through the REAL
//     requireAdminUnlessSelfService with a token carrying no admin role;
//   - the COLLISION census is derived from the route table's own vocabulary: for
//     every route with a parameter, every static segment any route uses is tried
//     in that slot, and the gate's answer for the crafted path must equal its
//     answer for the route gin actually chose.
//
// What is written down is only the DECISION about each route in the two tiers
// below admin -- with a reason, because "any authenticated user may do this" is
// a decision somebody has to own. Both halves are checked: an undeclared route
// in either tier is a finding, and an entry for a route that has since moved
// behind the admin gate is a stale decision.
type authzTier int

const (
	// tierAnonymous: no credential at all. These are the routes in the public
	// group -- the pre-login bootstrap calls and the token-bearing flows whose
	// token IS the credential (an invitation, a verification link, a reset).
	tierAnonymous authzTier = iota

	// tierAnyAuthenticated: a valid token is required and nothing more. Every
	// operation here acts on the caller's own account, and what bounds it to the
	// caller is either the route template (it names "me", with no parameter that
	// could point elsewhere), the handler reading its subject from the token
	// rather than the request, or -- where the template DOES carry a target --
	// an ownership check, which ownershipChecks makes each route name.
	tierAnyAuthenticated

	// tierAdmin: requires admin or super_admin. This is the default: any route
	// isIdentitySelfService does not recognise lands here, so a new
	// administrative route is protected the moment it is registered. Nothing is
	// declared for this tier -- deny-by-default needs no register.
	tierAdmin
)

func (t authzTier) String() string {
	switch t {
	case tierAnonymous:
		return "anonymous (no credential)"
	case tierAnyAuthenticated:
		return "self-service (any authenticated user)"
	default:
		return "admin"
	}
}

// anonymousIdentityRoutes are the routes that answer with no credential at all.
// The value is why, and it is mandatory: this is the list a reviewer reads to
// see the whole pre-authentication attack surface of identity-service.
var anonymousIdentityRoutes = map[string]string{
	"GET /api/v1/identity/branding":                   "the SPA login page fetches tenant branding before anyone has logged in; it resolves the tenant from ?org=/?domain= itself and returns safe defaults on a miss",
	"GET /api/v1/identity/providers":                  "the login page must list the configured SSO buttons before authentication; returns provider names and types only, never a client secret",
	"POST /api/v1/identity/federation/discover":       "home-realm discovery: the login page maps an email domain to an IdP before the user has any credential",
	"POST /api/v1/identity/invitations/:token/accept": "accepting an invitation is how an account first exists; the single-use invitation token in the path IS the credential",
	"POST /api/v1/identity/mfa/push/enroll/complete":  "a fresh authenticator binds itself using the single-use ticket from the scanned QR, so it cannot first log in as the target user; the ticket's org must match the tenant context",
	"POST /api/v1/identity/users/forgot-password":     "starting a password reset is by definition pre-authentication; answers identically for a known and an unknown address so it cannot be used to enumerate accounts",
	"POST /api/v1/identity/users/reset-password":      "completing a password reset: the single-use reset token in the body IS the credential, and the user has no other one by construction",
	"POST /api/v1/identity/verify-email":              "email verification: the token in the body IS the credential, and it is presented from a mail client with no session",
}

// selfServiceIdentityRoutes are the routes ANY authenticated user may call, with
// no admin role. The value is why that is safe -- what bounds the operation to
// the caller. Routes whose template carries a parameter must ALSO appear in
// ownershipChecks, which is derived, not listed.
var selfServiceIdentityRoutes = map[string]string{
	// ---- the caller's own profile, credentials and records: the template names
	// "me", so there is no target parameter that could point at anybody else.
	"GET /api/v1/identity/users/me":                                  "reads the caller's own profile; the subject comes from the token, and the template has no target parameter",
	"PUT /api/v1/identity/users/me":                                  "updates the caller's own profile; the subject comes from the token, and the template has no target parameter",
	"GET /api/v1/identity/users/me/password-info":                    "reads the caller's own password age and policy state, which the change-password screen needs",
	"POST /api/v1/identity/users/me/change-password":                 "changes the caller's own password and requires the current one; the admin set-password route is a separate, admin-gated template",
	"GET /api/v1/identity/users/me/sessions":                         "lists the caller's own sessions so they can see and end their signed-in devices",
	"GET /api/v1/identity/users/me/tokens":                           "lists the caller's own personal access tokens; the token values themselves are never returned",
	"POST /api/v1/identity/users/me/tokens":                          "mints a personal access token for the caller, carrying no more privilege than the caller already has",
	"GET /api/v1/identity/users/me/consents":                         "lists the OAuth applications the caller has authorized, for their own consent screen",
	"GET /api/v1/identity/users/me/privacy/consents":                 "lists the caller's own GDPR consent record",
	"POST /api/v1/identity/users/me/privacy/consents":                "records a GDPR consent for the caller; the subject comes from the token, never from the body",
	"POST /api/v1/identity/users/me/privacy/dsar":                    "raising a data-subject access request about one's own data is the right the endpoint exists to serve",
	"GET /api/v1/identity/users/me/privacy/dsars":                    "lists the caller's own data-subject access requests and their state",
	"GET /api/v1/identity/users/me/identity-links":                   "lists the external identities linked to the caller's own account",
	"DELETE /api/v1/identity/users/me/tokens/:id":                    "revokes one of the caller's own personal access tokens; the target is bounded by the ownership check below",
	"DELETE /api/v1/identity/users/me/consents/:client_id":           "withdraws the caller's own authorization of an OAuth client; the target is bounded by the ownership check below",
	"DELETE /api/v1/identity/users/me/privacy/consents/:consentType": "withdraws one of the caller's own GDPR consents; the target is bounded by the ownership check below",
	"DELETE /api/v1/identity/users/me/identity-links/:linkId":        "unlinks one of the caller's own external identities; the target is bounded by the ownership check below",
	"POST /api/v1/identity/users/me/mfa/setup":                       "starts MFA enrollment on the caller's own account; a user must be able to add a factor without an administrator",
	"POST /api/v1/identity/users/me/mfa/enable":                      "enables MFA on the caller's own account after they have proved the new factor",
	"POST /api/v1/identity/users/me/mfa/disable":                     "disables MFA on the caller's own account; policy enforcement lives in the handler, not in this gate",
	"GET /api/v1/identity/users/me/mfa/status":                       "reads whether the caller's own account has MFA enabled, which the security page renders",

	// ---- MFA enrollment and verification. Every one of these reads its subject
	// from the token (c.GetString("user_id")), never from the request, so the
	// caller can only ever act on their own factors.
	"GET /api/v1/identity/mfa/methods":                                "lists the factors enrolled on the caller's own account; the subject comes from the token",
	"POST /api/v1/identity/mfa/otp/verify":                            "verifies an OTP the caller was sent, against the caller's own account",
	"GET /api/v1/identity/mfa/backup/count":                           "reports how many unused backup codes the caller has left, so the security page can warn them",
	"POST /api/v1/identity/mfa/backup/generate":                       "regenerates the caller's own backup codes and invalidates the previous set",
	"POST /api/v1/identity/mfa/backup/verify":                         "redeems one of the caller's own backup codes as a second factor",
	"POST /api/v1/identity/mfa/bypass-codes/verify":                   "redemption only: verifies a break-glass code against the caller's own account -- generating, listing, revoking and auditing bypass codes are admin routes",
	"GET /api/v1/identity/mfa/totp/status":                            "reports whether the caller has a TOTP factor enrolled",
	"POST /api/v1/identity/mfa/totp/setup":                            "generates a TOTP secret and QR for the caller's own account",
	"POST /api/v1/identity/mfa/totp/enroll":                           "completes TOTP enrollment on the caller's own account once they prove a code",
	"POST /api/v1/identity/mfa/totp/verify":                           "verifies a TOTP code against the caller's own enrolled secret",
	"DELETE /api/v1/identity/mfa/totp":                                "removes the caller's own TOTP factor; the subject comes from the token",
	"GET /api/v1/identity/mfa/sms/status":                             "reports whether the caller has an SMS factor enrolled and to which masked number",
	"POST /api/v1/identity/mfa/sms/enroll":                            "enrolls an SMS factor on the caller's own account",
	"POST /api/v1/identity/mfa/sms/challenge":                         "sends an SMS code to the caller's own enrolled number",
	"POST /api/v1/identity/mfa/sms/verify":                            "verifies an SMS code against the caller's own enrollment",
	"DELETE /api/v1/identity/mfa/sms":                                 "removes the caller's own SMS factor; the subject comes from the token",
	"GET /api/v1/identity/mfa/email/status":                           "reports whether the caller has an email factor enrolled",
	"POST /api/v1/identity/mfa/email/enroll":                          "enrolls an email factor on the caller's own account",
	"POST /api/v1/identity/mfa/email/challenge":                       "sends an email code to the caller's own enrolled address",
	"POST /api/v1/identity/mfa/email/verify":                          "verifies an email code against the caller's own enrollment",
	"DELETE /api/v1/identity/mfa/email":                               "removes the caller's own email factor; the subject comes from the token",
	"GET /api/v1/identity/mfa/phone/status":                           "reports whether the caller has a phone-call factor enrolled",
	"POST /api/v1/identity/mfa/phone/enroll":                          "enrolls a phone-call factor on the caller's own account",
	"POST /api/v1/identity/mfa/phone/verify":                          "verifies a phone-call code against the caller's own enrollment",
	"POST /api/v1/identity/mfa/phone/callback":                        "the telephony provider's answer webhook for a call this install placed; it carries the provider's own call identifier and updates only that call's attempt",
	"DELETE /api/v1/identity/mfa/phone":                               "removes the caller's own phone-call factor; the subject comes from the token",
	"GET /api/v1/identity/mfa/hardware-token":                         "reports which hardware token is assigned to the caller; assigning and revoking tokens are admin routes under /hardware-tokens",
	"POST /api/v1/identity/mfa/hardware-token/verify":                 "verifies an OTP from the hardware token assigned to the caller",
	"GET /api/v1/identity/mfa/webauthn/credentials":                   "lists the passkeys registered to the caller's own account",
	"DELETE /api/v1/identity/mfa/webauthn/credentials/:credential_id": "removes one of the caller's own passkeys; the target is bounded by the ownership check below",
	"DELETE /api/v1/identity/mfa/push/devices/:device_id":             "removes one of the caller's own push authenticators; the target is bounded by the ownership check below",
	"GET /api/v1/identity/mfa/push/challenge/:challenge_id":           "reads a push challenge so the authenticator can render the approval screen; the target is bounded by the ownership check below",
	"POST /api/v1/identity/mfa/webauthn/register/begin":               "starts passkey registration for the caller; the ceremony is bound to the caller's user handle",
	"POST /api/v1/identity/mfa/webauthn/register/finish":              "completes passkey registration for the caller against the ceremony they started",
	"POST /api/v1/identity/mfa/webauthn/authenticate/begin":           "starts a passkey assertion for the caller's own credentials",
	"POST /api/v1/identity/mfa/webauthn/authenticate/finish":          "completes a passkey assertion against the ceremony the caller started",
	"GET /api/v1/identity/mfa/push/devices":                           "lists the push authenticators registered to the caller's own account",
	"POST /api/v1/identity/mfa/push/devices":                          "registers a push authenticator on the caller's own account",
	"POST /api/v1/identity/mfa/push/register":                         "registers a push authenticator token for the caller; the subject comes from the token",
	"POST /api/v1/identity/mfa/push/enroll/start":                     "starts QR enrollment for the caller and mints the single-use ticket the scanning device completes with",
	"POST /api/v1/identity/mfa/push/challenge":                        "raises a push approval prompt; the handler resolves the subject and refuses to raise one for another account",
	"POST /api/v1/identity/mfa/push/verify":                           "answers a push challenge raised for the caller's own account",

	// ---- trusted browsers: the caller's own remembered devices.
	"GET /api/v1/identity/trusted-browsers":                "lists the caller's own remembered browsers; the subject comes from the token",
	"POST /api/v1/identity/trusted-browsers":               "remembers the caller's current browser so MFA is not re-prompted on it",
	"DELETE /api/v1/identity/trusted-browsers":             "forgets ALL of the caller's own remembered browsers; the subject comes from the token",
	"GET /api/v1/identity/trusted-browsers/check":          "reports whether the caller's current browser is remembered, which the login flow needs",
	"DELETE /api/v1/identity/trusted-browsers/:browser_id": "forgets one of the caller's own remembered browsers; the target is bounded by the ownership check below",

	// ---- ending one of the caller's own sessions.
	"DELETE /api/v1/identity/sessions/:id": "signing a device out is something a user must be able to do without an administrator; the target is bounded by the ownership check below",

	// ---- the remaining two.
	"GET /api/v1/identity/risk-assessment":      "reports the risk signals computed for the caller's own current session, which the security page renders",
	"POST /api/v1/identity/resend-verification": "re-sends the caller's own address-verification email; it acts on the account in the token and nothing else",
}

// ownershipChecks covers the self-service routes whose TEMPLATE CARRIES A
// PARAMETER. Those take a target from the request, so the tier alone does not
// bound them to the caller -- something in the handler must prove the target is
// theirs, and this is where each route names it. The key set is DERIVED (it must
// equal exactly the parameterised self-service routes), so a new self-service
// route with a parameter cannot be added without answering this question.
var ownershipChecks = map[string]string{
	"DELETE /api/v1/identity/sessions/:id":                            "handleTerminateSession: a non-admin caller's session id is looked up and compared to the caller, and a mismatch answers 404 rather than 403 so the id cannot be probed",
	"DELETE /api/v1/identity/users/me/tokens/:id":                     "handleRevokeUserPAT: the UPDATE carries AND user_id = $2 AND org_id = $3 from the token, so another user's key id matches no row and answers 404",
	"DELETE /api/v1/identity/users/me/consents/:client_id":            "handleRevokeUserConsent: both deletes carry WHERE user_id = $1 from the token, so only the caller's grants to that client are revoked",
	"DELETE /api/v1/identity/users/me/privacy/consents/:consentType":  "handleRevokePrivacyConsent: the revocation row is INSERTed with the caller's user_id from the token; the parameter names a consent TYPE, not a record",
	"DELETE /api/v1/identity/users/me/identity-links/:linkId":         "handleUnlinkMyIdentity: the DELETE carries AND user_id = $2 from the token and answers 404 when no row matched",
	"DELETE /api/v1/identity/trusted-browsers/:browser_id":            "handleRevokeTrustedBrowser: RevokeTrustedBrowser takes the caller's user id from the token alongside the browser id",
	"DELETE /api/v1/identity/mfa/webauthn/credentials/:credential_id": "handleDeleteWebAuthnCredential: DeleteWebAuthnCredential takes the caller's user id from the token; the handler's own comment forbids reading it from the request",
	"DELETE /api/v1/identity/mfa/push/devices/:device_id":             "handleDeletePushDevice: DeletePushMFADevice takes the caller's user id from the token; the handler's own comment forbids reading it from the request",
	"GET /api/v1/identity/mfa/push/challenge/:challenge_id":           "handleGetPushChallenge: a challenge belonging to another user answers 404, so a challenge UUID does not leak its app, IP, location and timestamps",
}

// ---------------------------------------------------------------------------

func authzSurfaceService() *Service {
	// A non-nil wrapper with a nil pool: RegisterRoutes reads svc.db.Pool and
	// svc.redis.Client when it builds the permission resolver, and no route this
	// file drives ever reaches a query.
	return NewService(
		&database.PostgresDB{},
		&database.RedisClient{},
		&config.Config{Environment: "production"},
		zap.NewNop(),
	)
}

// identityRoutes returns the service's whole route table, keyed "METHOD /path".
func identityRoutes(t *testing.T) (*gin.Engine, []gin.RouteInfo) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterRoutes(r, authzSurfaceService())
	routes := r.Routes()
	// Vacuity guard: if RegisterRoutes ever stops registering (a nil handler, a
	// build tag, a refactor that moves the groups) this file would pass by
	// having nothing to check.
	if len(routes) < 150 {
		t.Fatalf("identity registered only %d routes; this guard is checking almost nothing. "+
			"Either RegisterRoutes changed shape or the service no longer builds its route table here.", len(routes))
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path == routes[j].Path {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Path < routes[j].Path
	})
	return r, routes
}

func routeKey(method, path string) string { return method + " " + path }

// concretePath substitutes a value for every :param / *wildcard so a template
// can be driven. The value is a UUID because that is what every parameter in
// this service names, and because a value that could collide with a static
// segment is the subject of the collision census below, not of the tier drive.
func concretePath(template string) string {
	segs := strings.Split(template, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") || strings.HasPrefix(s, "*") {
			segs[i] = "11111111-1111-1111-1111-111111111111"
		}
	}
	return strings.Join(segs, "/")
}

// missingCredential is the exact refusal openIDXAuthMiddleware writes when a
// request carries no Authorization header. A route that answers it is inside the
// authenticated group BY CONSTRUCTION; a route that answers anything else was
// never behind that middleware.
const missingCredential = "missing authorization header"

// deriveTiers drives the surface and returns the tier of every route. Nothing is
// read from the registers to compute this.
func deriveTiers(t *testing.T) ([]gin.RouteInfo, map[string]authzTier) {
	t.Helper()
	engine, routes := identityRoutes(t)

	// Tier 1, derived: drive anonymously against the real router.
	tiers := map[string]authzTier{}
	anonymous := map[string]bool{}
	for _, ri := range routes {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(ri.Method, concretePath(ri.Path), strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		reached := func() (reached bool) {
			// A handler that runs at all against the nil pool may panic. That
			// panic is itself the answer: the request got past the middleware.
			defer func() {
				if rec := recover(); rec != nil {
					reached = true
				}
			}()
			engine.ServeHTTP(w, req)
			return !(w.Code == http.StatusUnauthorized && strings.Contains(w.Body.String(), missingCredential))
		}()
		if reached {
			anonymous[routeKey(ri.Method, ri.Path)] = true
			tiers[routeKey(ri.Method, ri.Path)] = tierAnonymous
		}
	}

	// Tiers 2 and 3, derived: drive the REAL requireAdminUnlessSelfService with a
	// token that carries no admin role. The gate is the only thing that separates
	// them, so this is the decision itself and not a model of it.
	gate := authzGateRouter(t, routes, []string{"user"})
	for _, ri := range routes {
		k := routeKey(ri.Method, ri.Path)
		if anonymous[k] {
			continue
		}
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, httptest.NewRequest(ri.Method, concretePath(ri.Path), nil))
		if w.Code == http.StatusForbidden {
			tiers[k] = tierAdmin
		} else {
			tiers[k] = tierAnyAuthenticated
		}
	}
	return routes, tiers
}

// authzGateRouter rebuilds the route table with the real admin gate in front of
// an inert handler, standing in for openIDXAuthMiddleware with a token whose
// roles are given. Rebuilding from the real table keeps gin's matching -- and its
// backtracking, which is the whole subject of the census below -- identical.
func authzGateRouter(t *testing.T, routes []gin.RouteInfo, roles []string) *gin.Engine {
	t.Helper()
	svc := authzSurfaceService()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "11111111-1111-1111-1111-111111111111")
		c.Set("roles", roles)
		c.Next()
	})
	r.Use(svc.requireAdminUnlessSelfService())
	for _, ri := range routes {
		r.Handle(ri.Method, ri.Path, func(c *gin.Context) {
			c.String(http.StatusOK, c.FullPath())
		})
	}
	return r
}

func TestIdentityAuthorizationTiersAreDeclared(t *testing.T) {
	routes, tiers := deriveTiers(t)

	var undeclaredAnon, undeclaredSelf []string
	declaredAnon := map[string]bool{}
	declaredSelf := map[string]bool{}
	for _, ri := range routes {
		k := routeKey(ri.Method, ri.Path)
		switch tiers[k] {
		case tierAnonymous:
			if _, ok := anonymousIdentityRoutes[k]; !ok {
				undeclaredAnon = append(undeclaredAnon, k)
			}
			declaredAnon[k] = true
		case tierAnyAuthenticated:
			if _, ok := selfServiceIdentityRoutes[k]; !ok {
				undeclaredSelf = append(undeclaredSelf, k)
			}
			declaredSelf[k] = true
		}
	}

	if len(undeclaredAnon) > 0 {
		sort.Strings(undeclaredAnon)
		t.Errorf("route(s) answered WITHOUT ANY CREDENTIAL and are not declared in "+
			"anonymousIdentityRoutes:\n  %s\n\nEither the route belongs behind the auth "+
			"middleware -- register it on the `identity` group, not `public` -- or add an "+
			"entry saying why an anonymous caller may have it.",
			strings.Join(undeclaredAnon, "\n  "))
	}
	if len(undeclaredSelf) > 0 {
		sort.Strings(undeclaredSelf)
		t.Errorf("route(s) reachable by ANY AUTHENTICATED USER (no admin role) and not "+
			"declared in selfServiceIdentityRoutes:\n  %s\n\nA route lands here only when "+
			"isIdentitySelfService recognises its template -- most often because it fell "+
			"under an existing prefix rule such as \"/mfa/\". If it is administrative, carve "+
			"it out there; if it is not, add an entry saying what bounds it to the caller.",
			strings.Join(undeclaredSelf, "\n  "))
	}

	var staleAnon, staleSelf []string
	for k := range anonymousIdentityRoutes {
		if !declaredAnon[k] {
			staleAnon = append(staleAnon, k)
		}
	}
	for k := range selfServiceIdentityRoutes {
		if !declaredSelf[k] {
			staleSelf = append(staleSelf, k)
		}
	}
	if len(staleAnon) > 0 {
		sort.Strings(staleAnon)
		t.Errorf("anonymousIdentityRoutes declares route(s) that no longer answer without a "+
			"credential (moved behind the auth middleware, renamed, or deleted) -- delete the "+
			"entries:\n  %s", strings.Join(staleAnon, "\n  "))
	}
	if len(staleSelf) > 0 {
		sort.Strings(staleSelf)
		t.Errorf("selfServiceIdentityRoutes declares route(s) that are no longer reachable "+
			"without an admin role (moved behind the admin gate, renamed, or deleted) -- "+
			"delete the entries:\n  %s", strings.Join(staleSelf, "\n  "))
	}

	t.Logf("identity authorization surface: %d routes -- %d %s, %d %s, %d %s",
		len(routes),
		countTier(tiers, tierAnonymous), tierAnonymous,
		countTier(tiers, tierAnyAuthenticated), tierAnyAuthenticated,
		countTier(tiers, tierAdmin), tierAdmin)
}

func countTier(tiers map[string]authzTier, want authzTier) int {
	n := 0
	for _, v := range tiers {
		if v == want {
			n++
		}
	}
	return n
}

func TestEveryDeclaredIdentityRouteSaysWhy(t *testing.T) {
	const minReason = 40
	check := func(register string, m map[string]string) {
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if len(strings.TrimSpace(m[k])) < minReason {
				t.Errorf("%s[%q] has no real reason (%d chars). The register exists so a "+
					"reviewer can read what was decided and why; an empty or one-word entry "+
					"records the decision and loses the argument for it.",
					register, k, len(strings.TrimSpace(m[k])))
			}
		}
	}
	check("anonymousIdentityRoutes", anonymousIdentityRoutes)
	check("selfServiceIdentityRoutes", selfServiceIdentityRoutes)
	check("ownershipChecks", ownershipChecks)
}

func TestParameterisedSelfServiceRoutesNameTheirOwnershipCheck(t *testing.T) {
	routes, tiers := deriveTiers(t)

	// Derived: a self-service route whose template carries a parameter takes its
	// target from the request. Nothing in the tier bounds it to the caller, so
	// the handler must, and the register must say where.
	want := map[string]bool{}
	for _, ri := range routes {
		k := routeKey(ri.Method, ri.Path)
		if tiers[k] != tierAnyAuthenticated {
			continue
		}
		if strings.Contains(ri.Path, "/:") || strings.Contains(ri.Path, "/*") {
			want[k] = true
		}
	}

	var missing, stale []string
	for k := range want {
		if _, ok := ownershipChecks[k]; !ok {
			missing = append(missing, k)
		}
	}
	for k := range ownershipChecks {
		if !want[k] {
			stale = append(stale, k)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("self-service route(s) whose template names a TARGET, with nothing in "+
			"ownershipChecks saying how the handler proves the target belongs to the "+
			"caller:\n  %s\n\nThis is the IDOR question. Answer it by naming the check "+
			"(a WHERE clause carrying the token's user id, or an explicit comparison), or "+
			"move the route behind the admin gate.", strings.Join(missing, "\n  "))
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("ownershipChecks names route(s) that are no longer parameterised "+
			"self-service routes -- delete the entries:\n  %s", strings.Join(stale, "\n  "))
	}
}

// THE CENSUS. A route's tier must be a property of the route gin chose, never of
// the string the caller wrote. This derives every way the two could disagree from
// the route table's own vocabulary -- every static segment any route uses, tried
// in every parameter slot -- and drives each one through the real gate.
//
// Restoring the old c.Request.URL.Path read in requireAdminUnlessSelfService
// fails this with eleven entries, every one of them an administrative route
// answering a non-admin caller.
func TestSelfServiceTierFollowsTheMatchedRouteNotTheRequestPath(t *testing.T) {
	_, routes := identityRoutes(t)
	gate := authzGateRouter(t, routes, []string{"user"})

	vocabulary := map[string]bool{}
	for _, ri := range routes {
		for _, s := range strings.Split(ri.Path, "/") {
			if s == "" || strings.HasPrefix(s, ":") || strings.HasPrefix(s, "*") {
				continue
			}
			vocabulary[s] = true
		}
	}
	if len(vocabulary) < 50 {
		t.Fatalf("only %d static segments in the route table; the census would try almost "+
			"nothing", len(vocabulary))
	}

	type collision struct{ method, path, matched string }
	var collisions []collision
	tried := map[string]bool{}
	for _, ri := range routes {
		segs := strings.Split(ri.Path, "/")
		for i, s := range segs {
			if !strings.HasPrefix(s, ":") && !strings.HasPrefix(s, "*") {
				continue
			}
			for candidate := range vocabulary {
				trial := append([]string{}, segs...)
				trial[i] = candidate
				path := concretePath(strings.Join(trial, "/"))
				if tried[ri.Method+path] {
					continue
				}
				tried[ri.Method+path] = true

				w := httptest.NewRecorder()
				gate.ServeHTTP(w, httptest.NewRequest(ri.Method, path, nil))
				if w.Code == http.StatusNotFound {
					continue // nothing serves it; there is no tier to disagree about
				}
				// The handler echoes the template gin matched. What the gate
				// decided for the request must be what it decides for that
				// template -- if it is not, the caller moved a route between
				// tiers with a path segment.
				matched := w.Body.String()
				if w.Code == http.StatusForbidden {
					// The gate refused, so nothing echoed the template. Find it.
					matched = matchedTemplate(t, routes, ri.Method, path)
					if matched == "" {
						continue
					}
					if isIdentitySelfService(matched) {
						collisions = append(collisions, collision{ri.Method, path, matched})
					}
					continue
				}
				if matched != "" && !isIdentitySelfService(matched) {
					collisions = append(collisions, collision{ri.Method, path, matched})
				}
			}
		}
	}

	if len(collisions) > 0 {
		sort.Slice(collisions, func(i, j int) bool { return collisions[i].path < collisions[j].path })
		var b strings.Builder
		for _, c := range collisions {
			fmt.Fprintf(&b, "\n  %-6s %s\n         served by %s, but the gate answered as though it were a different route",
				c.method, c.path, c.matched)
		}
		t.Errorf("the authorization tier disagreed with the route gin actually chose, for "+
			"%d crafted path(s):%s\n\nA tier must be a property of the matched route. Decide "+
			"on c.FullPath(), never on c.Request.URL.Path: gin backtracks from a static "+
			"segment to a parameter, so a caller can write a path that reads like one route "+
			"and is served by another.", len(collisions), b.String())
	}
}

// matchedTemplate reports which registered template serves a concrete path.
func matchedTemplate(t *testing.T, routes []gin.RouteInfo, method, path string) string {
	t.Helper()
	r := gin.New()
	var matched string
	for _, ri := range routes {
		r.Handle(ri.Method, ri.Path, func(c *gin.Context) { matched = c.FullPath(); c.Status(http.StatusOK) })
	}
	matched = ""
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, path, nil))
	return matched
}

// The gate runs on a route group, so gin has always matched a route by the time
// it executes and c.FullPath() cannot be empty. Should that ever stop being
// true, the missing route name must not read as "self-service".
func TestAdminGateFailsClosedWithoutAMatchedRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := authzSurfaceService()
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("roles", []string{"user"}); c.Next() })
	r.Use(svc.requireAdminUnlessSelfService())
	r.NoRoute(func(c *gin.Context) { c.String(http.StatusOK, "reached the handler") })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/identity/users/me/tokens", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("with no route matched the gate answered %d (%s); it must refuse, because "+
			"an unnamed route cannot be shown to be self-service", w.Code, w.Body.String())
	}
}
