package identity

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

// Service planes, as drawn by availability class rather than by data
// ownership (global-scale design §4.3, ADR-2). identity-service straddles two
// of them: completing a login is the ISSUE plane, and managing users, roles
// and policies is the ADMIN plane. ADMIN is the first plane shed under load,
// so a flood against the admin console must not take the login path with it —
// which it does as long as both are served by the same process.
type servicePlane uint8

const (
	// planeIssue is exercised by a principal who is not yet (fully) signed in:
	// the login surface, and every factor a login or step-up has to challenge,
	// verify or enrol.
	planeIssue servicePlane = iota
	// planeAdmin is everything a signed-in operator or user does afterwards:
	// user/role/group CRUD, providers, policies, settings, analytics,
	// lifecycle, and self-service profile management.
	planeAdmin
)

func (p servicePlane) String() string {
	if p == planeIssue {
		return "issue"
	}
	return "admin"
}

// Profile selects which plane this identity-service process serves. It is read
// from SERVICE_PROFILE once at startup (global-scale plan task 3.4).
//
// ProfileAll is the default and registers every route, which is exactly what a
// single identity-service did before the split — so an existing deployment
// that never sets SERVICE_PROFILE behaves identically.
type Profile string

const (
	// ProfileAll serves both planes: today's behaviour, and the default.
	ProfileAll Profile = "all"
	// ProfileAuth serves the ISSUE plane only.
	ProfileAuth Profile = "auth"
	// ProfileAdmin serves the ADMIN plane only.
	ProfileAdmin Profile = "admin"
)

// ParseProfile reads SERVICE_PROFILE. Unlike RLS_MODE — where an unrecognised
// value falls back to the safe mode — a typo here is refused outright: the
// point of the flag is that the auth pod does NOT serve admin routes, and a
// process that silently served both would give away the isolation it was
// deployed for without saying so.
func ParseProfile(v string) (Profile, error) {
	switch p := Profile(strings.ToLower(strings.TrimSpace(v))); p {
	case "", ProfileAll:
		return ProfileAll, nil
	case ProfileAuth, ProfileAdmin:
		return p, nil
	default:
		return "", fmt.Errorf("unknown SERVICE_PROFILE %q: want one of %q, %q, %q", v, ProfileAll, ProfileAuth, ProfileAdmin)
	}
}

// serves reports whether this profile registers routes on the given plane.
func (p Profile) serves(plane servicePlane) bool {
	switch p {
	case ProfileAuth:
		return plane == planeIssue
	case ProfileAdmin:
		return plane == planeAdmin
	default:
		return true
	}
}

// routePlanes assigns every identity-service route to a plane. The key is
// "METHOD path", with the path exactly as registered (relative to
// /api/v1/identity).
//
// A route missing from this table is served by BOTH profiles — an unclassified
// route must never disappear from a running deployment — and
// TestEveryIdentityRouteIsClassified fails until it is added here, so the gap
// is loud in CI rather than silent in production.
//
// The rule: ISSUE is what an unauthenticated or partially-authenticated
// principal needs to finish signing in, plus a user's own authentication
// factors (enrol, challenge, verify, remove). Everything else is ADMIN —
// including self-service profile, tokens, consents and privacy, which belong
// to the portal rather than to the login.
var routePlanes = map[string]servicePlane{
	"POST /users/forgot-password":                     planeIssue,
	"POST /users/reset-password":                      planeIssue,
	"POST /verify-email":                              planeIssue,
	"POST /invitations/:token/accept":                 planeIssue,
	"GET /providers":                                  planeIssue,
	"GET /branding":                                   planeIssue,
	"POST /federation/discover":                       planeIssue,
	"POST /mfa/push/enroll/complete":                  planeIssue,
	"GET /users/me":                                   planeAdmin,
	"PUT /users/me":                                   planeAdmin,
	"GET /users/me/password-info":                     planeAdmin,
	"POST /users/me/change-password":                  planeAdmin,
	"POST /users/me/mfa/setup":                        planeIssue,
	"POST /users/me/mfa/enable":                       planeIssue,
	"POST /users/me/mfa/disable":                      planeIssue,
	"GET /users/me/mfa/status":                        planeIssue,
	"GET /users/me/sessions":                          planeAdmin,
	"GET /users/me/tokens":                            planeAdmin,
	"POST /users/me/tokens":                           planeAdmin,
	"DELETE /users/me/tokens/:id":                     planeAdmin,
	"GET /users/me/consents":                          planeAdmin,
	"DELETE /users/me/consents/:client_id":            planeAdmin,
	"GET /users/me/privacy/consents":                  planeAdmin,
	"POST /users/me/privacy/consents":                 planeAdmin,
	"DELETE /users/me/privacy/consents/:consentType":  planeAdmin,
	"POST /users/me/privacy/dsar":                     planeAdmin,
	"GET /users/me/privacy/dsars":                     planeAdmin,
	"GET /users/me/identity-links":                    planeAdmin,
	"DELETE /users/me/identity-links/:linkId":         planeAdmin,
	"GET /users":                                      planeAdmin,
	"POST /users":                                     planeAdmin,
	"GET /users/search":                               planeAdmin,
	"GET /users/export":                               planeAdmin,
	"POST /users/import":                              planeAdmin,
	"GET /users/:id":                                  planeAdmin,
	"PUT /users/:id":                                  planeAdmin,
	"DELETE /users/:id":                               planeAdmin,
	"POST /users/:id/reset-password":                  planeAdmin,
	"POST /users/:id/set-password":                    planeAdmin,
	"POST /providers":                                 planeAdmin,
	"GET /providers/:id":                              planeAdmin,
	"PUT /providers/:id":                              planeAdmin,
	"DELETE /providers/:id":                           planeAdmin,
	"GET /users/:id/sessions":                         planeAdmin,
	"DELETE /sessions/:id":                            planeAdmin,
	"GET /roles":                                      planeAdmin,
	"POST /roles":                                     planeAdmin,
	"GET /roles/:id":                                  planeAdmin,
	"PUT /roles/:id":                                  planeAdmin,
	"DELETE /roles/:id":                               planeAdmin,
	"GET /permissions":                                planeAdmin,
	"GET /roles/:id/permissions":                      planeAdmin,
	"PUT /roles/:id/permissions":                      planeAdmin,
	"GET /users/:id/roles":                            planeAdmin,
	"POST /users/:id/roles":                           planeAdmin,
	"DELETE /users/:id/roles/:roleId":                 planeAdmin,
	"PUT /users/:id/roles":                            planeAdmin,
	"GET /users/:id/role-assignments":                 planeAdmin,
	"GET /groups":                                     planeAdmin,
	"POST /groups":                                    planeAdmin,
	"GET /groups/:id":                                 planeAdmin,
	"PUT /groups/:id":                                 planeAdmin,
	"DELETE /groups/:id":                              planeAdmin,
	"GET /groups/:id/members":                         planeAdmin,
	"POST /groups/:id/members":                        planeAdmin,
	"DELETE /groups/:id/members/:userId":              planeAdmin,
	"GET /groups/:id/subgroups":                       planeAdmin,
	"POST /mfa/totp/setup":                            planeIssue,
	"POST /mfa/totp/enroll":                           planeIssue,
	"POST /mfa/totp/verify":                           planeIssue,
	"GET /mfa/totp/status":                            planeIssue,
	"DELETE /mfa/totp":                                planeIssue,
	"POST /mfa/backup/generate":                       planeIssue,
	"POST /mfa/backup/verify":                         planeIssue,
	"GET /mfa/backup/count":                           planeIssue,
	"POST /mfa/webauthn/register/begin":               planeIssue,
	"POST /mfa/webauthn/register/finish":              planeIssue,
	"POST /mfa/webauthn/authenticate/begin":           planeIssue,
	"POST /mfa/webauthn/authenticate/finish":          planeIssue,
	"GET /mfa/webauthn/credentials":                   planeIssue,
	"DELETE /mfa/webauthn/credentials/:credential_id": planeIssue,
	"POST /mfa/push/register":                         planeIssue,
	"POST /mfa/push/devices":                          planeIssue,
	"GET /mfa/push/devices":                           planeIssue,
	"DELETE /mfa/push/devices/:device_id":             planeIssue,
	"POST /mfa/push/enroll/start":                     planeIssue,
	"POST /mfa/push/challenge":                        planeIssue,
	"POST /mfa/push/verify":                           planeIssue,
	"GET /mfa/push/challenge/:challenge_id":           planeIssue,
	"POST /mfa/sms/enroll":                            planeIssue,
	"POST /mfa/sms/verify":                            planeIssue,
	"GET /mfa/sms/status":                             planeIssue,
	"DELETE /mfa/sms":                                 planeIssue,
	"POST /mfa/sms/challenge":                         planeIssue,
	"POST /mfa/email/enroll":                          planeIssue,
	"POST /mfa/email/verify":                          planeIssue,
	"GET /mfa/email/status":                           planeIssue,
	"DELETE /mfa/email":                               planeIssue,
	"POST /mfa/email/challenge":                       planeIssue,
	"POST /mfa/otp/verify":                            planeIssue,
	"GET /mfa/methods":                                planeIssue,
	"POST /trusted-browsers":                          planeIssue,
	"GET /trusted-browsers":                           planeAdmin,
	"DELETE /trusted-browsers/:browser_id":            planeAdmin,
	"DELETE /trusted-browsers":                        planeAdmin,
	"GET /trusted-browsers/check":                     planeIssue,
	"GET /risk-assessment":                            planeIssue,
	"POST /resend-verification":                       planeAdmin,
	"GET /invitations":                                planeAdmin,
	"POST /invitations":                               planeAdmin,
	"DELETE /invitations/:id":                         planeAdmin,
	"POST /users/:id/offboard":                        planeAdmin,
	"GET /hardware-tokens":                            planeAdmin,
	"POST /hardware-tokens":                           planeAdmin,
	"GET /hardware-tokens/:token_id":                  planeAdmin,
	"POST /hardware-tokens/:token_id/assign":          planeAdmin,
	"POST /hardware-tokens/:token_id/unassign":        planeAdmin,
	"POST /hardware-tokens/:token_id/revoke":          planeAdmin,
	"POST /hardware-tokens/:token_id/report-lost":     planeAdmin,
	"GET /hardware-tokens/:token_id/events":           planeAdmin,
	"GET /mfa/hardware-token":                         planeIssue,
	"POST /mfa/hardware-token/verify":                 planeIssue,
	"POST /mfa/phone/enroll":                          planeIssue,
	"POST /mfa/phone/verify":                          planeIssue,
	"GET /mfa/phone/status":                           planeIssue,
	"DELETE /mfa/phone":                               planeIssue,
	"POST /mfa/phone/callback":                        planeIssue,
	"GET /device-trust-requests":                      planeAdmin,
	"POST /device-trust-requests/:request_id/approve": planeAdmin,
	"POST /device-trust-requests/:request_id/reject":  planeAdmin,
	"POST /device-trust-requests/bulk-approve":        planeAdmin,
	"POST /device-trust-requests/bulk-reject":         planeAdmin,
	"GET /device-trust-requests/pending-count":        planeAdmin,
	"GET /device-trust-settings":                      planeAdmin,
	"PUT /device-trust-settings":                      planeAdmin,
	"POST /mfa/bypass-codes":                          planeAdmin,
	"GET /mfa/bypass-codes":                           planeAdmin,
	"DELETE /mfa/bypass-codes/:code_id":               planeAdmin,
	"DELETE /users/:id/bypass-codes":                  planeAdmin,
	"POST /mfa/bypass-codes/verify":                   planeIssue,
	"GET /mfa/bypass-codes/audit":                     planeAdmin,
	"POST /passwordless/magic-link":                   planeIssue,
	"POST /passwordless/magic-link/verify":            planeIssue,
	"POST /passwordless/qr-login":                     planeIssue,
	"POST /passwordless/qr-login/scan":                planeIssue,
	"POST /passwordless/qr-login/approve":             planeIssue,
	"POST /passwordless/qr-login/reject":              planeIssue,
	"GET /passwordless/qr-login/poll":                 planeIssue,
	"GET /passwordless/preferences":                   planeIssue,
	"PUT /passwordless/preferences":                   planeIssue,
	"GET /passwordless/settings":                      planeAdmin,
	"PUT /passwordless/settings":                      planeAdmin,
	"PATCH /passwordless/settings":                    planeAdmin,
	"GET /passwordless/stats":                         planeAdmin,
	"POST /passwordless/magic-link/test":              planeAdmin,
	"GET /biometric/preferences":                      planeIssue,
	"PUT /biometric/preferences":                      planeIssue,
	"POST /biometric/enable-only":                     planeIssue,
	"POST /biometric/disable-only":                    planeIssue,
	"GET /biometric/authenticators":                   planeIssue,
	"GET /biometric/policies":                         planeAdmin,
	"POST /biometric/policies":                        planeAdmin,
	"PUT /biometric/policies/:policy_id":              planeAdmin,
	"DELETE /biometric/policies/:policy_id":           planeAdmin,
	"GET /risk/policies":                              planeAdmin,
	"POST /risk/policies":                             planeAdmin,
	"GET /risk/policies/:id":                          planeAdmin,
	"PUT /risk/policies/:id":                          planeAdmin,
	"DELETE /risk/policies/:id":                       planeAdmin,
	"PATCH /risk/policies/:id/toggle":                 planeAdmin,
	"POST /risk/evaluate":                             planeAdmin,
	"GET /risk/stats":                                 planeAdmin,
	"GET /risk/login-history":                         planeAdmin,
	"GET /analytics/logins":                           planeAdmin,
	"GET /lifecycle/workflows":                        planeAdmin,
	"POST /lifecycle/workflows":                       planeAdmin,
	"GET /lifecycle/workflows/:id":                    planeAdmin,
	"PUT /lifecycle/workflows/:id":                    planeAdmin,
	"DELETE /lifecycle/workflows/:id":                 planeAdmin,
	"POST /lifecycle/workflows/:id/execute":           planeAdmin,
	"GET /lifecycle/executions":                       planeAdmin,
	"GET /lifecycle/executions/:id":                   planeAdmin,
}

// planeOf classifies a route. Unknown routes are served by every profile; see
// routePlanes.
func planeOf(method, path string) (servicePlane, bool) {
	p, ok := routePlanes[method+" "+path]
	return p, ok
}

// planeGroup is a *gin.RouterGroup that drops the routes this process's
// profile does not serve. The wrapper carries the policy so the 182
// registration lines below stay exactly as they were — the same move that put
// the tenant scope in database.ScopedPool instead of in 1,967 call sites.
type planeGroup struct {
	group   *gin.RouterGroup
	profile Profile
	// skipped records what this profile declined to register, for the startup
	// log line and for tests.
	skipped []string
}

func newPlaneGroup(g *gin.RouterGroup, p Profile) *planeGroup {
	return &planeGroup{group: g, profile: p}
}

func (g *planeGroup) Use(m ...gin.HandlerFunc) { g.group.Use(m...) }

func (g *planeGroup) GET(path string, h ...gin.HandlerFunc)  { g.handle(http.MethodGet, path, h...) }
func (g *planeGroup) POST(path string, h ...gin.HandlerFunc) { g.handle(http.MethodPost, path, h...) }
func (g *planeGroup) PUT(path string, h ...gin.HandlerFunc)  { g.handle(http.MethodPut, path, h...) }
func (g *planeGroup) PATCH(path string, h ...gin.HandlerFunc) {
	g.handle(http.MethodPatch, path, h...)
}
func (g *planeGroup) DELETE(path string, h ...gin.HandlerFunc) {
	g.handle(http.MethodDelete, path, h...)
}

func (g *planeGroup) handle(method, path string, h ...gin.HandlerFunc) {
	if plane, known := planeOf(method, path); known && !g.profile.serves(plane) {
		g.skipped = append(g.skipped, method+" "+path)
		return
	}
	g.group.Handle(method, path, h...)
}

// skippedRoutes returns what the profile declined, sorted.
func skippedRoutes(groups ...*planeGroup) []string {
	var out []string
	for _, g := range groups {
		out = append(out, g.skipped...)
	}
	sort.Strings(out)
	return out
}

// ServesIssue reports whether this profile serves the ISSUE plane.
func (p Profile) ServesIssue() bool { return p.serves(planeIssue) }

// ServesAdmin reports whether this profile serves the ADMIN plane. Callers
// outside this package use it for the route sets identity-service mounts but
// does not own -- the portal and notification groups in cmd/identity-service,
// which are console surfaces and belong to ADMIN.
func (p Profile) ServesAdmin() bool { return p.serves(planeAdmin) }

// RoutePrefix is where identity-service mounts every route it owns.
const RoutePrefix = "/api/v1/identity"

// PlaneManifest is the classification as data: the same table the process uses
// to decide what to register, in the form the edge needs to decide where to
// send a request.
//
// It is written to the chart as files/identity-planes.json and kept in step
// with routePlanes by TestPlaneManifestMatchesTheRouteTable, so the routing
// rules are generated from the table rather than retyped beside it — the same
// arrangement the edge rule set already uses (deployments/terraform, §5.3).
//
// Regenerate with: go run ./tools/identityplanes
type PlaneManifest struct {
	// Generator names what produced the file, for whoever finds it first.
	Generator string `json:"generated_by"`
	// Prefix is the mount point every Route below is relative to.
	Prefix string `json:"prefix"`
	// Issue and Admin are "METHOD /path", sorted.
	Issue []string `json:"issue"`
	Admin []string `json:"admin"`
}

// BuildPlaneManifest renders the manifest from routePlanes.
func BuildPlaneManifest() PlaneManifest {
	m := PlaneManifest{
		Generator: "go run ./tools/identityplanes (source: internal/identity/profile.go routePlanes)",
		Prefix:    RoutePrefix,
		Issue:     []string{},
		Admin:     []string{},
	}
	for route, plane := range routePlanes {
		if plane == planeIssue {
			m.Issue = append(m.Issue, route)
		} else {
			m.Admin = append(m.Admin, route)
		}
	}
	sort.Strings(m.Issue)
	sort.Strings(m.Admin)
	return m
}

// PlaneManifestJSON renders the manifest exactly as the file on disk holds it:
// indented, with a trailing newline, so a byte comparison is a fair test.
func PlaneManifestJSON() ([]byte, error) {
	b, err := json.MarshalIndent(BuildPlaneManifest(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
