package identity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// THE PLANE SPLIT OF identity-service, CHECKED AGAINST THE REAL ROUTE TABLE.
//
// SERVICE_PROFILE lets one binary run as two deployments: the ISSUE plane, which
// finishes logins, and the ADMIN plane, which is the first thing shed when the
// platform is under load. The split is only worth deploying if it is exact --
// a login route misfiled as ADMIN means logins break the moment ADMIN is shed,
// and an admin route misfiled as ISSUE means the flood you shed still lands.
//
// So nothing here reads the classification table on its own terms. Every
// assertion drives RegisterRoutesForProfile against a real gin engine and looks
// at the routes that actually got registered.

const identityPrefix = "/api/v1/identity"

// routesFor returns the routes a profile actually registers, keyed
// "METHOD /path" with the /api/v1/identity prefix stripped -- the same spelling
// routePlanes uses.
func routesFor(t *testing.T, p Profile) map[string]bool {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterRoutesForProfile(r, authzSurfaceService(), p)
	out := map[string]bool{}
	for _, rt := range r.Routes() {
		path := strings.TrimPrefix(rt.Path, identityPrefix)
		out[rt.Method+" "+path] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Every route the service registers must be classified, and every entry in the
// table must still correspond to a route. The first half stops a new route from
// quietly landing on both planes; the second stops the table from accumulating
// entries for routes that have since been renamed or deleted.
func TestEveryIdentityRouteIsClassified(t *testing.T) {
	all := routesFor(t, ProfileAll)
	if len(all) < 150 {
		t.Fatalf("identity registered only %d routes; this guard is checking almost nothing", len(all))
	}

	var unclassified []string
	for _, k := range sortedKeys(all) {
		if _, ok := routePlanes[k]; !ok {
			unclassified = append(unclassified, k)
		}
	}
	if len(unclassified) > 0 {
		t.Errorf("%d identity route(s) have no plane in routePlanes (they are served by BOTH profiles until classified):\n  %s",
			len(unclassified), strings.Join(unclassified, "\n  "))
	}

	var stale []string
	for k := range routePlanes {
		if !all[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("%d entr(ies) in routePlanes name a route that is no longer registered:\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}
}

// The default profile must register exactly what the service registered before
// the split existed: an install that never sets SERVICE_PROFILE sees no change.
func TestProfileAllRegistersEverything(t *testing.T) {
	all := routesFor(t, ProfileAll)
	auth := routesFor(t, ProfileAuth)
	admin := routesFor(t, ProfileAdmin)

	for k := range auth {
		if !all[k] {
			t.Errorf("ProfileAuth registers %q but ProfileAll does not", k)
		}
	}
	for k := range admin {
		if !all[k] {
			t.Errorf("ProfileAdmin registers %q but ProfileAll does not", k)
		}
	}
	if len(all) != len(auth)+len(admin) {
		t.Errorf("the two profiles do not add up to the whole: all=%d auth=%d admin=%d",
			len(all), len(auth), len(admin))
	}
}

// The two profiles partition the surface: nothing is served twice, nothing is
// served by neither. A route that fell through both would be unreachable in a
// split deployment while still answering in a single one -- the worst kind of
// difference, because staging would not show it.
func TestAuthAndAdminProfilesPartitionTheSurface(t *testing.T) {
	all := routesFor(t, ProfileAll)
	auth := routesFor(t, ProfileAuth)
	admin := routesFor(t, ProfileAdmin)

	for k := range auth {
		if admin[k] {
			t.Errorf("route %q is served by BOTH profiles", k)
		}
	}
	var orphan []string
	for _, k := range sortedKeys(all) {
		if !auth[k] && !admin[k] {
			orphan = append(orphan, k)
		}
	}
	if len(orphan) > 0 {
		t.Errorf("%d route(s) are served by NEITHER profile, so a split deployment cannot answer them:\n  %s",
			len(orphan), strings.Join(orphan, "\n  "))
	}
}

// loginSurface is the set a login or step-up cannot complete without. It is
// written out rather than derived: if a future edit reclassifies one of these
// as ADMIN, shedding the admin plane would start breaking logins, and this test
// is the only thing that would say so before production did.
var loginSurface = []string{
	"GET /branding",
	"GET /providers",
	"POST /federation/discover",
	"POST /users/forgot-password",
	"POST /users/reset-password",
	"POST /verify-email",
	"POST /invitations/:token/accept",
	"POST /mfa/totp/verify",
	"POST /mfa/backup/verify",
	"POST /mfa/webauthn/authenticate/begin",
	"POST /mfa/webauthn/authenticate/finish",
	"POST /mfa/push/challenge",
	"POST /mfa/push/verify",
	"POST /mfa/sms/challenge",
	"POST /mfa/email/challenge",
	"POST /mfa/otp/verify",
	"GET /mfa/methods",
	"POST /mfa/bypass-codes/verify",
	"POST /mfa/hardware-token/verify",
	"POST /passwordless/magic-link",
	"POST /passwordless/magic-link/verify",
	"POST /passwordless/qr-login",
	"GET /passwordless/qr-login/poll",
	"GET /trusted-browsers/check",
}

func TestLoginSurfaceSurvivesTheAuthProfile(t *testing.T) {
	auth := routesFor(t, ProfileAuth)
	for _, r := range loginSurface {
		if !auth[r] {
			t.Errorf("SERVICE_PROFILE=auth does not serve %q; a login that needs it would fail once the admin plane is shed", r)
		}
	}
}

// The converse, and the reason the split is worth deploying: an admin-only pod
// must not be an alternate login endpoint, or a flood aimed at the console
// still reaches the code the console was separated from.
func TestAdminProfileDropsTheLoginSurface(t *testing.T) {
	admin := routesFor(t, ProfileAdmin)
	for _, r := range loginSurface {
		if admin[r] {
			t.Errorf("SERVICE_PROFILE=admin still serves the login route %q", r)
		}
	}
}

// A representative slice of the ADMIN plane, for the same reason in reverse:
// these are expensive, they are what gets shed, and none of them may leak onto
// the pod that must keep answering.
var adminSurface = []string{
	"GET /users",
	"POST /users",
	"GET /users/search",
	"GET /users/export",
	"POST /users/import",
	"DELETE /users/:id",
	"GET /roles",
	"PUT /roles/:id/permissions",
	"POST /users/:id/roles",
	"GET /groups",
	"GET /analytics/logins",
	"GET /risk/stats",
	"GET /risk/login-history",
	"GET /lifecycle/executions",
	"PUT /providers/:id",
	"GET /device-trust-requests",
	"GET /mfa/bypass-codes",
	"GET /passwordless/stats",
}

func TestAuthProfileDropsTheAdminSurface(t *testing.T) {
	auth := routesFor(t, ProfileAuth)
	for _, r := range adminSurface {
		if auth[r] {
			t.Errorf("SERVICE_PROFILE=auth still serves the admin route %q; the plane split buys nothing for it", r)
		}
	}
	admin := routesFor(t, ProfileAdmin)
	for _, r := range adminSurface {
		if !admin[r] {
			t.Errorf("SERVICE_PROFILE=admin does not serve %q", r)
		}
	}
}

// A profile the operator did not spell correctly is refused, rather than
// quietly serving everything: the flag exists to remove routes, and a typo that
// silently left them in place would hand back the isolation the deployment was
// split to get.
func TestParseProfile(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Profile
	}{
		{"", ProfileAll},
		{"all", ProfileAll},
		{"ALL", ProfileAll},
		{" auth ", ProfileAuth},
		{"Admin", ProfileAdmin},
	} {
		got, err := ParseProfile(tc.in)
		if err != nil {
			t.Errorf("ParseProfile(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseProfile(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"issue", "auth,admin", "athu", "none", "off"} {
		if _, err := ParseProfile(bad); err == nil {
			t.Errorf("ParseProfile(%q) accepted an unknown profile; a typo must not silently serve every route", bad)
		}
	}
}

// The skipped list is what the process logs at startup, so an operator can see
// the split took effect rather than assume it.
func TestSkippedRoutesAreReported(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	if skipped := RegisterRoutesForProfile(r, authzSurfaceService(), ProfileAll); len(skipped) != 0 {
		t.Errorf("ProfileAll skipped %d route(s); it must register everything: %v", len(skipped), skipped)
	}

	r = gin.New()
	skipped := RegisterRoutesForProfile(r, authzSurfaceService(), ProfileAuth)
	admin := routesFor(t, ProfileAdmin)
	if len(skipped) != len(admin) {
		t.Errorf("ProfileAuth reported %d skipped routes but the admin plane has %d", len(skipped), len(admin))
	}
	for _, s := range skipped {
		if !admin[s] {
			t.Errorf("ProfileAuth reported skipping %q, which is not an admin-plane route", s)
		}
	}
	if !sort.StringsAreSorted(skipped) {
		t.Error("skipped routes are not sorted; the startup log line would be unstable")
	}
}

// The chart's copy of the classification must be the table's copy. If it is
// not, the edge would send a request to a pod that does not serve it — and a
// 404 on a login route is the failure this whole split exists to prevent.
func TestPlaneManifestMatchesTheRouteTable(t *testing.T) {
	const path = "../../deployments/kubernetes/helm/openidx/files/identity-planes.json"

	want, err := PlaneManifestJSON()
	if err != nil {
		t.Fatalf("render manifest: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with: go run ./tools/identityplanes)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s has drifted from routePlanes; regenerate with:\n\n\tgo run ./tools/identityplanes\n", path)
	}

	// The file is only worth generating if it is complete: every route the
	// service registers is in it exactly once.
	var m PlaneManifest
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("%s is not valid JSON: %v", path, err)
	}
	if m.Prefix != RoutePrefix {
		t.Errorf("manifest prefix = %q, want %q", m.Prefix, RoutePrefix)
	}
	all := routesFor(t, ProfileAll)
	seen := map[string]int{}
	for _, r := range append(append([]string{}, m.Issue...), m.Admin...) {
		seen[r]++
	}
	for _, r := range sortedKeys(all) {
		switch seen[r] {
		case 1:
		case 0:
			t.Errorf("route %q is registered but missing from the manifest", r)
		default:
			t.Errorf("route %q appears %d times in the manifest", r, seen[r])
		}
	}
	if len(m.Issue) == 0 || len(m.Admin) == 0 {
		t.Fatal("manifest has an empty plane; the edge would route everything one way")
	}
}

// THE SPLIT HAS TO BE ROUTABLE, NOT JUST CORRECT.
//
// Classifying a route decides which POD serves it. Something in front has to
// decide which pod to SEND it to, and the routers in play -- a Kubernetes
// Ingress, an APISIX uri rule -- match on the PATH. A Kubernetes Ingress cannot
// match on the method at all.
//
// So a path served by two planes cannot be routed: whichever pod the rule picks
// answers one of its methods and 404s the other. The same goes for a prefix
// rule derived from a parameterised route that reaches over a route on the
// other plane.
//
// The resolution, whenever this test finds one, is always the same direction:
// the whole path goes to ISSUE. A route wrongly on ISSUE costs a little surface
// on the cheap plane; a route wrongly on ADMIN stops working the moment the
// admin plane is shed, which is the failure the split exists to prevent.

func TestThePlaneSplitIsRoutable(t *testing.T) {
	byPath := map[string]map[string][]string{} // path -> plane -> methods
	for route, plane := range routePlanes {
		method, path, ok := strings.Cut(route, " ")
		if !ok {
			t.Fatalf("malformed route key %q", route)
		}
		if byPath[path] == nil {
			byPath[path] = map[string][]string{}
		}
		byPath[path][plane.String()] = append(byPath[path][plane.String()], method)
	}

	// 1. No path may be served by both planes: no path router can split it.
	var collisions []string
	for _, path := range sortedPaths(byPath) {
		if len(byPath[path]) > 1 {
			issue, admin := byPath[path]["issue"], byPath[path]["admin"]
			sort.Strings(issue)
			sort.Strings(admin)
			collisions = append(collisions, fmt.Sprintf("%s: issue=%v admin=%v", path, issue, admin))
		}
	}
	if len(collisions) > 0 {
		t.Errorf("%d path(s) are served by both planes, so no path router can split them. Move the whole path to ISSUE:\n  %s",
			len(collisions), strings.Join(collisions, "\n  "))
	}

	// 2. No prefix rule an ISSUE route forces may reach over an ADMIN route.
	var prefixes []PlaneRule
	for route, plane := range routePlanes {
		if plane != planeIssue {
			continue
		}
		_, path, _ := strings.Cut(route, " ")
		if r := PlaneRuleFor(path); r.Type == "Prefix" {
			prefixes = append(prefixes, r)
		}
	}
	var reachOver []string
	for _, route := range sortedKeys(mapKeysAsSet(routePlanes)) {
		if routePlanes[route] != planeAdmin {
			continue
		}
		_, path, _ := strings.Cut(route, " ")
		for _, p := range prefixes {
			if PlaneRuleMatches(p, RoutePrefix+path) {
				reachOver = append(reachOver, fmt.Sprintf("%s is ADMIN but falls under the ISSUE prefix %q", route, p.Path))
				break // one prefix is enough; several ISSUE routes share them
			}
		}
	}
	if len(reachOver) > 0 {
		sort.Strings(reachOver)
		t.Errorf("%d ADMIN route(s) sit under a prefix an ISSUE route forces; a path router would send them to the auth pod, which does not serve them:\n  %s",
			len(reachOver), strings.Join(reachOver, "\n  "))
	}

	// 3. The mirror image, with one exemption that is a real routing rule
	// rather than a convenience: Kubernetes gives an Exact path precedence over
	// a Prefix that also matches, so an ISSUE route with no parameter survives
	// an ADMIN prefix reaching over it. An ISSUE route that can only be
	// expressed as a prefix does not, and would be swallowed.
	var adminPrefixes []PlaneRule
	for route, plane := range routePlanes {
		if plane != planeAdmin {
			continue
		}
		_, path, _ := strings.Cut(route, " ")
		if r := PlaneRuleFor(path); r.Type == "Prefix" {
			adminPrefixes = append(adminPrefixes, r)
		}
	}
	var swallowed []string
	for route, plane := range routePlanes {
		if plane != planeIssue {
			continue
		}
		_, path, _ := strings.Cut(route, " ")
		if PlaneRuleFor(path).Type != "Prefix" {
			continue // Exact wins; nothing to answer for.
		}
		for _, p := range adminPrefixes {
			if RoutePrefix+path != p.Path && PlaneRuleMatches(p, RoutePrefix+path) {
				swallowed = append(swallowed,
					fmt.Sprintf("%s is ISSUE and can only be a prefix rule, but sits under the ADMIN prefix %q", route, p.Path))
			}
		}
	}
	if len(swallowed) > 0 {
		sort.Strings(swallowed)
		t.Errorf("%d ISSUE route(s) would be swallowed by an ADMIN prefix; a login request would reach the admin pod:\n  %s",
			len(swallowed), strings.Join(swallowed, "\n  "))
	}
}

func sortedPaths(m map[string]map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mapKeysAsSet(m map[string]servicePlane) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// The rule list is the whole of the edge configuration -- what it does not
// match falls through to the ADMIN plane -- so it has to cover every ISSUE
// route and reach over no ADMIN one. This drives the rules the way a router
// would, against the real route table.
func TestTheGeneratedRulesRouteEveryRoute(t *testing.T) {
	m := BuildPlaneManifest()
	if len(m.IssueRules) == 0 {
		t.Fatal("no routing rules; the edge would send every request to the admin plane, logins included")
	}

	matches := func(full string) bool {
		for _, r := range m.IssueRules {
			if PlaneRuleMatches(r, full) {
				return true
			}
		}
		return false
	}

	for _, route := range m.Issue {
		_, path, _ := strings.Cut(route, " ")
		// A parameterised route is driven with a value in the slot, because
		// that is what arrives: the rule has to match the real request, not the
		// template it was derived from.
		full := RoutePrefix + strings.ReplaceAll(replaceParams(path), "//", "/")
		if !matches(full) {
			t.Errorf("ISSUE route %s (as %s) matches no rule, so the edge would send it to the admin plane", route, full)
		}
	}
	for _, route := range m.Admin {
		_, path, _ := strings.Cut(route, " ")
		full := RoutePrefix + replaceParams(path)
		if matches(full) {
			t.Errorf("ADMIN route %s (as %s) matches an ISSUE rule, so the edge would send it to the auth plane, which 404s it", route, full)
		}
	}
	if !t.Failed() {
		t.Logf("%d rules cover %d ISSUE routes and no ADMIN route", len(m.IssueRules), len(m.Issue))
	}
}

// replaceParams substitutes a concrete value for every ":param" segment.
func replaceParams(path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") {
			segs[i] = "0a1b2c3d-0000-4000-8000-000000000000"
		}
	}
	return strings.Join(segs, "/")
}
