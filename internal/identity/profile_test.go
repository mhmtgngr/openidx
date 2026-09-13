package identity

import (
	"bytes"
	"encoding/json"
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
	"POST /providers",
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
