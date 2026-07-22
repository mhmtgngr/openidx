package access

import (
	"strings"
	"testing"
)

// Dark-platform tier invariants (spec:
// docs/superpowers/specs/2026-07-17-dark-platform-ziti-first-design.md).
// These are the load-bearing safety properties of the dark cutover. They are
// mutation-checked: see dark-drill / the plan's Step 3 (flip a tier attr and
// these MUST fail). Keep them strict.

// TestTier2ServicesRequireDeviceTrust: every dark service carries a known tier
// attribute, and the management/data-plane surfaces are Tier 2 (#device-trusted,
// not merely #enrolled-users). A Tier-2 surface downgraded to Tier 1 would let
// any enrolled (but untrusted-device) user dial the admin/data plane.
func TestTier2ServicesRequireDeviceTrust(t *testing.T) {
	mustBeTier2 := map[string]bool{
		"openidx-admin-api":    true,
		"openidx-governance":   true,
		"openidx-audit":        true,
		"openidx-provisioning": true,
		"openidx-scim":         true,
		"openidx-access":       true,
	}
	seen := map[string]bool{}
	for _, d := range defaultDarkServices() {
		seen[d.name] = true
		switch d.tierAttr {
		case "device-trusted", "enrolled-users":
		default:
			t.Errorf("%s has unexpected tier attr %q (want device-trusted|enrolled-users)", d.name, d.tierAttr)
		}
		if mustBeTier2[d.name] && d.tierAttr != "device-trusted" {
			t.Errorf("%s must be Tier 2 (#device-trusted), got %q", d.name, d.tierAttr)
		}
	}
	for name := range mustBeTier2 {
		if !seen[name] {
			t.Errorf("required Tier-2 dark surface %q missing from defaultDarkServices()", name)
		}
	}
}

// TestNoTier0SurfaceIsDarked: the bootstrap gate (enroll / oauth / well-known /
// jwks) must NEVER be modeled as a dark service — darking it bricks enrollment
// and login, making the platform unrecoverable without break-glass.
func TestNoTier0SurfaceIsDarked(t *testing.T) {
	forbidden := []string{"enroll", "oauth", "wellknown", "well-known", "jwks", "openid-config"}
	for _, d := range defaultDarkServices() {
		low := strings.ToLower(d.name)
		for _, f := range forbidden {
			if strings.Contains(low, f) {
				t.Errorf("Tier-0 bootstrap surface %q must never be a dark service", d.name)
			}
		}
	}
}

// TestDarkServiceUpstreamsAreLoopback: every dark upstream must be loopback —
// the router hosts it locally, and a non-loopback upstream would re-expose the
// surface on a routable interface, defeating the dark posture.
func TestDarkServiceUpstreamsAreLoopback(t *testing.T) {
	for _, d := range defaultDarkServices() {
		if !strings.HasPrefix(d.upstream, "127.0.0.1:") && !strings.HasPrefix(d.upstream, "localhost:") {
			t.Errorf("%s upstream %q is not loopback (dark services must bind loopback)", d.name, d.upstream)
		}
	}
}

// TestDarkServiceNamesAreUnique: duplicate names would make the reconciler and
// the console seed disagree about which surface a Ziti service maps to.
func TestDarkServiceNamesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range defaultDarkServices() {
		if seen[d.name] {
			t.Errorf("duplicate dark service name %q", d.name)
		}
		seen[d.name] = true
	}
}
