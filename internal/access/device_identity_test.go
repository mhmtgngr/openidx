package access

import (
	"reflect"
	"testing"
)

// A device identity carries its own markers and its user's reach, never the
// user-only markers, and trust only when told so.
func TestDeviceAttributesFromKeepsReachAndDropsUserMarkers(t *testing.T) {
	user := []string{"Finance", "enrolled-users", "device-trusted", "browzer-users", "app-11111111", "jit-req-1", "org-o1"}
	got := deviceAttributesFrom("agent-1", "user-uuid", user, true)
	want := []string{"openidx-agent", "device-agent-1", "user-user-uuid", "Finance", "enrolled-users", "app-11111111", "jit-req-1", "org-o1", "device-trusted"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("attrs = %v, want %v", got, want)
	}
	got = deviceAttributesFrom("agent-2", "", nil, false)
	if !reflect.DeepEqual(got, []string{"openidx-agent", "device-agent-2"}) {
		t.Errorf("a device with no user and no trust = %v", got)
	}
	for _, a := range []string{"device-agent-1", "user-user-uuid", "posture-ok-x"} {
		if !zitiManagedAttr(a) {
			t.Errorf("%s is not a managed attribute; the attribute guard would let a client claim it", a)
		}
	}
}

// With assignment enforced and the route requiring a trusted device, the
// dial policy is AllOf [#app, #device-trusted]; anything less keeps AnyOf.
func TestDialPolicyRequiresADeviceOnlyWhenItCanRefuse(t *testing.T) {
	roles, sem := dialPolicyFor("#access-proxy-clients", "app1", true, true)
	if sem != "AllOf" || !reflect.DeepEqual(roles, []string{"#" + appMarkerAttr("app1"), "#device-trusted"}) {
		t.Errorf("enforced + trust: roles=%v sem=%s", roles, sem)
	}
	for name, c := range map[string]struct {
		app     string
		enforce bool
		trust   bool
	}{
		"observe mode":       {"app1", false, true},
		"no application":     {"", true, true},
		"trust not required": {"app1", true, false},
		"nothing at all":     {"", false, false},
		"observe, no trust":  {"app1", false, false},
	} {
		roles, sem := dialPolicyFor("#blanket", c.app, c.enforce, c.trust)
		if sem != "AnyOf" {
			t.Errorf("%s: semantic %s, want AnyOf", name, sem)
		}
		if !reflect.DeepEqual(roles, dialIdentityRoles("#blanket", c.app, c.enforce)) {
			t.Errorf("%s: roles %v differ from dialIdentityRoles", name, roles)
		}
	}
	if policySemantic("allof") != "AllOf" || policySemantic("") != "AnyOf" || policySemantic("whatever") != "AnyOf" {
		t.Error("policySemantic does not normalise to AllOf/AnyOf")
	}
}

// The user identity never carries #device-trusted any more.
func TestUserIdentityNeverCarriesDeviceTrust(t *testing.T) {
	attrs := assembleAttributes([]string{"Finance"}, false, true, []string{"app-1"})
	for _, a := range attrs {
		if a == "device-trusted" {
			t.Fatal("user attributes carry device-trusted")
		}
	}
	// assembleAttributes still honours its flag, since the dark-tier tests
	// use it; buildUserAttributes is what passes false.
	attrs = assembleAttributes(nil, true, false, nil)
	found := false
	for _, a := range attrs {
		found = found || a == "device-trusted"
	}
	if !found {
		t.Fatal("assembleAttributes dropped the flag it was given")
	}
}
