package access

import "testing"

func containsAttr(attrs []string, want string) bool {
	for _, a := range attrs {
		if a == want {
			return true
		}
	}
	return false
}

func TestAssembleAttributesAlwaysIncludesEnrolledUsers(t *testing.T) {
	attrs := assembleAttributes([]string{"engineering"}, false /*deviceTrusted*/, false /*browzer*/)
	if !containsAttr(attrs, "enrolled-users") {
		t.Errorf("attrs %v missing enrolled-users", attrs)
	}
	if !containsAttr(attrs, "engineering") {
		t.Errorf("attrs %v missing the group name", attrs)
	}
}

func TestAssembleAttributesDeviceTrustedGated(t *testing.T) {
	trusted := assembleAttributes(nil, true, false)
	untrusted := assembleAttributes(nil, false, false)
	if !containsAttr(trusted, "device-trusted") {
		t.Error("a trusted device should carry #device-trusted")
	}
	if containsAttr(untrusted, "device-trusted") {
		t.Error("an untrusted device must NOT carry #device-trusted")
	}
	// enrolled-users is present regardless of trust
	if !containsAttr(untrusted, "enrolled-users") {
		t.Error("enrolled-users must be present even without device trust")
	}
}

func TestAssembleAttributesBrowZerGated(t *testing.T) {
	on := assembleAttributes(nil, false, true)
	off := assembleAttributes(nil, false, false)
	if !containsAttr(on, "browzer-users") {
		t.Error("browzer on should carry #browzer-users")
	}
	if containsAttr(off, "browzer-users") {
		t.Error("browzer off must NOT carry #browzer-users")
	}
}
