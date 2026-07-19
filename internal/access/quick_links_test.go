package access

import "testing"

func TestValidQuickLinkURL(t *testing.T) {
	ok := []string{"https://teams.microsoft.com", "http://intranet", "mailto:help@x.com", "tel:+15550100"}
	for _, u := range ok {
		if !validQuickLinkURL(u) {
			t.Errorf("expected %q to be valid", u)
		}
	}
	bad := []string{"javascript:alert(1)", "data:text/html,x", "ftp://x", "  ", "file:///etc/passwd"}
	for _, u := range bad {
		if validQuickLinkURL(u) {
			t.Errorf("expected %q to be REJECTED (unsafe scheme)", u)
		}
	}
}

func TestQuickLinkRoleRank(t *testing.T) {
	if quickLinkRank("user") >= quickLinkRank("admin") {
		t.Error("admin must outrank user")
	}
	if quickLinkRank("super_admin") < quickLinkRank("operator") {
		t.Error("super_admin must outrank operator")
	}
	if quickLinkRank("nonsense") != 0 {
		t.Error("unknown role must rank as 0 (user)")
	}
}

func TestNormalizeQuickLinkRole(t *testing.T) {
	if normalizeQuickLinkRole("bogus") != "user" {
		t.Error("bogus role must normalize to user")
	}
	if normalizeQuickLinkRole("admin") != "admin" {
		t.Error("valid role must pass through")
	}
}

func TestQuickLinkCategoryIconDefaults(t *testing.T) {
	if quickLinkCategory("") != "Other" {
		t.Error("empty category must default to Other")
	}
	if quickLinkIcon("") != "Link2" {
		t.Error("empty icon must default to Link2")
	}
	if quickLinkCategory("Support") != "Support" || quickLinkIcon("Video") != "Video" {
		t.Error("non-empty values must pass through")
	}
}

func TestBoolOrDefault(t *testing.T) {
	tru := true
	fls := false
	if boolOrDefault(nil, true) != true || boolOrDefault(nil, false) != false {
		t.Error("nil must yield the default")
	}
	if boolOrDefault(&fls, true) != false || boolOrDefault(&tru, false) != true {
		t.Error("non-nil must yield the pointed value")
	}
}
