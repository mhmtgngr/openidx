package oauth

import "testing"

func TestBrowZerRedirectHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://PSM.tdv.org/":            "psm.tdv.org",
		"https://psm.tdv.org:8443/cb?x=1": "psm.tdv.org",
		"openidx://oauth-callback":        "oauth-callback",
		"":                                "",
		"not a url":                       "",
		"/relative/path":                  "",
	} {
		if got := browzerRedirectHost(in); got != want {
			t.Errorf("browzerRedirectHost(%q) = %q, want %q", in, got, want)
		}
	}
}
