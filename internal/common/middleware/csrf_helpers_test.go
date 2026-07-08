package middleware

import (
	"net/http"
	"testing"
)

// TestMatchesDomain locks in the exact/subdomain matching and, importantly, the
// look-alike rejections that a CSRF origin check depends on.
func TestMatchesDomain(t *testing.T) {
	cases := []struct {
		host, domain string
		want         bool
	}{
		{"example.com", "example.com", true},          // exact
		{"app.example.com", "example.com", true},       // subdomain
		{"a.b.example.com", "example.com", true},        // nested subdomain
		{"EXAMPLE.com", "example.COM", true},            // case-insensitive
		{"notexample.com", "example.com", false},        // suffix without dot boundary
		{"example.com.evil.com", "example.com", false},  // classic prefix trick
		{"evil.com", "example.com", false},              // unrelated
		{"", "example.com", false},                      // empty host
	}
	for _, tc := range cases {
		if got := matchesDomain(tc.host, tc.domain); got != tc.want {
			t.Errorf("matchesDomain(%q,%q)=%v want %v", tc.host, tc.domain, got, tc.want)
		}
	}
}

func TestIsAllowedOrigin(t *testing.T) {
	cases := []struct {
		origin, trusted string
		want            bool
	}{
		{"https://evil.com", "", true},                         // no trusted domain configured → allow
		{"https://app.example.com", "example.com", true},       // matching subdomain
		{"https://example.com:8443", "example.com", true},      // port ignored (Hostname())
		{"https://evil.com", "example.com", false},             // cross-origin
		{"https://example.com.evil.com", "example.com", false}, // look-alike
		{"://malformed", "example.com", false},                 // unparseable → blocked
	}
	for _, tc := range cases {
		if got := isAllowedOrigin(tc.origin, tc.trusted); got != tc.want {
			t.Errorf("isAllowedOrigin(%q,%q)=%v want %v", tc.origin, tc.trusted, got, tc.want)
		}
	}
}

func TestIsAllowedReferer(t *testing.T) {
	cases := []struct {
		referer, trusted string
		want             bool
	}{
		{"https://evil.com/x", "", true},
		{"https://app.example.com/login", "example.com", true},
		{"https://evil.com/x", "example.com", false},
		{"https://example.com.evil.com/x", "example.com", false},
	}
	for _, tc := range cases {
		if got := isAllowedReferer(tc.referer, tc.trusted); got != tc.want {
			t.Errorf("isAllowedReferer(%q,%q)=%v want %v", tc.referer, tc.trusted, got, tc.want)
		}
	}
}

func TestSameSiteFromString(t *testing.T) {
	cases := map[string]http.SameSite{
		"none":    http.SameSiteNoneMode,
		"lax":     http.SameSiteLaxMode,
		"strict":  http.SameSiteStrictMode,
		"STRICT":  http.SameSiteStrictMode, // case-insensitive
		"default": http.SameSiteDefaultMode,
		"":        http.SameSiteDefaultMode,
		"garbage": http.SameSiteDefaultMode, // unknown → default
	}
	for in, want := range cases {
		if got := SameSiteFromString(in); got != want {
			t.Errorf("SameSiteFromString(%q)=%v want %v", in, got, want)
		}
	}
}
