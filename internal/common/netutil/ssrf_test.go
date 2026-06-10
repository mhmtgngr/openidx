package netutil

import (
	"net"
	"strings"
	"testing"
)

// TestDefaultSSRFConfig confirms the secure-by-default constructor blocks
// every private and localhost destination. If any future maintenance flips
// a flag here we want a test failure, not a silent SSRF regression.
func TestDefaultSSRFConfig(t *testing.T) {
	c := DefaultSSRFConfig()
	if !c.BlockPrivateIPs {
		t.Error("BlockPrivateIPs default = false; defaults must block private IPs")
	}
	if !c.BlockLocalhost {
		t.Error("BlockLocalhost default = false; defaults must block localhost")
	}
	if len(c.AllowedDomains) != 0 || len(c.AllowedIPs) != 0 {
		t.Error("default config has non-empty allowlists; defaults must require explicit allowlisting")
	}
}

// TestValidateURL_RejectsBadScheme makes sure file:// and other non-HTTP
// schemes can't sneak past — even with an empty config the scheme check
// runs first.
func TestValidateURL_RejectsBadScheme(t *testing.T) {
	c := DefaultSSRFConfig()
	for _, bad := range []string{
		"file:///etc/passwd",
		"gopher://example.com/",
		"ldap://internal/",
		"javascript:alert(1)",
	} {
		if err := c.ValidateURL(bad); err == nil {
			t.Errorf("ValidateURL(%q) returned nil; want scheme rejection", bad)
		}
	}
}

// TestValidateURL_RejectsLocalhost — the most basic SSRF gate. Whether the
// attacker uses the name or the literal IP, the validator must reject it.
// Uses 127.x literals so the test does not depend on DNS resolution at all.
func TestValidateURL_RejectsLocalhost(t *testing.T) {
	c := DefaultSSRFConfig()
	for _, bad := range []string{
		"http://127.0.0.1/",
		"http://127.0.0.2:8080/admin",
		"http://[::1]/",
	} {
		if err := c.ValidateURL(bad); err == nil {
			t.Errorf("ValidateURL(%q) returned nil; localhost must be blocked", bad)
		}
	}
}

// TestValidateURL_RejectsPrivateIPs walks the RFC 1918 / RFC 4193 ranges with
// literal IPs (so the test does not hit DNS).
func TestValidateURL_RejectsPrivateIPs(t *testing.T) {
	c := DefaultSSRFConfig()
	for _, bad := range []string{
		"http://10.0.0.5/",
		"http://172.16.42.1/",
		"http://192.168.1.1/",
		"http://169.254.169.254/", // AWS metadata
		"http://100.64.0.1/",      // CGNAT
		"http://[fc00::1]/",       // IPv6 ULA
		"http://[fe80::1]/",       // IPv6 link-local
	} {
		if err := c.ValidateURL(bad); err == nil {
			t.Errorf("ValidateURL(%q) returned nil; private IP must be blocked", bad)
		}
	}
}

// TestValidateURL_NoHostname rejects URLs that lack a hostname so the
// hostname-based gates aren't bypassed by relative or malformed URLs.
func TestValidateURL_NoHostname(t *testing.T) {
	c := DefaultSSRFConfig()
	if err := c.ValidateURL("http:///foo"); err == nil {
		t.Error("ValidateURL(http:///foo) returned nil; want 'no hostname' error")
	}
}

// TestValidateURL_AllowlistMissDomain confirms an unknown domain is rejected
// when an allowlist is configured, even if the IP itself looks public.
func TestValidateURL_AllowlistMissDomain(t *testing.T) {
	c := &SSRFProtectedClient{AllowedDomains: []string{"api.pwnedpasswords.com"}}
	if err := c.ValidateURL("https://attacker.example.com/"); err == nil {
		t.Error("ValidateURL: domain not in allowlist accepted")
	}
}

// TestValidateURL_AllowlistDomainExact verifies the exact-match branch of
// domainMatches.
func TestValidateURL_AllowlistDomainExact(t *testing.T) {
	c := &SSRFProtectedClient{AllowedDomains: []string{"example.com"}}
	if !c.domainMatches("example.com", "example.com") {
		t.Error("exact-match domain rejected by domainMatches")
	}
	if c.domainMatches("attacker.example.com", "example.com") {
		t.Error("subdomain accepted by exact-match pattern (must require wildcard)")
	}
}

// TestValidateURL_AllowlistDomainWildcard covers the *.example.com pattern.
// It must accept api.example.com (subdomain) AND example.com (apex itself).
func TestValidateURL_AllowlistDomainWildcard(t *testing.T) {
	c := &SSRFProtectedClient{AllowedDomains: []string{"*.example.com"}}
	if !c.domainMatches("api.example.com", "*.example.com") {
		t.Error("subdomain not matched by *. pattern")
	}
	if !c.domainMatches("example.com", "*.example.com") {
		t.Error("apex domain not matched by *. pattern (intentional behavior — host matches the trimmed pattern)")
	}
	if c.domainMatches("attacker.com", "*.example.com") {
		t.Error("unrelated domain matched by *.example.com pattern")
	}
	if c.domainMatches("notexample.com", "*.example.com") {
		t.Error("notexample.com falsely matched (must not match by string suffix without the dot)")
	}
}

// TestIsPrivateIP walks the RFC 1918 / RFC 4193 boundaries plus a public IP
// or two on each side to make sure the predicate isn't always returning
// true/false.
func TestIsPrivateIP(t *testing.T) {
	private := []string{
		"10.0.0.1", "10.255.255.254",
		"172.16.0.1", "172.31.255.254",
		"192.168.0.1",
		"169.254.0.1",
		"100.64.0.1",
		"127.0.0.1", "127.0.0.255",
		"::1",
		"fc00::1", "fd12:3456:789a::1",
		"fe80::1",
	}
	for _, s := range private {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test setup: ParseIP(%q) = nil", s)
		}
		if !isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%q) = false, want true", s)
		}
	}

	public := []string{
		"8.8.8.8", "1.1.1.1", "9.9.9.9",
		"172.32.0.1", // just outside 172.16.0.0/12
		"2001:4860:4860::8888",
	}
	for _, s := range public {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test setup: ParseIP(%q) = nil", s)
		}
		if isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%q) = true, want false", s)
		}
	}
}

// TestIsLocalhostIP — narrow predicate that only flags 127.0.0.0/8 / ::1.
func TestIsLocalhostIP(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "127.0.0.2", "::1"} {
		if !isLocalhostIP(net.ParseIP(s)) {
			t.Errorf("isLocalhostIP(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"10.0.0.1", "8.8.8.8", "2001:db8::1"} {
		if isLocalhostIP(net.ParseIP(s)) {
			t.Errorf("isLocalhostIP(%q) = true, want false", s)
		}
	}
}

// TestIsPrivateURL — convenience wrapper. Should return true (i.e. "private,
// don't use") for localhost / private literals, false for clearly public
// targets. Uses literal IPs to keep the test off DNS.
func TestIsPrivateURL(t *testing.T) {
	for _, p := range []string{"http://127.0.0.1/", "http://10.0.0.1/", "http://[fc00::1]/"} {
		if !IsPrivateURL(p) {
			t.Errorf("IsPrivateURL(%q) = false, want true", p)
		}
	}
	// Non-routable scheme also reads as "private" — the wrapper returns
	// err != nil for anything ValidateURL rejects, which is what callers
	// want.
	if !IsPrivateURL("file:///etc/passwd") {
		t.Error("IsPrivateURL(file:///etc/passwd) = false, want true")
	}
}

// TestKnownPublicAPIs makes sure the pre-built configs at least have
// allowlists set and the protective flags on — a sanity check against
// accidental misconfiguration. We don't network-test them.
func TestKnownPublicAPIs(t *testing.T) {
	for name, c := range map[string]*SSRFProtectedClient{
		"HIBP":       KnownPublicAPIs.HIBP,
		"Cloudflare": KnownPublicAPIs.Cloudflare,
		"AWS":        KnownPublicAPIs.AWS,
		"Azure":      KnownPublicAPIs.Azure,
		"GCP":        KnownPublicAPIs.GCP,
	} {
		if !c.BlockPrivateIPs {
			t.Errorf("%s: BlockPrivateIPs = false", name)
		}
		if !c.BlockLocalhost {
			t.Errorf("%s: BlockLocalhost = false", name)
		}
		if len(c.AllowedDomains) == 0 {
			t.Errorf("%s: AllowedDomains is empty (no allowlist)", name)
		}
		for _, d := range c.AllowedDomains {
			if strings.HasPrefix(d, "http://") || strings.HasPrefix(d, "https://") {
				t.Errorf("%s: allowed domain %q contains scheme; want bare hostname", name, d)
			}
		}
	}
}
