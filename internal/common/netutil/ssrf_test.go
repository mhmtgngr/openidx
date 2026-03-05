package netutil

import (
	"net"
	"testing"
)

func TestDefaultSSRFConfig(t *testing.T) {
	cfg := DefaultSSRFConfig()
	if !cfg.BlockPrivateIPs {
		t.Error("expected BlockPrivateIPs=true by default")
	}
	if !cfg.BlockLocalhost {
		t.Error("expected BlockLocalhost=true by default")
	}
	if len(cfg.AllowedDomains) != 0 {
		t.Error("expected no AllowedDomains by default")
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"169.254.1.1", true},
		{"100.64.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.1", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP: %s", tt.ip)
		}
		got := isPrivateIP(ip)
		if got != tt.private {
			t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
		}
	}
}

func TestIsLocalhostIP(t *testing.T) {
	tests := []struct {
		ip        string
		localhost bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.1", false},
		{"8.8.8.8", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := isLocalhostIP(ip)
		if got != tt.localhost {
			t.Errorf("isLocalhostIP(%s) = %v, want %v", tt.ip, got, tt.localhost)
		}
	}
}

func TestDomainMatches(t *testing.T) {
	client := &SSRFProtectedClient{}

	tests := []struct {
		hostname string
		pattern  string
		match    bool
	}{
		{"example.com", "example.com", true},
		{"api.example.com", "example.com", false},
		{"api.example.com", "*.example.com", true},
		{"deep.api.example.com", "*.example.com", true},
		{"example.com", "*.example.com", true},
		{"other.com", "example.com", false},
		{"other.com", "*.example.com", false},
		{"malicious-example.com", "*.example.com", false},
	}

	for _, tt := range tests {
		got := client.domainMatches(tt.hostname, tt.pattern)
		if got != tt.match {
			t.Errorf("domainMatches(%q, %q) = %v, want %v", tt.hostname, tt.pattern, got, tt.match)
		}
	}
}

func TestValidateURLSchemes(t *testing.T) {
	// Only test schemes that fail before DNS resolution (bad schemes)
	// and IP-based URLs that don't require DNS
	client := &SSRFProtectedClient{} // no blocking enabled

	badSchemes := []string{
		"ftp://example.com",
		"file:///etc/passwd",
		"gopher://example.com",
		"javascript:alert(1)",
	}
	for _, u := range badSchemes {
		err := client.ValidateURL(u)
		if err == nil {
			t.Errorf("ValidateURL(%q) should reject bad scheme", u)
		}
	}

	// http/https with raw IP (no DNS needed)
	goodURLs := []string{
		"http://8.8.8.8",
		"https://8.8.8.8",
	}
	for _, u := range goodURLs {
		err := client.ValidateURL(u)
		if err != nil {
			t.Errorf("ValidateURL(%q) unexpected error: %v", u, err)
		}
	}
}

func TestValidateURLNoHostname(t *testing.T) {
	client := &SSRFProtectedClient{}
	err := client.ValidateURL("http://")
	if err == nil {
		t.Error("expected error for URL with no hostname")
	}
}

func TestValidateURLDomainAllowlist(t *testing.T) {
	client := &SSRFProtectedClient{
		AllowedDomains: []string{"api.example.com", "*.safe.com"},
	}

	// Domains NOT in allowlist should be rejected before DNS resolution
	blockedURLs := []string{
		"https://evil.com/path",
		"https://other.org/path",
	}
	for _, u := range blockedURLs {
		err := client.ValidateURL(u)
		if err == nil {
			t.Errorf("ValidateURL(%q) should reject domain not in allowlist", u)
		}
	}
}

func TestKnownPublicAPIs(t *testing.T) {
	if KnownPublicAPIs.HIBP == nil {
		t.Error("HIBP client should not be nil")
	}
	if !KnownPublicAPIs.HIBP.BlockPrivateIPs {
		t.Error("HIBP should block private IPs")
	}
	if len(KnownPublicAPIs.HIBP.AllowedDomains) == 0 {
		t.Error("HIBP should have allowed domains")
	}

	if KnownPublicAPIs.AWS == nil {
		t.Error("AWS client should not be nil")
	}
	if KnownPublicAPIs.Azure == nil {
		t.Error("Azure client should not be nil")
	}
	if KnownPublicAPIs.GCP == nil {
		t.Error("GCP client should not be nil")
	}
	if KnownPublicAPIs.Cloudflare == nil {
		t.Error("Cloudflare client should not be nil")
	}
}

func TestIsPrivateURL(t *testing.T) {
	// Public IP-based URL should not be flagged (no DNS needed)
	if IsPrivateURL("https://8.8.8.8") {
		t.Error("https://8.8.8.8 should not be flagged as private")
	}

	// Private IP URL should be flagged
	if !IsPrivateURL("https://10.0.0.1") {
		t.Error("https://10.0.0.1 should be flagged as private")
	}

	// Localhost should be flagged
	if !IsPrivateURL("https://127.0.0.1") {
		t.Error("https://127.0.0.1 should be flagged as private")
	}

	// Invalid URLs should be flagged
	if !IsPrivateURL("not-a-url") {
		t.Error("invalid URL should be flagged")
	}
}
