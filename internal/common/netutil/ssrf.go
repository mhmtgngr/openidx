// Package netutil provides network utilities with security protections
package netutil

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// SSRFProtectedClient is an HTTP client wrapper that validates URLs
// to prevent Server-Side Request Forgery (SSRF) attacks.
type SSRFProtectedClient struct {
	// AllowedDomains is a list of allowed domains (wildcards supported, e.g., "*.api.example.com")
	AllowedDomains []string
	// AllowedIPs is a list of allowed IP CIDR ranges
	AllowedIPs []string
	// BlockPrivateIPs blocks requests to private/internal IP addresses
	BlockPrivateIPs bool
	// BlockLocalhost blocks requests to localhost/127.0.0.1
	BlockLocalhost bool
}

// DefaultSSRFConfig returns a secure-by-default SSRF configuration
// that blocks all private and internal IP addresses.
func DefaultSSRFConfig() *SSRFProtectedClient {
	return &SSRFProtectedClient{
		BlockPrivateIPs: true,
		BlockLocalhost:  true,
	}
}

// ValidateURL checks if a URL is safe to call, protecting against SSRF attacks.
// Returns an error if the URL points to a disallowed destination.
func (c *SSRFProtectedClient) ValidateURL(rawURL string) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow http and https schemes
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("invalid scheme '%s': only http and https are allowed", parsedURL.Scheme)
	}

	host := parsedURL.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no hostname")
	}

	// Check for domain-based allowlist
	if len(c.AllowedDomains) > 0 {
		allowed := false
		for _, allowedDomain := range c.AllowedDomains {
			if c.domainMatches(host, allowedDomain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("domain '%s' is not in the allowlist", host)
		}
	}

	// Resolve hostname to IP addresses for further checks
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve hostname '%s': %w", host, err)
	}

	for _, ip := range ips {
		if c.BlockPrivateIPs {
			if isPrivateIP(ip) {
				return fmt.Errorf("hostname '%s' resolves to private IP '%s': SSRF protection blocked", host, ip)
			}
		}

		if c.BlockLocalhost {
			if isLocalhostIP(ip) {
				return fmt.Errorf("hostname '%s' resolves to localhost IP '%s': SSRF protection blocked", host, ip)
			}
		}
	}

	// Check IP-based allowlist if configured
	if len(c.AllowedIPs) > 0 {
		allowed := false
		for _, ip := range ips {
			for _, allowedCIDR := range c.AllowedIPs {
				_, cidr, err := net.ParseCIDR(allowedCIDR)
				if err != nil {
					continue
				}
				if cidr.Contains(ip) {
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}
		if !allowed {
			return fmt.Errorf("IP addresses for '%s' are not in the IP allowlist", host)
		}
	}

	return nil
}

// domainMatches checks if a hostname matches an allowed domain pattern.
// Supports wildcards (e.g., "*.example.com" matches "api.example.com").
func (c *SSRFProtectedClient) domainMatches(hostname, pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		domain := strings.TrimPrefix(pattern, "*.")
		return hostname == domain || strings.HasSuffix(hostname, "."+domain)
	}
	return hostname == pattern
}

// isPrivateIP checks if an IP address is in a private range (RFC 1918, RFC 4193, etc.)
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}

	if ip4 := ip.To4(); ip4 != nil {
		// RFC 1918 private IPv4 ranges
		privateRanges := []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16", // Link-local
			"100.64.0.0/10",  // Carrier-grade NAT
		}
		for _, cidr := range privateRanges {
			_, network, _ := net.ParseCIDR(cidr)
			if network.Contains(ip4) {
				return true
			}
		}
		return false
	}

	// IPv6 private ranges (RFC 4193, etc.)
	privateIPv6Ranges := []string{
		"fc00::/7",   // Unique local addresses
		"fe80::/10",  // Link-local
		"fd00::/8",   // Unique local (commonly used)
	}
	for _, cidr := range privateIPv6Ranges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// isLocalhostIP checks if an IP address is localhost
func isLocalhostIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.Equal(net.ParseIP("::1"))
}

// IsPrivateURL is a convenience function to check if a URL is private/internal.
// Useful for quick SSRF checks without creating a client.
func IsPrivateURL(rawURL string) bool {
	client := DefaultSSRFConfig()
	err := client.ValidateURL(rawURL)
	return err != nil
}

// KnownPublicAPIs returns pre-configured SSRF clients for known public APIs.
// Use these instead of creating custom configurations for well-known services.
var KnownPublicAPIs = struct {
	HIBP      *SSRFProtectedClient
	Cloudflare *SSRFProtectedClient
	AWS       *SSRFProtectedClient
	Azure     *SSRFProtectedClient
	GCP       *SSRFProtectedClient
}{
	HIBP: &SSRFProtectedClient{
		AllowedDomains:   []string{"api.pwnedpasswords.com", "pwnedpasswords.com"},
		BlockPrivateIPs:  true,
		BlockLocalhost:   true,
	},
	Cloudflare: &SSRFProtectedClient{
		AllowedDomains:   []string{"*.cloudflare.com", "cloudflare.com"},
		BlockPrivateIPs:  true,
		BlockLocalhost:   true,
	},
	AWS: &SSRFProtectedClient{
		AllowedDomains:   []string{"*.amazonaws.com", "amazonaws.com"},
		BlockPrivateIPs:  true,
		BlockLocalhost:   true,
	},
	Azure: &SSRFProtectedClient{
		AllowedDomains:   []string{"*.azure.com", "*.azure.net", "azure.com", "azure.net"},
		BlockPrivateIPs:  true,
		BlockLocalhost:   true,
	},
	GCP: &SSRFProtectedClient{
		AllowedDomains:   []string{"*.googleapis.com", "googleapis.com", "*.gcp.com", "gcp.com"},
		BlockPrivateIPs:  true,
		BlockLocalhost:   true,
	},
}
