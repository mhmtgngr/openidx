package tray

import "testing"

// TestSecurityKeysURL: an enrolled server, with or without a trailing slash,
// yields the page; no server yields nothing to open.
func TestSecurityKeysURL(t *testing.T) {
	const want = "https://idp.example.com/security-keys"
	if got := securityKeysURL("https://idp.example.com"); got != want {
		t.Fatalf("plain: got %q, want %q", got, want)
	}
	if got := securityKeysURL("https://idp.example.com///"); got != want {
		t.Fatalf("trailing slashes: got %q, want %q", got, want)
	}
	if got := securityKeysURL(""); got != "" {
		t.Fatalf("no server: got %q, want nothing to open", got)
	}
	if got := securityKeysURL("  "); got != "" {
		t.Fatalf("blank server: got %q, want nothing to open", got)
	}
}
