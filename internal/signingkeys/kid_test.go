package signingkeys

import "testing"

// A kid names the cell that minted it, and nothing else about it changes.
func TestKidPrefixNamesTheCell(t *testing.T) {
	for _, tc := range []struct{ cell, want string }{
		{"", "openidx-key-"},
		{"eu-1", "eu-1-key-"},
		{"us-1", "us-1-key-"},
	} {
		if got := KidPrefix(tc.cell); got != tc.want {
			t.Errorf("KidPrefix(%q) = %q, want %q", tc.cell, got, tc.want)
		}
	}
	// Two cells never share a prefix, and neither shares the single-cell one.
	if KidPrefix("eu-1") == KidPrefix("us-1") || KidPrefix("eu-1") == KidPrefix("") {
		t.Fatal("cell prefixes collide")
	}
}
