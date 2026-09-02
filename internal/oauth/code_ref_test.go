package oauth

import (
	"strings"
	"testing"
)

// codeRef stands in for the raw authorization code in log lines: it must be
// stable (correlate store→consume→delete events) without containing or
// revealing the code, which is a bearer credential until exchanged.
func TestCodeRef(t *testing.T) {
	code := "SplxlOBeZQQYbYS6WxSbIA"

	ref := codeRef(code)
	if ref != codeRef(code) {
		t.Fatal("codeRef must be deterministic")
	}
	if len(ref) != 12 {
		t.Fatalf("want 12 hex chars, got %q", ref)
	}
	if strings.Contains(code, ref) || strings.Contains(ref, code) {
		t.Fatal("codeRef must not contain the code (or vice versa)")
	}
	if other := codeRef(code + "x"); other == ref {
		t.Fatal("different codes must get different refs")
	}
}
