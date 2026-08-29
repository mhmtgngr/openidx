package access

import (
	"strings"
	"testing"
)

func TestGenerateEnrollShortCode(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 2000; i++ {
		code, err := generateEnrollShortCode()
		if err != nil {
			t.Fatalf("generateEnrollShortCode: %v", err)
		}
		if len(code) != enrollCodeLen {
			t.Fatalf("length = %d, want %d (%q)", len(code), enrollCodeLen, code)
		}
		// Only the unambiguous alphabet — no 0/O/1/I/L, no lowercase, no symbols.
		for _, r := range code {
			if !strings.ContainsRune(enrollCodeAlphabet, r) {
				t.Fatalf("code %q contains disallowed char %q", code, r)
			}
		}
		if seen[code] {
			t.Fatalf("duplicate code within 2000 draws: %q", code)
		}
		seen[code] = true
	}
}

func TestEnrollCodeAlphabetIsUnambiguous(t *testing.T) {
	for _, bad := range []rune{'0', 'O', '1', 'I', 'L'} {
		if strings.ContainsRune(enrollCodeAlphabet, bad) {
			t.Fatalf("alphabet must not contain ambiguous char %q", bad)
		}
	}
}
