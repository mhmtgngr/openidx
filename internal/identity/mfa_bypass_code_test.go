package identity

import (
	"strings"
	"testing"
)

func TestBypassCodeHasNoLookAlikes(t *testing.T) {
	for i := 0; i < 200; i++ {
		code, err := generateBypassCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != bypassCodeLength {
			t.Fatalf("code %q has %d symbols, want %d", code, len(code), bypassCodeLength)
		}
		if strings.ContainsAny(code, "ILOUilou") || strings.ToUpper(code) != code {
			t.Fatalf("code %q carries a look-alike or lower-case symbol", code)
		}
	}
}

func TestBypassCodeVerificationForgivesHowItWasTyped(t *testing.T) {
	issued := "9378VBRDJANB1DEY"
	for _, typed := range []string{
		"9378VBRDJANB1DEY",
		"9378vbrdjanb1dey",
		"9378-VBRD-JANB-1DEY",
		"9378 VBRD JANB IDEY", // I read as 1
		"9378VBRDJANBlDEY",    // l read as 1
		"  9378VBRDJANB1DEY\n",
	} {
		if got := normalizeBypassCode(typed); got != issued {
			t.Errorf("normalize(%q) = %q, want %q", typed, got, issued)
		}
	}
	if got := normalizeBypassCode("0OLI"); got != "0011" {
		t.Errorf("look-alike fold = %q, want 0011", got)
	}
}
