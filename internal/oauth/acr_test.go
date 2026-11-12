package oauth

import (
	"testing"
	"time"
)

func TestParseACRValuesKeepsKnownClassesOnly(t *testing.T) {
	got := parseACRValues("  urn:openidx:mfa  urn:example:gold urn:openidx:phishing-resistant ")
	if len(got) != 2 || got[0] != ACRMFA || got[1] != ACRPhishingResistant {
		t.Fatalf("parseACRValues = %v", got)
	}
	if normalizedACRValues("urn:example:gold") != "" {
		t.Fatal("an unknown class alone must normalise to no request")
	}
}

func TestSessionAssuranceClasses(t *testing.T) {
	now := time.Now()
	window := 15 * time.Minute
	recent := now.Add(-2 * time.Minute)
	stale := now.Add(-time.Hour)
	for _, tc := range []struct {
		name    string
		a       sessionAssurance
		highest string
		meets   map[string]bool
	}{
		{"no session", sessionAssurance{}, "", map[string]bool{ACRPassword: false, ACRMFA: false}},
		{"password only", sessionAssurance{Found: true, Methods: []string{"pwd"}}, ACRPassword,
			map[string]bool{ACRPassword: true, ACRMFA: false, ACRMFAFresh: false, ACRPhishingResistant: false}},
		{"totp, recent", sessionAssurance{Found: true, Methods: []string{"pwd", "mfa"}, MFAVerifiedAt: &recent}, ACRMFAFresh,
			map[string]bool{ACRMFA: true, ACRMFAFresh: true, ACRPhishingResistant: false}},
		{"totp, stale", sessionAssurance{Found: true, Methods: []string{"pwd", "mfa"}, MFAVerifiedAt: &stale}, ACRMFA,
			map[string]bool{ACRMFA: true, ACRMFAFresh: false}},
		{"passkey as second factor", sessionAssurance{Found: true, Methods: []string{"pwd", "hwk", "mfa"}, MFAVerifiedAt: &recent}, ACRPhishingResistant,
			map[string]bool{ACRMFA: true, ACRMFAFresh: true, ACRPhishingResistant: true}},
		{"passkey without user verification is one factor", sessionAssurance{Found: true, Methods: []string{"hwk"}}, ACRPassword,
			map[string]bool{ACRMFA: false, ACRPhishingResistant: false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.highest(now, window); got != tc.highest {
				t.Fatalf("highest = %q, want %q", got, tc.highest)
			}
			for class, want := range tc.meets {
				if got := tc.a.requirementMet([]string{class}, now, window); got != want {
					t.Errorf("requirementMet(%s) = %v, want %v", class, got, want)
				}
			}
		})
	}
}

func TestRequirementMetAcceptsAnyAlternativeAndNoRequest(t *testing.T) {
	a := sessionAssurance{Found: true, Methods: []string{"pwd"}}
	if !a.requirementMet(nil, time.Now(), time.Minute) {
		t.Fatal("no request must always be met")
	}
	if !a.requirementMet([]string{ACRMFA, ACRPassword}, time.Now(), time.Minute) {
		t.Fatal("any listed alternative is enough")
	}
}

func TestNarrowMFAMethodsForACR(t *testing.T) {
	methods := []string{"totp", "webauthn", "push"}
	if got := narrowMFAMethodsForACR(map[string]string{paramACRValues: ACRPhishingResistant}, methods); len(got) != 1 || got[0] != "webauthn" {
		t.Fatalf("phishing-resistant only: %v", got)
	}
	if got := narrowMFAMethodsForACR(map[string]string{paramACRValues: ACRPhishingResistant + " " + ACRMFA}, methods); len(got) != 3 {
		t.Fatalf("a weaker alternative keeps every method: %v", got)
	}
	if got := narrowMFAMethodsForACR(map[string]string{paramACRValues: ACRPhishingResistant}, []string{"totp"}); len(got) != 1 || got[0] != "totp" {
		t.Fatalf("no passkey enrolled leaves the list: %v", got)
	}
}

func TestMFAAuthMethodsRecordsHardwareKey(t *testing.T) {
	if got := mfaAuthMethods("pwd", "webauthn"); len(got) != 3 || got[1] != "hwk" {
		t.Fatalf("webauthn: %v", got)
	}
	if got := mfaAuthMethods("fed", "totp"); len(got) != 2 || got[0] != "fed" || got[1] != "mfa" {
		t.Fatalf("totp: %v", got)
	}
}
