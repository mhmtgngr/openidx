package oauth

import (
	"errors"
	"testing"

	"github.com/openidx/openidx/internal/identity"
)

func TestFederatedPopulation(t *testing.T) {
	rules := identity.JITPolicy{
		Population: identity.PopulationInternal,
		PopulationRules: []identity.PopulationRule{
			{Claim: "acct", Values: []string{"1"}, Population: identity.PopulationExternal},
		},
	}
	cases := []struct {
		name     string
		policy   identity.JITPolicy
		raw      map[string]interface{}
		pref     string
		upn      string
		expected string
	}{
		{"default internal", identity.JITPolicy{}, nil, "a@x", "", identity.PopulationInternal},
		{"default external", identity.JITPolicy{Population: identity.PopulationExternal}, nil, "", "", identity.PopulationExternal},
		{"acct number matches", rules, map[string]interface{}{"acct": float64(1)}, "", "", identity.PopulationExternal},
		{"acct string matches", rules, map[string]interface{}{"acct": "1"}, "", "", identity.PopulationExternal},
		{"acct member stays internal", rules, map[string]interface{}{"acct": float64(0)}, "", "", identity.PopulationInternal},
		{"EXT guest fallback", rules, map[string]interface{}{}, "bob_x.com#EXT#@tdv.onmicrosoft.com", "", identity.PopulationExternal},
		{"EXT in upn", identity.JITPolicy{}, nil, "", "bob#ext#@t", identity.PopulationExternal},
		{"rule to internal wins over EXT", identity.JITPolicy{PopulationRules: []identity.PopulationRule{
			{Claim: "grp", Values: []string{"staff"}, Population: identity.PopulationInternal}}},
			map[string]interface{}{"grp": []interface{}{"x", "staff"}}, "a#EXT#", "", identity.PopulationInternal},
	}
	for _, c := range cases {
		if got := federatedPopulation(c.policy, c.raw, c.pref, c.upn); got != c.expected {
			t.Errorf("%s: got %q want %q", c.name, got, c.expected)
		}
	}
}

func TestEmailDomain(t *testing.T) {
	for in, want := range map[string]string{"a@Diyanet.GOV.tr": "diyanet.gov.tr", "nobody": "", "a@b@c.org": "c.org"} {
		if got := emailDomain(in); got != want {
			t.Errorf("emailDomain(%q)=%q want %q", in, got, want)
		}
	}
}

func TestFederatedExternalRefusal(t *testing.T) {
	if r, d := federatedExternalRefusal(errPartnerNotRegistered); r != ssoErrPartnerNotRegistered || d != "partner_not_registered" {
		t.Errorf("not registered: %q %q", r, d)
	}
	if r, d := federatedExternalRefusal(errors.New("db down")); r != externalErrUnavailable || d != "provisioning_failed" {
		t.Errorf("generic: %q %q", r, d)
	}
}
