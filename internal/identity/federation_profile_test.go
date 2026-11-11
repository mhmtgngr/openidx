package identity

import (
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/federation/oidcrp"
)

func TestFederationProfileDefaultsFillWhatTheRequestLeftOut(t *testing.T) {
	idp := &IdentityProvider{Name: "Entra", ProviderType: ProviderTypeOIDC, IssuerURL: "https://login.microsoftonline.com/t/v2.0", ClientID: "c"}
	idp.NormalizeFederationProfile()
	if idp.UsePKCE == nil || !*idp.UsePKCE {
		t.Error("use_pkce should default to true")
	}
	if idp.ExternalIDClaim != "sub" {
		t.Errorf("external_id_claim = %q, want sub", idp.ExternalIDClaim)
	}
	if idp.JITPolicy.Population != PopulationInternal || idp.JITPolicy.Provision {
		t.Errorf("jit_policy = %+v, want internal/no provisioning", idp.JITPolicy)
	}
	if strings.Join(idp.PassThroughParams, ",") != "login_hint,prompt,max_age" {
		t.Errorf("pass_through_params = %v", idp.PassThroughParams)
	}
	if idp.ClaimsMapping == nil || idp.GroupMapping == nil {
		t.Error("mappings should be empty, not null, so JSONB NOT NULL columns accept them")
	}
}

func TestFederationProfileValidationRefusesWhatTheSignInPathCannotUse(t *testing.T) {
	good := func() *IdentityProvider {
		idp := &IdentityProvider{Name: "x", ProviderType: ProviderTypeOIDC, IssuerURL: "https://idp.example.org", ClientID: "c"}
		idp.NormalizeFederationProfile()
		return idp
	}
	cases := []struct {
		name string
		mut  func(*IdentityProvider)
		want string // substring of the error; empty means accepted
	}{
		{"defaults are valid", func(*IdentityProvider) {}, ""},
		{"an http issuer", func(i *IdentityProvider) { i.IssuerURL = "http://idp.example.org" }, "https"},
		{"an http discovery url", func(i *IdentityProvider) { i.DiscoveryURL = "http://idp.example.org/adfs/.well-known/openid-configuration" }, "https"},
		{"an unknown population", func(i *IdentityProvider) { i.JITPolicy.Population = "partner" }, "population"},
		{"an unknown external id claim", func(i *IdentityProvider) { i.ExternalIDClaim = "employee_no" }, "external_id_claim"},
		{"a claims mapping with an unknown field", func(i *IdentityProvider) { i.ClaimsMapping = oidcrp.ClaimsMapping{"colour": "x"} }, "claims mapping"},
		{"a group mapping without a group", func(i *IdentityProvider) { i.GroupMapping = GroupMapping{{ClaimValue: "Admins"}} }, "group_mapping"},
		{"a group mapping with a non-uuid group", func(i *IdentityProvider) {
			i.GroupMapping = GroupMapping{{ClaimValue: "Admins", GroupID: "admins"}}
		}, "group_mapping"},
		{"a pass-through parameter the request must not forward", func(i *IdentityProvider) {
			i.PassThroughParams = []string{"redirect_uri"}
		}, "pass_through_params"},
		{"a population rule naming no claim", func(i *IdentityProvider) {
			i.JITPolicy.PopulationRules = []PopulationRule{{Values: []string{"1"}, Population: PopulationExternal}}
		}, "population_rules"},
		{"a vendor that is not a uuid", func(i *IdentityProvider) { i.JITPolicy.VendorOrgID = "diyanet" }, "vendor_org_id"},
		{"a complete external profile", func(i *IdentityProvider) {
			i.ExternalIDClaim = "oid"
			i.JITPolicy = JITPolicy{Provision: true, Population: PopulationExternal, VendorOrgID: "0d1b4f3e-1111-4c3a-9b0b-aaaaaaaaaaaa",
				PopulationRules: []PopulationRule{{Claim: "acct", Values: []string{"1"}, Population: PopulationExternal}}}
			i.GroupMapping = GroupMapping{{ClaimValue: "Staff", GroupID: "0d1b4f3e-2222-4c3a-9b0b-aaaaaaaaaaaa"}}
			i.PassThroughParams = []string{"login_hint", "domain_hint"}
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idp := good()
			c.mut(idp)
			err := idp.ValidateFederationProfile()
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.want != "" && err == nil:
				t.Fatal("accepted")
			case c.want != "" && !strings.Contains(err.Error(), c.want):
				t.Fatalf("err = %v, want it to name %q", err, c.want)
			}
		})
	}
}
