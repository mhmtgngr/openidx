package identity

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/federation/oidcrp"
)

// THE FEDERATION PROFILE OF AN IDENTITY PROVIDER (migration 246).
//
// Beyond issuer, client and scopes, signing in through an upstream provider
// needs what OpenID Connect lets a relying party configure and what OpenIDX
// decides about the people who arrive that way. Those decisions live on the
// identity_providers row and are validated here, once, for the admin API
// and for anything else that writes a provider.

// Populations a provider may provision into.
const (
	PopulationInternal = "internal"
	PopulationExternal = "external"
)

// ErrFederationProfile is wrapped by every refusal below; the admin API turns
// it into a 400 with the message.
var ErrFederationProfile = errors.New("identity provider profile")

// externalIDClaims are the claims a provider may be told to use as a person's
// stable identifier. sub is the standard; Entra keeps sub pairwise per client
// and recommends oid; ADFS deployments sometimes only have upn.
var externalIDClaims = map[string]bool{"sub": true, "oid": true, "upn": true, "email": true, "preferred_username": true}

// passThroughParams are the authorization-request parameters a provider may
// be told to forward from the original request. Anything else (redirect_uri,
// state, nonce, client_id, scope, response_type, code_challenge) is OpenIDX's
// own and is never forwarded.
var passThroughParams = map[string]bool{"login_hint": true, "prompt": true, "max_age": true, "domain_hint": true, "ui_locales": true, "acr_values": true}

// DefaultPassThroughParams is what a provider forwards when not told otherwise.
var DefaultPassThroughParams = []string{"login_hint", "prompt", "max_age"}

// GroupMapEntry maps one value of the provider's groups claim to one OpenIDX
// group.
type GroupMapEntry struct {
	ClaimValue string `json:"claim_value"`
	GroupID    string `json:"group_id"`
}

// GroupMapping is the provider's group mapping, stored as JSONB.
type GroupMapping []GroupMapEntry

// PopulationRule puts a person in a population when a claim has one of the
// listed values. Entra sends acct=1 for a guest, so one Entra provider can
// provision staff as internal and B2B guests as external.
type PopulationRule struct {
	Claim      string   `json:"claim"`
	Values     []string `json:"values"`
	Population string   `json:"population"`
}

// JITPolicy says what happens to a person the provider asserts whom OpenIDX
// does not know.
type JITPolicy struct {
	// Provision creates the person; false refuses an unknown person.
	Provision bool `json:"provision"`
	// Population is the default population: internal or external.
	Population string `json:"population"`
	// LinkByEmail lets an unknown subject be matched to an existing user by
	// email even when the provider does not mark the email verified.
	LinkByEmail bool `json:"link_by_email,omitempty"`
	// VendorOrgID is the vendor organization an external person joins when
	// no vendor claims the provider or the email domain.
	VendorOrgID string `json:"vendor_org_id,omitempty"`
	// PopulationRules override Population per claim value, first match wins.
	PopulationRules []PopulationRule `json:"population_rules,omitempty"`
}

// NormalizeFederationProfile fills the profile fields a request may leave
// out with the values migration 246 defaults them to, so a provider created
// through the API and one created before the profile existed behave the
// same. Call before validating or writing.
func (idp *IdentityProvider) NormalizeFederationProfile() {
	if idp.UsePKCE == nil {
		on := true
		idp.UsePKCE = &on
	}
	if idp.ExternalIDClaim == "" {
		idp.ExternalIDClaim = "sub"
	}
	if idp.JITPolicy.Population == "" {
		idp.JITPolicy.Population = PopulationInternal
	}
	if idp.PassThroughParams == nil {
		idp.PassThroughParams = append([]string(nil), DefaultPassThroughParams...)
	}
	if idp.ClaimsMapping == nil {
		idp.ClaimsMapping = oidcrp.ClaimsMapping{}
	}
	if idp.GroupMapping == nil {
		idp.GroupMapping = GroupMapping{}
	}
	idp.IssuerURL = strings.TrimSpace(idp.IssuerURL)
	idp.DiscoveryURL = strings.TrimSpace(idp.DiscoveryURL)
}

// ValidateFederationProfile refuses a profile the sign-in path could not act
// on. Every message names the field, for the administrator reading the 400.
func (idp *IdentityProvider) ValidateFederationProfile() error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrFederationProfile, fmt.Sprintf(format, a...))
	}
	if idp.ProviderType == ProviderTypeOIDC || idp.ProviderType == "" {
		if err := checkHTTPS(idp.IssuerURL); err != nil {
			return fail("issuer_url: %v", err)
		}
	}
	if idp.DiscoveryURL != "" {
		if err := checkHTTPS(idp.DiscoveryURL); err != nil {
			return fail("discovery_url: %v", err)
		}
	}
	if !externalIDClaims[idp.ExternalIDClaim] {
		return fail("external_id_claim %q is not one of sub, oid, upn, email, preferred_username", idp.ExternalIDClaim)
	}
	if err := idp.ClaimsMapping.Validate(); err != nil {
		return fail("%v", err)
	}
	for i, g := range idp.GroupMapping {
		if strings.TrimSpace(g.ClaimValue) == "" {
			return fail("group_mapping[%d]: claim_value is empty", i)
		}
		if _, err := uuid.Parse(g.GroupID); err != nil {
			return fail("group_mapping[%d]: group_id %q is not a group id", i, g.GroupID)
		}
	}
	for _, p := range idp.PassThroughParams {
		if !passThroughParams[p] {
			return fail("pass_through_params: %q may not be forwarded (login_hint, prompt, max_age, domain_hint, ui_locales, acr_values)", p)
		}
	}
	if !validPopulation(idp.JITPolicy.Population) {
		return fail("jit_policy.population %q is not internal or external", idp.JITPolicy.Population)
	}
	if idp.JITPolicy.VendorOrgID != "" {
		if _, err := uuid.Parse(idp.JITPolicy.VendorOrgID); err != nil {
			return fail("jit_policy.vendor_org_id %q is not a vendor organization id", idp.JITPolicy.VendorOrgID)
		}
	}
	for i, r := range idp.JITPolicy.PopulationRules {
		if strings.TrimSpace(r.Claim) == "" {
			return fail("jit_policy.population_rules[%d]: claim is empty", i)
		}
		if len(r.Values) == 0 {
			return fail("jit_policy.population_rules[%d]: values is empty", i)
		}
		if !validPopulation(r.Population) {
			return fail("jit_policy.population_rules[%d]: population %q is not internal or external", i, r.Population)
		}
	}
	return nil
}

func validPopulation(p string) bool {
	return p == PopulationInternal || p == PopulationExternal
}

// checkHTTPS requires an absolute https URL. Plain http is allowed only on
// loopback, for development against a local provider.
func checkHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not an absolute URL", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1") {
		return nil
	}
	return fmt.Errorf("%q must use https", raw)
}
