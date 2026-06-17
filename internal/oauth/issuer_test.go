package oauth

import (
	"testing"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// v1.7.0: in a subdomain-tenancy deployment each org's tokens carry an issuer
// bound to that tenant; the default org and single-tenant installs keep the
// global issuer (no behavior change unless TenantBaseDomain is set).
func TestIssuerForOrg(t *testing.T) {
	const global = "https://idp.example.com"

	tenant := &Service{issuer: global, tenantBaseDomain: "openidx.io"}
	single := &Service{issuer: global, tenantBaseDomain: ""}

	cases := []struct {
		name string
		svc  *Service
		org  orgctx.Org
		want string
	}{
		{"tenant org gets subdomain issuer", tenant, orgctx.Org{ID: "x", Slug: "acme"}, "https://acme.openidx.io"},
		{"default org keeps global issuer", tenant, orgctx.Org{ID: "x", Slug: "default"}, global},
		{"empty slug keeps global issuer", tenant, orgctx.Org{ID: "x", Slug: ""}, global},
		{"no base domain keeps global issuer", single, orgctx.Org{ID: "x", Slug: "acme"}, global},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.svc.issuerForOrg(tc.org); got != tc.want {
				t.Fatalf("issuerForOrg = %q, want %q", got, tc.want)
			}
		})
	}
}
