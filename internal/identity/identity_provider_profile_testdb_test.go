package identity

import (
	"context"
	"reflect"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/federation/oidcrp"
	"github.com/openidx/openidx/internal/migrations"
)

// The federation profile (migration 246) round-trips through the provider
// CRUD: what an administrator configures is what the sign-in path reads back.
func TestIdentityProviderProfileRoundTrips(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	cipher, err := secretcrypt.New("idp-profile-roundtrip-key-32byte")
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{db: db, cfg: &config.Config{}, logger: zap.NewNop(), idpCipher: cipher}
	octx := orgctx.With(ctx, orgctx.Org{ID: "00000000-0000-0000-0000-000000000010"}) // seeded by migrations

	on := true
	want := &IdentityProvider{
		Name: "Entra", ProviderType: ProviderTypeOIDC,
		IssuerURL: "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
		ClientID:  "client-1", ClientSecret: "s3cret", Scopes: Scopes{"openid", "profile", "email"}, Enabled: true,
		DiscoveryURL:      "",
		UsePKCE:           &on,
		TrustUpstreamMFA:  true,
		ClaimsMapping:     oidcrp.ClaimsMapping{"external_id": "oid", "email": "preferred_username"},
		GroupMapping:      GroupMapping{{ClaimValue: "11111111-aaaa-4bbb-8ccc-dddddddddddd", GroupID: "0d1b4f3e-2222-4c3a-9b0b-aaaaaaaaaaaa"}},
		JITPolicy:         JITPolicy{Provision: true, Population: PopulationInternal, LinkByEmail: true},
		PassThroughParams: []string{"login_hint", "domain_hint"},
		ExternalIDClaim:   "oid",
	}
	if err := s.CreateIdentityProvider(octx, want); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := s.GetIdentityProvider(octx, want.ID.String())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	same := func(label string, g *IdentityProvider) {
		t.Helper()
		if g.UsePKCE == nil || *g.UsePKCE != on || g.TrustUpstreamMFA != want.TrustUpstreamMFA ||
			!reflect.DeepEqual(g.ClaimsMapping, want.ClaimsMapping) || !reflect.DeepEqual(g.GroupMapping, want.GroupMapping) ||
			!reflect.DeepEqual(g.JITPolicy, want.JITPolicy) || !reflect.DeepEqual(g.PassThroughParams, want.PassThroughParams) ||
			g.ExternalIDClaim != want.ExternalIDClaim || g.DiscoveryURL != want.DiscoveryURL {
			t.Errorf("%s: profile differs\n got %+v\nwant %+v", label, g, want)
		}
		if g.ClientSecret != "s3cret" {
			t.Errorf("%s: client secret did not round-trip through the cipher", label)
		}
	}
	same("get", got)

	list, _, err := s.ListIdentityProviders(octx, 0, 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var listed *IdentityProvider
	for i := range list {
		if list[i].ID == want.ID {
			listed = &list[i]
		}
	}
	if listed == nil {
		t.Fatal("list did not return the provider")
	}
	same("list", listed)

	want.TrustUpstreamMFA = false
	want.DiscoveryURL = "https://adfs.example.org/adfs/.well-known/openid-configuration"
	want.JITPolicy.Population = PopulationExternal
	want.JITPolicy.VendorOrgID = "0d1b4f3e-1111-4c3a-9b0b-aaaaaaaaaaaa"
	if err := s.UpdateIdentityProvider(octx, want); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err = s.GetIdentityProvider(octx, want.ID.String())
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	same("update", got)
}

// A provider written before migration 246 (no profile at all) reads back with
// the defaults the sign-in path relied on until now.
func TestIdentityProviderWithoutAProfileReadsBackTheDefaults(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	var id string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO identity_providers (org_id, name, provider_type, issuer_url, client_id, client_secret)
		VALUES ('00000000-0000-0000-0000-000000000010', 'legacy', 'oidc', 'https://legacy.example.org', 'cid', '') RETURNING id::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	s := &Service{db: db, cfg: &config.Config{}, logger: zap.NewNop(), idpCipher: secretcrypt.NewNoop()}
	got, err := s.GetIdentityProvider(orgctx.With(ctx, orgctx.Org{ID: "00000000-0000-0000-0000-000000000010"}), id)
	if err != nil {
		t.Fatal(err)
	}
	if got.UsePKCE == nil || !*got.UsePKCE || got.TrustUpstreamMFA || got.ExternalIDClaim != "sub" ||
		got.JITPolicy.Provision || got.JITPolicy.Population != PopulationInternal ||
		len(got.ClaimsMapping) != 0 || len(got.GroupMapping) != 0 ||
		!reflect.DeepEqual(got.PassThroughParams, []string{"login_hint", "prompt", "max_age"}) {
		t.Errorf("defaults not read back: %+v", got)
	}
}
