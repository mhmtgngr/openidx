package oauth

import (
	"context"
	"os"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Tenant isolation for saml_service_providers — the registry of the federation
// partners this install acts as a SAML IdP for.
//
// Before v144 every handler read it install-wide: the list and its count had no
// org predicate at all, and get, update, certificate rotation, metadata refresh
// and delete all took a bare id. The disclosure is bad enough — one tenant's
// admin could enumerate another's partners — but the mutations are worse. The
// ACS URL is where assertions are POSTed and the certificate is what the IdP
// trusts, so a cross-tenant update redirects another tenant's single sign-on to
// a host of the attacker's choosing, and a cross-tenant delete takes their
// federation down.
//
// These tests use a real database when one is reachable and are skipped
// otherwise; the belt itself is proved separately under a NOSUPERUSER role by
// test/integration/cross_org_test.go.
const samlSPIsolationSchema = `
CREATE TABLE IF NOT EXISTS organizations (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	name VARCHAR(255) NOT NULL,
	created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS saml_service_providers (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	org_id UUID NOT NULL,
	name VARCHAR(255) NOT NULL,
	description TEXT,
	entity_id VARCHAR(500) UNIQUE NOT NULL,
	acs_url VARCHAR(500) NOT NULL,
	slo_url VARCHAR(500),
	metadata_url VARCHAR(500),
	metadata_xml TEXT,
	certificate TEXT,
	name_id_format VARCHAR(255) NOT NULL DEFAULT 'emailAddress',
	attribute_mappings JSONB DEFAULT '{}',
	want_assertions_signed BOOLEAN DEFAULT true,
	encryption_enabled BOOLEAN DEFAULT false,
	enabled BOOLEAN DEFAULT true,
	created_at TIMESTAMPTZ DEFAULT NOW(),
	updated_at TIMESTAMPTZ DEFAULT NOW(),
	last_used_at TIMESTAMPTZ);
`

const (
	samlOrgA = "00000000-0000-0000-0000-0000000000c1"
	samlOrgB = "00000000-0000-0000-0000-0000000000d1"
)

// TestSAMLServiceProviderIsolation covers the read and mutate paths that took a
// bare id.
func TestSAMLServiceProviderIsolation(t *testing.T) {
	db, cleanup := setupSAMLIsolationDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	s := newSAMLIsolationService(db)
	ctx := context.Background()
	aCtx := orgctx.With(ctx, orgctx.Org{ID: samlOrgA})
	bCtx := orgctx.With(ctx, orgctx.Org{ID: samlOrgB})

	spB, err := s.createSAMLServiceProvider(bCtx, &CreateSAMLServiceProviderRequest{
		Name:     "org B partner",
		EntityID: "https://b.example.test/metadata",
		ACSURL:   "https://b.example.test/acs",
	})
	if err != nil {
		t.Fatalf("seed org B provider: %v", err)
	}

	t.Run("get by id cannot reach another tenant's provider", func(t *testing.T) {
		if _, err := s.getSAMLServiceProviderByID(aCtx, spB.ID); err == nil {
			t.Error("org A read org B's service provider by id")
		}
	})

	t.Run("delete by id cannot remove another tenant's provider", func(t *testing.T) {
		if err := s.deleteSAMLServiceProvider(aCtx, spB.ID); err == nil {
			t.Error("org A deleted org B's service provider")
		}
		var n int
		if err := db.Pool.QueryRow(ctx,
			"SELECT count(*) FROM saml_service_providers WHERE id = $1", spB.ID).Scan(&n); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if n != 1 {
			t.Errorf("org B's provider is gone (count=%d)", n)
		}
	})

	t.Run("the owner can still read its own", func(t *testing.T) {
		got, err := s.getSAMLServiceProviderByID(bCtx, spB.ID)
		if err != nil {
			t.Fatalf("org B cannot read its own provider: %v", err)
		}
		if got.ACSURL != "https://b.example.test/acs" {
			t.Errorf("acs_url = %q, want the seeded value", got.ACSURL)
		}
	})

	// entity_id stays UNIQUE across the install on purpose: it is a globally
	// unique URI by the SAML specification and it is what resolves the tenant on
	// an inbound AuthnRequest, so two tenants claiming one would make that
	// lookup ambiguous. This is the deliberate difference from v143's
	// provider_key, and the test states it so a later batch cannot "fix" it by
	// applying that pattern here.
	t.Run("two tenants cannot claim the same entity id", func(t *testing.T) {
		_, err := s.createSAMLServiceProvider(aCtx, &CreateSAMLServiceProviderRequest{
			Name:     "org A tries to squat",
			EntityID: "https://b.example.test/metadata",
			ACSURL:   "https://a.example.test/acs",
		})
		if err == nil {
			t.Error("org A registered an entity id org B already holds; " +
				"the install-wide UNIQUE is what keeps inbound request resolution unambiguous")
		}
	})

	// The lookup that resolves the tenant must span orgs: an AuthnRequest names
	// an entity id and nothing else, so a query scoped to a not-yet-known org
	// could never answer it.
	t.Run("resolution by entity id works without an org context", func(t *testing.T) {
		got, err := s.getSAMLServiceProviderByEntityID(ctx, "https://b.example.test/metadata")
		if err != nil {
			t.Fatalf("entity-id resolution failed with no org on the context: %v", err)
		}
		if got.ID != spB.ID {
			t.Errorf("resolved %s, want %s", got.ID, spB.ID)
		}
	})
}

// setupSAMLIsolationDB prefers OPENIDX_TEST_DATABASE_URL and otherwise starts a
// throwaway container, then applies the table shape.
//
// It used to take only the first path, on the argument that a suite which can
// run against a plain Postgres should not skip merely because no Docker daemon
// is reachable — a developer running `go test ./internal/...` without one gets
// a green sweep that never executed it.
//
// THAT ARGUMENT WAS RIGHT AND THE CONCLUSION WAS BACKWARDS. Dropping the
// container fallback did not make the suite run more often, it made it run
// NOWHERE: ci.yml's unit matrix supplies a live Postgres as DATABASE_URL and
// never sets OPENIDX_TEST_DATABASE_URL, so the one place that always has both a
// database and a Docker daemon skipped these tests on every run, silently,
// while `Unit Tests (internal/oauth)` reported success. Tenant isolation is
// exactly the property nobody notices is unproven.
//
// So: keep the variable as the preferred path (it is friendlier to a shared
// database — this helper deletes only its own rows rather than dropping the
// schema, unlike ssfSetupTestDB's env branch), and fall back to a container so
// CI executes it. scripts/check-test-reachability.sh fails on the old shape.
func setupSAMLIsolationDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()
	ctx := context.Background()

	url := os.Getenv("OPENIDX_TEST_DATABASE_URL")
	if url == "" {
		db, containerCleanup := ssfSetupTestDB(t)
		if _, err := db.Pool.Exec(ctx, samlSPIsolationSchema); err != nil {
			containerCleanup()
			t.Fatalf("apply schema: %v", err)
		}
		seedSAMLIsolationOrgs(t, db, containerCleanup)
		return db, containerCleanup
	}

	db, err := database.NewPostgres(url)
	if err != nil {
		t.Skipf("OPENIDX_TEST_DATABASE_URL set but unreachable: %v", err)
		return nil, func() {}
	}
	if _, err := db.Pool.Exec(ctx, samlSPIsolationSchema); err != nil {
		db.Close()
		t.Fatalf("apply schema: %v", err)
	}
	seedSAMLIsolationOrgs(t, db, func() { db.Close() })
	return db, func() {
		db.Pool.Exec(context.Background(),
			"DELETE FROM saml_service_providers WHERE org_id IN ($1,$2)", samlOrgA, samlOrgB)
		db.Close()
	}
}

// seedSAMLIsolationOrgs brings either database to the same known state. Both
// setup paths call it, so a fixture change cannot land on one and not the other
// -- the divergence that makes a suite pass in CI and fail on a workstation.
// cleanup releases whatever the caller acquired: the pool alone on the
// variable path, the pool and the container on the fallback.
func seedSAMLIsolationOrgs(t *testing.T, db *database.PostgresDB, cleanup func()) {
	t.Helper()
	ctx := context.Background()
	// Start from a known state: these tests assert on counts and on a unique
	// entity id, so a row left by an earlier run would make them lie.
	if _, err := db.Pool.Exec(ctx,
		"DELETE FROM saml_service_providers WHERE org_id IN ($1,$2)", samlOrgA, samlOrgB); err != nil {
		cleanup()
		t.Fatalf("reset: %v", err)
	}
	for _, org := range []string{samlOrgA, samlOrgB} {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO organizations (id, name) VALUES ($1,$2) ON CONFLICT (id) DO NOTHING`,
			org, "saml-org-"+org[len(org)-2:]); err != nil {
			cleanup()
			t.Fatalf("seed org %s: %v", org, err)
		}
	}
}

func newSAMLIsolationService(db *database.PostgresDB) *Service {
	return &Service{db: db, logger: zap.NewNop()}
}
