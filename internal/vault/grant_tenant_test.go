package vault

import (
	"context"
	"testing"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestGrantChecksHoldUnderBypass is the case the belt cannot cover.
//
// vault_access_grants and vault_checkouts carry FORCE ROW LEVEL SECURITY, so on
// an ordinary request path a query that names no organization is scoped by the
// database anyway. That is why these five queries sat on the
// predicateAuditPending register rather than needing a migration.
//
// The register's own note says what the predicate is still for: a caller that
// opts into orgctx.WithBypassRLS loses the belt and keeps only what the SQL
// says. The vault has such callers — Use() refuses to run without a bypass
// context, because it is the system credential-injection path — so "the belt
// will catch it" is an argument that stops applying exactly where these tables
// are most sensitive.
//
// This test runs the grant and checkout reads UNDER a bypass, which is the
// condition the belt is switched off in, and asserts they still refuse another
// tenant's rows. hasGrant is the predicate behind Reveal: if it answers yes for
// a grant in another organization, a plaintext credential is handed over.
func TestGrantChecksHoldUnderBypass(t *testing.T) {
	db := vaultTestDB(t)
	if db == nil {
		return
	}

	// The harness applies the whole migration set, so these are the REAL belted
	// tables. Seeding therefore has to run under a bypass, which is also the
	// condition the assertions below run in.
	ctx := context.Background()
	seed := orgctx.WithBypassRLS(ctx)

	const principal = "00000000-0000-0000-0000-0000000000d1"
	var orgA, orgB, secretID, grantID string
	if err := db.Pool.QueryRow(seed,
		`SELECT id::text FROM organizations ORDER BY created_at LIMIT 1`).Scan(&orgA); err != nil {
		t.Fatalf("read primary org: %v", err)
	}
	if err := db.Pool.QueryRow(seed, `INSERT INTO organizations (name, slug)
		VALUES ('vault-grant-b','vault-grant-b')
		ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	if err := db.Pool.QueryRow(seed, `INSERT INTO vault_secrets (org_id, name, type)
		VALUES ($1, 'grant-tenant-secret', 'password') RETURNING id::text`, orgB).Scan(&secretID); err != nil {
		t.Fatalf("seed secret: %v", err)
	}

	// One grant and one checkout, both belonging to org B.
	if err := db.Pool.QueryRow(seed, `
		INSERT INTO vault_access_grants (id, org_id, secret_id, principal_type, principal_id, actions)
		VALUES (gen_random_uuid(),$1,$2,'user',$3,ARRAY['reveal']) RETURNING id::text`,
		orgB, secretID, principal).Scan(&grantID); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	if _, err := db.Pool.Exec(seed, `
		INSERT INTO vault_checkouts (org_id, secret_id, secret_version, principal_id, mode)
		VALUES ($1,$2,1,$3,'reveal')`, orgB, secretID, principal); err != nil {
		t.Fatalf("seed checkout: %v", err)
	}

	s := &Service{db: db}

	// The bypass is the point: with it set, the database stops scoping and only
	// the SQL is left.
	asA := orgctx.WithBypassRLS(orgctx.With(ctx, orgctx.Org{ID: orgA}))
	asB := orgctx.WithBypassRLS(orgctx.With(ctx, orgctx.Org{ID: orgB}))

	t.Run("hasGrant refuses another tenant's grant", func(t *testing.T) {
		ok, err := s.hasGrant(asA, secretID, principal, nil, "reveal")
		if err != nil {
			t.Fatalf("hasGrant: %v", err)
		}
		if ok {
			t.Error("org A was granted reveal by a grant belonging to org B. hasGrant is " +
				"the predicate behind Reveal, so this is a plaintext credential handed over")
		}
	})

	t.Run("hasGrant honours the owning tenant's grant", func(t *testing.T) {
		ok, err := s.hasGrant(asB, secretID, principal, nil, "reveal")
		if err != nil {
			t.Fatalf("hasGrant: %v", err)
		}
		if !ok {
			t.Error("org B's own reveal grant was not honoured — the predicate is too tight")
		}
	})

	t.Run("ListGrants shows another tenant nothing", func(t *testing.T) {
		got, err := s.ListGrants(asA, secretID)
		if err != nil {
			t.Fatalf("ListGrants: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("org A listed %d of org B's grants on this secret", len(got))
		}
	})

	t.Run("Checkouts shows another tenant nothing", func(t *testing.T) {
		got, err := s.Checkouts(asA, secretID)
		if err != nil {
			t.Fatalf("Checkouts: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("org A read %d of org B's checkout ledger entries — who revealed "+
				"which credential, when, and why", len(got))
		}
	})

	t.Run("RevokeGrantForPrincipal cannot revoke across tenants", func(t *testing.T) {
		if err := s.RevokeGrantForPrincipal(asA, secretID, "user", principal); err != nil {
			t.Fatalf("RevokeGrantForPrincipal: %v", err)
		}
		var n int
		db.Pool.QueryRow(seed, `SELECT count(*) FROM vault_access_grants WHERE id=$1`, grantID).Scan(&n)
		if n != 1 {
			t.Error("org A revoked org B's grant. A revoke that matches nothing is silent, " +
				"so the caller is told the grant is gone either way")
		}
	})

	t.Run("RemoveGrant cannot remove across tenants", func(t *testing.T) {
		err := s.RemoveGrant(asA, grantID)
		if err == nil {
			t.Error("org A removed org B's grant by id")
		}
		var n int
		db.Pool.QueryRow(seed, `SELECT count(*) FROM vault_access_grants WHERE id=$1`, grantID).Scan(&n)
		if n != 1 {
			t.Error("org B's grant is gone")
		}
	})
}
