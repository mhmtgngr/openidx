package vault

import (
	"context"
	"testing"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestUseRefusesAnotherTenantsSecret covers the one place in this programme
// where the missing predicate was not latent.
//
// Use is the system credential-injection path. It REQUIRES a bypass-RLS
// context — that is its documented contract — so the database's own tenant rule
// is switched off for the read it makes, and the SQL is the only thing left.
// Until this change the SQL selected on the secret id alone.
//
// handleCloudConnect (POST /pam/connect/cloud, no admin guard) takes secret_id
// straight from the request body, resolves the caller's organization, refuses
// without one, and then never used it: it called Use with the caller's chosen
// id under an explicit bypass. Any authenticated user of any tenant could name
// any vault secret in the installation and have its plaintext used as their AWS
// broker credential — the resulting STS credentials returned in the response,
// the brokered session recorded under the CALLER's organization, and nothing at
// all recorded for the tenant whose credential was spent.
//
// The bypass in this test is not a contrivance; it is the condition Use runs in
// by construction.
func TestUseRefusesAnotherTenantsSecret(t *testing.T) {
	db := vaultTestDB(t)
	if db == nil {
		return
	}
	seed := orgctx.WithBypassRLS(context.Background())

	var orgA, orgB, secretID string
	if err := db.Pool.QueryRow(seed,
		`SELECT id::text FROM organizations ORDER BY created_at LIMIT 1`).Scan(&orgA); err != nil {
		t.Fatalf("read primary org: %v", err)
	}
	if err := db.Pool.QueryRow(seed, `INSERT INTO organizations (name, slug)
		VALUES ('vault-use-b','vault-use-b')
		ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	if err := db.Pool.QueryRow(seed, `INSERT INTO vault_secrets (org_id, name, type, current_version)
		VALUES ($1, 'use-tenant-secret', 'password', 1) RETURNING id::text`, orgB).Scan(&secretID); err != nil {
		t.Fatalf("seed org B's secret: %v", err)
	}

	// A real key ring: the assertions below are about which rows the query
	// selects, so the encryption only has to round-trip.
	ring, err := newKeyring("", 1, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	if err != nil || ring == nil {
		t.Fatalf("key ring: %v (ring=%v) — this test must not silently skip", err, ring)
	}
	s := &Service{db: db, ring: ring}
	kid, blob, err := ring.Seal(secretID, 1, []byte("org-b-broker-credential"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	keyID := int(kid)
	if _, err := db.Pool.Exec(seed, `
		INSERT INTO vault_secret_versions (org_id, secret_id, version, key_id, ciphertext)
		VALUES ($1,$2,1,$3,$4)`, orgB, secretID, keyID, blob); err != nil {
		t.Fatalf("seed version: %v", err)
	}

	bypassA := orgctx.WithBypassRLS(orgctx.With(context.Background(), orgctx.Org{ID: orgA}))
	bypassB := orgctx.WithBypassRLS(orgctx.With(context.Background(), orgctx.Org{ID: orgB}))

	t.Run("another tenant cannot use this secret", func(t *testing.T) {
		pt, err := s.Use(bypassA, orgA, secretID)
		if err == nil {
			for i := range pt {
				pt[i] = 0
			}
			t.Error("org A decrypted org B's vault secret. Use runs under an explicit " +
				"RLS bypass, so the org predicate is the only control on this read — " +
				"and POST /pam/connect/cloud passes a caller-supplied secret_id straight to it")
		}
	})

	t.Run("the owning tenant still uses it", func(t *testing.T) {
		pt, err := s.Use(bypassB, orgB, secretID)
		if err != nil {
			t.Fatalf("org B could not use its own secret (%v) — the org predicate must "+
				"scope the read, not empty it", err)
		}
		if string(pt) != "org-b-broker-credential" {
			t.Errorf("plaintext = %q, want the seeded value", string(pt))
		}
		for i := range pt {
			pt[i] = 0
		}
	})

	t.Run("a caller naming no organization is refused", func(t *testing.T) {
		if _, err := s.Use(bypassB, "", secretID); err == nil {
			t.Error("Use decrypted a secret for a caller that named no organization")
		}
	})

	t.Run("a request-scoped caller is still refused outright", func(t *testing.T) {
		noBypass := orgctx.With(context.Background(), orgctx.Org{ID: orgB})
		if _, err := s.Use(noBypass, orgB, secretID); err == nil {
			t.Error("Use ran without a bypass context — its fail-closed contract is gone")
		}
	})
}
