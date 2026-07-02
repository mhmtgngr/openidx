//go:build integration

package integration

// Vault integration tests — Task 10 of 2026-07-02-pam-m1-vault-store.md
//
// Bootstrap model: identical to cross_org_test.go.
//   - integrationDB(t)    — admin (superuser) pool; skips if DATABASE_URL/POSTGRES_PASSWORD unset.
//   - rlsRolePool(t, db)  — dedicated NOSUPERUSER/NOBYPASSRLS pool for real RLS assertion.
//   - bypassExec/seedOrg  — from helpers already in cross_org_test.go.
//
// GUC strategy: the vault Service's pool connections are raw (no GUC set). Rather
// than patching the production pool, we test the crypto path via the Service on
// the admin (superuser, which ignores RLS) pool for round-trip assertions, and
// test the RLS predicate directly via acquired connections on the NOSUPERUSER role
// pool with set_config(...,false) — exactly the pattern TestRLSBelt uses.
//
// For the Service round-trip the admin pool is wrapped in a bypass transaction
// (mirroring seedUserInOrg). The FORCE-RLS vault tables would otherwise reject the
// raw INSERT (no app.org_id GUC + no WITH CHECK bypass). The superuser pool bypasses
// RLS inherently, but to be explicit and match the seeding convention, we set
// app.bypass_rls='on' in the transaction that calls Service.Store. Because Store
// calls pool.Begin() on the same pool, and the superuser already bypasses RLS, this
// works as expected.
//
// Run: go test -tags=integration ./test/integration/ -run TestVault -v

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/vault"
)

// rlsRolePoolForVault extends rlsRolePool's grant set to include the four vault
// tables so the NOSUPERUSER role can run SELECT assertions on them.
func rlsRolePoolForVault(t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	// Grant vault tables to the RLS test role before opening the pool.
	for _, stmt := range []string{
		`GRANT SELECT, INSERT, UPDATE, DELETE ON vault_secrets TO openidx_rls_test`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON vault_secret_versions TO openidx_rls_test`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON vault_access_grants TO openidx_rls_test`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON vault_checkouts TO openidx_rls_test`,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Logf("vault grant (may be pre-existing): %v", err)
		}
	}
	return rlsRolePool(t, admin)
}

// newVaultService builds a vault.Service backed by the provided pool. The keyring
// uses a deterministic 32-byte test KEK (id 0) so the tests are hermetic.
func newVaultService(t *testing.T, pool *pgxpool.Pool) *vault.Service {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	ring, err := vault.KeyringFromConfig(vault.KeyConfig{
		// 32-byte raw key via ENCRYPTION_KEY fallback path (test-only; never production).
		EncryptionKey: "vault-integration-test-kek-00000",
	})
	require.NoError(t, err, "build test keyring")
	db := &database.PostgresDB{Pool: pool}
	svc, err := vault.NewService(db, ring, nil, 5*time.Minute, logger)
	require.NoError(t, err, "construct vault Service")
	return svc
}

// seedVaultSecret inserts a vault_secret + version directly under app.bypass_rls
// (mirroring seedUserInOrg). Returns the secret UUID. The ring/AEAD operations
// are intentionally done outside the DB transaction so the ciphertext comparison
// in the round-trip test stays independent of the Service code path.
func seedVaultSecret(t *testing.T, admin *pgxpool.Pool, orgID, name string, plaintext []byte, svc *vault.Service) string {
	t.Helper()
	// Use the vault Service to Store — it runs its own transaction on the admin
	// pool. Superusers bypass FORCE RLS so this works without needing to set the
	// GUC, but we set bypass explicitly on the context for clarity.
	ctx := orgctx.With(orgctx.WithBypassRLS(context.Background()), orgctx.Org{ID: orgID})
	meta, err := svc.Store(ctx, vault.StoreInput{
		Name:  name,
		Type:  "generic",
		Value: plaintext,
	})
	require.NoError(t, err, "seed vault secret %s in org %s", name, orgID)
	return meta.ID
}

// cleanupVaultSecret removes a vault_secret (cascade deletes versions+checkouts).
func cleanupVaultSecret(t *testing.T, admin *pgxpool.Pool, secretID string) {
	t.Helper()
	bypassExec(t, admin, `DELETE FROM vault_secrets WHERE id = $1`, secretID)
}

// ── TestVaultMigrationApplies ─────────────────────────────────────────────────

// TestVaultMigrationApplies asserts that migration v56 has been applied: the four
// vault_* tables exist and both relrowsecurity AND relforcerowsecurity are true on
// each of them. It mirrors the requireForceRLS helper but targets all four tables
// and fails rather than skips when the tables are missing (a missing table means
// the migration was not applied, which is a hard failure for this feature).
func TestVaultMigrationApplies(t *testing.T) {
	db := integrationDB(t)
	defer db.Close()
	ctx := context.Background()

	tables := []string{
		"vault_secrets",
		"vault_secret_versions",
		"vault_access_grants",
		"vault_checkouts",
	}
	for _, tbl := range tables {
		tbl := tbl
		t.Run(tbl, func(t *testing.T) {
			var rls, forced bool
			err := db.QueryRow(ctx,
				`SELECT relrowsecurity, relforcerowsecurity
				 FROM pg_class
				 WHERE relname = $1 AND relkind = 'r'`, tbl).Scan(&rls, &forced)
			if err != nil {
				t.Fatalf("table %s not found in pg_class (migration v56 not applied?): %v", tbl, err)
			}
			assert.True(t, rls, "table %s must have relrowsecurity = true", tbl)
			assert.True(t, forced, "table %s must have relforcerowsecurity = true (FORCE ROW LEVEL SECURITY)", tbl)
		})
	}
}

// ── TestVaultRoundTrip ────────────────────────────────────────────────────────

// TestVaultRoundTrip exercises the full store-seal-reveal lifecycle:
//  1. Store a secret; verify the stored ciphertext does not contain the plaintext.
//  2. Reveal (admin path) returns the original value.
//  3. NewVersion bumps current_version; the new version decrypts correctly.
//  4. The previous version row still exists in vault_secret_versions.
//  5. Delete removes the secret (and cascades to versions).
//
// The Service is backed by the admin (superuser) pool; superusers bypass FORCE
// RLS so the pool connects without needing app.org_id. We still set an orgctx and
// bypass marker on the context to satisfy orgctx.From and vault.Use's guard.
func TestVaultRoundTrip(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()

	// Skip if vault tables aren't present (migration not applied in this DB).
	var exists bool
	err := admin.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname='vault_secrets' AND relkind='r')`).
		Scan(&exists)
	require.NoError(t, err)
	if !exists {
		t.Skip("vault_secrets table not found — migration v56 not applied in this DB")
	}

	svc := newVaultService(t, admin)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgID := seedOrg(t, admin, "vault-rt-"+suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	const plaintext = "s3cr3t-p@ssw0rd"
	ctx := orgctx.With(orgctx.WithBypassRLS(context.Background()), orgctx.Org{ID: orgID})

	// 1. Store.
	meta, err := svc.Store(ctx, vault.StoreInput{
		Name:  "rt-secret-" + suffix,
		Type:  "generic",
		Value: []byte(plaintext),
	})
	require.NoError(t, err, "Store")
	assert.Equal(t, 1, meta.CurrentVersion)
	t.Cleanup(func() { cleanupVaultSecret(t, admin, meta.ID) })

	// 2. Ciphertext in the DB must not contain the plaintext.
	var ciphertext []byte
	err = admin.QueryRow(context.Background(),
		`SELECT ciphertext FROM vault_secret_versions WHERE secret_id = $1 AND version = 1`,
		meta.ID).Scan(&ciphertext)
	require.NoError(t, err, "read ciphertext from vault_secret_versions")
	assert.False(t, bytes.Contains(ciphertext, []byte(plaintext)),
		"ciphertext stored in vault_secret_versions must not contain the plaintext")

	// 3. Reveal (admin path — isAdmin=true skips grant check).
	revealed, err := svc.Reveal(ctx, meta.ID, "", nil, "integration test round-trip", true)
	require.NoError(t, err, "Reveal")
	assert.Equal(t, plaintext, string(revealed), "Reveal must return the original plaintext")

	// 4. NewVersion bumps current_version.
	const plaintext2 = "updated-s3cr3t"
	v2, err := svc.NewVersion(ctx, meta.ID, []byte(plaintext2), "")
	require.NoError(t, err, "NewVersion")
	assert.Equal(t, 2, v2)

	// 5. Retrieve the detail — current_version must be 2, two versions present.
	detail, err := svc.Get(ctx, meta.ID)
	require.NoError(t, err, "Get after NewVersion")
	assert.Equal(t, 2, detail.CurrentVersion)
	assert.Len(t, detail.Versions, 2, "must have 2 version rows")

	// 6. Old version (v1) row still present in DB.
	var v1Count int
	err = admin.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM vault_secret_versions WHERE secret_id = $1 AND version = 1`,
		meta.ID).Scan(&v1Count)
	require.NoError(t, err)
	assert.Equal(t, 1, v1Count, "v1 ciphertext row must still exist after NewVersion")

	// 7. Reveal after version bump returns new value.
	revealed2, err := svc.Reveal(ctx, meta.ID, "", nil, "round-trip v2 check", true)
	require.NoError(t, err, "Reveal v2")
	assert.Equal(t, plaintext2, string(revealed2), "Reveal must return v2 plaintext after bump")

	// 8. Delete removes the secret (cascade).
	err = svc.Delete(ctx, meta.ID)
	require.NoError(t, err, "Delete")

	var afterDelete int
	err = admin.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM vault_secrets WHERE id = $1`, meta.ID).Scan(&afterDelete)
	require.NoError(t, err)
	assert.Equal(t, 0, afterDelete, "Delete must remove the secret row")

	var versionsAfter int
	err = admin.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM vault_secret_versions WHERE secret_id = $1`, meta.ID).
		Scan(&versionsAfter)
	require.NoError(t, err)
	assert.Equal(t, 0, versionsAfter, "Delete must cascade-remove all version rows")
}

// ── TestVaultRLSIsolation ─────────────────────────────────────────────────────

// TestVaultRLSIsolation verifies the FORCE RLS belt on the vault tables:
//
//	org A stores a secret → set app.org_id = org B → SELECT returns 0 rows
//	set app.bypass_rls = 'on' → SELECT returns the row
//
// This mirrors TestRLSBelt / TestRLSBeltTables exactly: seeding uses the admin
// (superuser) pool under bypass, assertions use the NOSUPERUSER role pool with
// set_config(...,false) so the policies actually fire. A superuser ignores FORCE
// RLS even on non-owned tables, so assertions on the admin pool would be vacuous.
func TestVaultRLSIsolation(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()

	// Skip if vault tables aren't present (migration not applied in this DB).
	var exists bool
	err := admin.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname='vault_secrets' AND relkind='r')`).
		Scan(&exists)
	require.NoError(t, err)
	if !exists {
		t.Skip("vault_secrets table not found — migration v56 not applied in this DB")
	}

	// Skip if FORCE RLS isn't active (requireForceRLS skips rather than fails).
	requireForceRLS(t, admin, "vault_secrets")
	requireForceRLS(t, admin, "vault_secret_versions")

	svc := newVaultService(t, admin)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgA := seedOrg(t, admin, "vrls-a-"+suffix)
	orgB := seedOrg(t, admin, "vrls-b-"+suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM organizations WHERE id IN ($1,$2)`, orgA, orgB)
	})

	// Seed a secret in org A using the Service (superuser pool bypasses FORCE RLS).
	const plaintext = "isolated-credential"
	secretID := seedVaultSecret(t, admin, orgA, "vrls-secret-"+suffix, []byte(plaintext), svc)
	t.Cleanup(func() { cleanupVaultSecret(t, admin, secretID) })

	// Open the NOSUPERUSER role pool (with vault-table grants).
	rolePool := rlsRolePoolForVault(t, admin)
	defer rolePool.Close()

	ctx := context.Background()
	conn, err := rolePool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()

	// Helper: set GUCs on the acquired connection (persistent for the session, same
	// as TestRLSBelt and TestPreResolutionLookupsUnderRLS).
	setScope := func(orgID, bypass string) {
		_, err := conn.Exec(ctx,
			`select set_config('app.org_id', $1, false), set_config('app.bypass_rls', $2, false)`,
			orgID, bypass)
		require.NoError(t, err)
	}
	countSecrets := func() int {
		var n int
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM vault_secrets WHERE id = $1`, secretID).Scan(&n))
		return n
	}
	countVersions := func() int {
		var n int
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM vault_secret_versions WHERE secret_id = $1`, secretID).Scan(&n))
		return n
	}

	t.Run("scoped to org A: sees its own secret", func(t *testing.T) {
		setScope(orgA, "off")
		assert.Equal(t, 1, countSecrets(), "org A must see its own vault_secrets row")
		assert.Equal(t, 1, countVersions(), "org A must see its own vault_secret_versions row")
	})

	t.Run("scoped to org B: cannot see org A's secret (0 rows)", func(t *testing.T) {
		setScope(orgB, "off")
		assert.Equal(t, 0, countSecrets(), "org B must not see org A's vault_secrets row (RLS filtered)")
		assert.Equal(t, 0, countVersions(), "org B must not see org A's vault_secret_versions row (RLS filtered)")
	})

	t.Run("no scope set: fail-closed (0 rows)", func(t *testing.T) {
		setScope("", "off")
		assert.Equal(t, 0, countSecrets(), "unset app.org_id must be fail-closed on vault_secrets")
		assert.Equal(t, 0, countVersions(), "unset app.org_id must be fail-closed on vault_secret_versions")
	})

	t.Run("bypass=on: sees across orgs", func(t *testing.T) {
		setScope("", "on")
		assert.Equal(t, 1, countSecrets(), "app.bypass_rls='on' must reveal org A's secret from any session")
		assert.Equal(t, 1, countVersions(), "app.bypass_rls='on' must reveal version row from any session")
	})

	t.Run("ciphertext under bypass does not contain plaintext", func(t *testing.T) {
		setScope("", "on")
		var ct []byte
		err := conn.QueryRow(ctx,
			`SELECT ciphertext FROM vault_secret_versions WHERE secret_id = $1 AND version = 1`,
			secretID).Scan(&ct)
		require.NoError(t, err)
		assert.False(t, bytes.Contains(ct, []byte(plaintext)),
			"ciphertext at rest must not contain plaintext even when RLS is bypassed")
	})

	t.Run("vault_access_grants RLS: org B cannot see grants for org A secrets", func(t *testing.T) {
		// Insert a grant row for org A's secret (via admin / bypass seeding).
		grantID := ""
		func() {
			gctx := orgctx.With(orgctx.WithBypassRLS(context.Background()), orgctx.Org{ID: orgA})
			var err error
			grantID, err = svc.AddGrant(gctx, vault.Grant{
				SecretID:      secretID,
				PrincipalType: "user",
				PrincipalID:   "00000000-0000-0000-0000-000000000001",
				Actions:       []string{"use"},
				GrantedBy:     "",
			})
			require.NoError(t, err, "AddGrant for org A secret")
		}()
		t.Cleanup(func() {
			grantCtx := orgctx.WithBypassRLS(context.Background())
			_ = svc.RemoveGrant(grantCtx, grantID)
		})

		setScope(orgB, "off")
		var n int
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM vault_access_grants WHERE secret_id = $1`, secretID).Scan(&n))
		assert.Equal(t, 0, n, "org B must not see org A's vault_access_grants row")

		setScope(orgA, "off")
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM vault_access_grants WHERE secret_id = $1`, secretID).Scan(&n))
		assert.Equal(t, 1, n, "org A must see its own vault_access_grants row")
	})

	t.Run("vault_checkouts RLS: org B cannot see org A's checkout records", func(t *testing.T) {
		// Reveal creates a checkout record. Use the admin (bypass) path.
		revCtx := orgctx.With(orgctx.WithBypassRLS(context.Background()), orgctx.Org{ID: orgA})
		_, err := svc.Reveal(revCtx, secretID, "", nil, "rls isolation test reveal", true)
		require.NoError(t, err, "Reveal to generate checkout row")

		setScope(orgB, "off")
		var n int
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM vault_checkouts WHERE secret_id = $1`, secretID).Scan(&n))
		assert.Equal(t, 0, n, "org B must not see org A's vault_checkouts rows")

		setScope(orgA, "off")
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM vault_checkouts WHERE secret_id = $1`, secretID).Scan(&n))
		assert.Greater(t, n, 0, "org A must see its own vault_checkouts rows")
	})
}
