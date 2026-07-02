//go:build integration

package integration

// JIT credential checkout integration test — Task 8 of
// 2026-07-02-pam-m2b-jit-credential-checkout.md.
//
// Bootstrap: reuses integrationDB, seedOrg, bypassExec (cross_org_test.go),
// newCredsVaultService / seedCredsPolicy (rotation_test.go),
// rlsRolePoolForVault (vault_test.go), and the orgctx idiom from all three.
//
// Layer: vault.Service + DB-direct; governance HTTP handlers are not driven
// (gin+JWT wiring is heavy). This validates the checkout mechanics that the
// HTTP layer delegates to.
//
// Run: go test -tags=integration ./test/integration/ -run TestJITCredentialCheckout -v

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/vault"
)

// TestJITCredentialCheckout covers the end-to-end mechanics of the JIT
// credential checkout feature at the vault-service + DB layer:
//
//  1. Store a secret (v1) under bypass+org ctx.
//  2. Seed a rotate_on_checkout=true rotation policy for that secret.
//  3. Simulate fulfillment: AddGrant with a future expiry.
//  4. Assert Reveal returns the stored value (grant authorizes).
//  5. Simulate rotate-on-return: UPDATE next_run_at=NOW(); assert it is non-null and <= NOW().
//  6. Simulate early return: RevokeGrantForPrincipal; assert Reveal is now denied (ErrForbidden).
//  7. Expired-grant path: AddGrant with past expiry; assert Reveal is denied.
//  8. RLS: second org's context cannot Reveal org A's secret.
func TestJITCredentialCheckout(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()

	// Skip if vault tables are absent (migration v56 not applied).
	var vaultExists bool
	err := admin.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname='vault_secrets' AND relkind='r')`).
		Scan(&vaultExists)
	require.NoError(t, err)
	if !vaultExists {
		t.Skip("vault_secrets table not found — migration v56 not applied in this DB")
	}

	// Skip if credential_rotation_policies is absent (migration v57 not applied).
	skipIfCredsMigrationNotApplied(t, admin)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgID := seedOrg(t, admin, "jit-co-"+suffix)
	orgB := seedOrg(t, admin, "jit-co-b-"+suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM credential_rotation_policies WHERE org_id IN ($1,$2)`, orgID, orgB)
		bypassExec(t, admin, `DELETE FROM vault_secrets WHERE org_id IN ($1,$2)`, orgID, orgB)
		bypassExec(t, admin, `DELETE FROM organizations WHERE id IN ($1,$2)`, orgID, orgB)
	})

	vaultSvc := newCredsVaultService(t, admin)

	// ── Step 1: Store a secret (v1, value "svc-pw") under bypass+org ctx ────────
	ctx := orgctx.With(orgctx.WithBypassRLS(context.Background()), orgctx.Org{ID: orgID})
	meta, err := vaultSvc.Store(ctx, vault.StoreInput{
		Name:  "jit-secret-" + suffix,
		Type:  "generic",
		Value: []byte("svc-pw"),
	})
	require.NoError(t, err, "Store vault secret")
	assert.Equal(t, 1, meta.CurrentVersion, "initial current_version must be 1")
	secretID := meta.ID

	// ── Step 2: Seed rotate_on_checkout=true policy for that secret ─────────────
	policyID := seedCredsPolicy(t, admin, orgID, secretID, true)
	require.NotEmpty(t, policyID, "seedCredsPolicy must return a policy id")

	// Verify last_run_at starts as NULL (or the seeded default).
	// seedCredsPolicy sets interval_seconds=0, enabled=true, rotate_on_checkout=$3.
	var nextRunAt *time.Time
	{
		bCtx := context.Background()
		tx, txErr := admin.Begin(bCtx)
		require.NoError(t, txErr)
		_, _ = tx.Exec(bCtx, `SELECT set_config('app.bypass_rls','on',true)`)
		_ = tx.QueryRow(bCtx,
			`SELECT next_run_at FROM credential_rotation_policies WHERE id=$1`, policyID).
			Scan(&nextRunAt)
		_ = tx.Commit(bCtx)
	}
	// next_run_at may be NULL or already set; we just record it for the later assertion.

	// ── Step 3: Simulate fulfillment — AddGrant with future expiry ───────────────
	userID := uuid.New().String()
	future := time.Now().Add(1 * time.Hour)
	grantID, err := vaultSvc.AddGrant(ctx, vault.Grant{
		SecretID:      secretID,
		PrincipalType: "user",
		PrincipalID:   userID,
		Actions:       []string{"reveal"},
		ExpiresAt:     &future,
	})
	require.NoError(t, err, "AddGrant must succeed for future expiry")
	require.NotEmpty(t, grantID, "AddGrant must return a grant id")

	// ── Step 4: Assert Reveal returns the stored value ───────────────────────────
	revealed, err := vaultSvc.Reveal(ctx, secretID, userID, nil, "JIT test", false)
	require.NoError(t, err, "Reveal must succeed when a valid grant is present")
	assert.Equal(t, "svc-pw", string(revealed), "Reveal must return the stored plaintext 'svc-pw'")

	// ── Step 5: Simulate rotate-on-return ────────────────────────────────────────
	// Mirror bumpRotationOnReturn from governance/workflows.go.
	before := time.Now()
	bypassExec(t, admin,
		`UPDATE credential_rotation_policies SET next_run_at = NOW()
		 WHERE secret_id = $1 AND rotate_on_checkout = true`, secretID)

	// Read back next_run_at and assert it is now non-null and <= NOW().
	var rotateNextRunAt time.Time
	{
		bCtx := context.Background()
		tx, txErr := admin.Begin(bCtx)
		require.NoError(t, txErr)
		_, _ = tx.Exec(bCtx, `SELECT set_config('app.bypass_rls','on',true)`)
		err = tx.QueryRow(bCtx,
			`SELECT next_run_at FROM credential_rotation_policies WHERE id=$1`, policyID).
			Scan(&rotateNextRunAt)
		_ = tx.Commit(bCtx)
	}
	require.NoError(t, err, "must be able to read next_run_at after rotate-on-return bump")
	assert.False(t, rotateNextRunAt.IsZero(), "next_run_at must be non-null after rotate-on-return bump")
	assert.True(t, !rotateNextRunAt.After(time.Now()),
		"next_run_at must be <= NOW() after bump (got %v, before=%v)", rotateNextRunAt, before)

	// ── Step 6: Simulate early return — RevokeGrantForPrincipal ─────────────────
	err = vaultSvc.RevokeGrantForPrincipal(ctx, secretID, "user", userID)
	require.NoError(t, err, "RevokeGrantForPrincipal must succeed")

	// Reveal must now be denied because the grant is gone.
	_, err = vaultSvc.Reveal(ctx, secretID, userID, nil, "JIT test post-revoke", false)
	require.Error(t, err, "Reveal must return an error after grant is revoked")
	assert.True(t, errors.Is(err, vault.ErrForbidden),
		"Reveal after revoke must return ErrForbidden, got: %v", err)

	// ── Step 7: Expired-grant path ───────────────────────────────────────────────
	past := time.Now().Add(-1 * time.Minute)
	_, err = vaultSvc.AddGrant(ctx, vault.Grant{
		SecretID:      secretID,
		PrincipalType: "user",
		PrincipalID:   userID,
		Actions:       []string{"reveal"},
		ExpiresAt:     &past,
	})
	require.NoError(t, err, "AddGrant with past expiry must not error (insert is valid)")

	_, err = vaultSvc.Reveal(ctx, secretID, userID, nil, "JIT test expired grant", false)
	require.Error(t, err, "Reveal with an expired grant must be denied")
	assert.True(t, errors.Is(err, vault.ErrForbidden),
		"Reveal with expired grant must return ErrForbidden, got: %v", err)

	// Clean up the expired grant so it doesn't interfere with the RLS subtest.
	_ = vaultSvc.RevokeGrantForPrincipal(ctx, secretID, "user", userID)

	// ── Step 8: RLS — org B cannot Reveal org A's secret ────────────────────────
	// requireForceRLS skips (not fails) if FORCE RLS is not active, which avoids a
	// false negative on a plain-superuser dev DB. The test is real on CI.
	requireForceRLS(t, admin, "vault_secrets")
	requireForceRLS(t, admin, "vault_access_grants")

	t.Run("rls: org B cannot reveal org A secret", func(t *testing.T) {
		// Open a NOSUPERUSER role pool so RLS actually fires.
		rolePool := rlsRolePoolForVault(t, admin)
		defer rolePool.Close()

		// Build a vault.Service backed by the NOSUPERUSER pool — RLS applies.
		// newVaultService is defined in vault_test.go and uses the same test KEK.
		rlsVaultSvc := newVaultService(t, rolePool)

		// Seed a grant for a new userID on org A's secret (via admin / bypass).
		rlsUserID := uuid.New().String()
		rlsFuture := time.Now().Add(1 * time.Hour)
		adminCtx := orgctx.With(orgctx.WithBypassRLS(context.Background()), orgctx.Org{ID: orgID})
		_, err := vaultSvc.AddGrant(adminCtx, vault.Grant{
			SecretID:      secretID,
			PrincipalType: "user",
			PrincipalID:   rlsUserID,
			Actions:       []string{"reveal"},
			ExpiresAt:     &rlsFuture,
		})
		require.NoError(t, err, "seed grant for RLS subtest")
		t.Cleanup(func() {
			_ = vaultSvc.RevokeGrantForPrincipal(adminCtx, secretID, "user", rlsUserID)
		})

		// Attempt Reveal from org B's context — RLS must hide the secret (ErrNotFound
		// or ErrForbidden; either proves the secret is invisible to org B).
		ctxB := orgctx.With(context.Background(), orgctx.Org{ID: orgB})
		_, err = rlsVaultSvc.Reveal(ctxB, secretID, rlsUserID, nil, "RLS cross-org JIT test", false)
		require.Error(t, err,
			"org B must not be able to Reveal org A's secret; expected ErrNotFound or ErrForbidden")
		assert.True(t, errors.Is(err, vault.ErrNotFound) || errors.Is(err, vault.ErrForbidden),
			"org B Reveal must return ErrNotFound or ErrForbidden (got %v) — RLS must filter the secret", err)
	})
}
