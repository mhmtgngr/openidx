//go:build integration

package integration

// Credential rotation engine integration tests — Task 10 of
// 2026-07-02-pam-m1b-rotation-engine.md.
//
// Bootstrap model: identical to vault_test.go / cross_org_test.go.
//   - integrationDB(t)   — admin (superuser) pool; skips if DATABASE_URL/POSTGRES_PASSWORD unset.
//   - rlsRolePoolForCreds(t, db) — NOSUPERUSER pool with cred-table grants for real RLS assertions.
//   - bypassExec / seedOrg — from cross_org_test.go helpers.
//
// Fake rotator: fakeDirectoryRotator implements credentials.Rotator with Type()=="directory".
// Apply/Verify behaviour is controlled per-test via boolean flags and a captured-call counter.
// Passing []credentials.Rotator{fake} to credentials.NewService exercises the full
// DB-backed RotateSecret state machine + vault candidate/promote path without a real LDAP.
//
// Run: go test -tags=integration ./test/integration/ -run 'TestRotation|TestRotate' -v

import (
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
	"github.com/openidx/openidx/internal/credentials"
	"github.com/openidx/openidx/internal/vault"
)

// ── fakeDirectoryRotator ──────────────────────────────────────────────────────

// fakeDirectoryRotator is a test double for credentials.Rotator.
// Set applyErr/verifyErr before a rotation to inject faults.
// ApplyCalls records every Apply invocation.
type fakeDirectoryRotator struct {
	applyErr   error
	verifyErr  error
	ApplyCalls [][]byte // each call appends a copy of newValue
}

func (f *fakeDirectoryRotator) Type() string { return "directory" }

func (f *fakeDirectoryRotator) Apply(_ context.Context, _ map[string]any, newValue []byte) error {
	cp := make([]byte, len(newValue))
	copy(cp, newValue)
	f.ApplyCalls = append(f.ApplyCalls, cp)
	return f.applyErr
}

func (f *fakeDirectoryRotator) Verify(_ context.Context, _ map[string]any, _ []byte) error {
	if f.verifyErr != nil {
		return f.verifyErr
	}
	return credentials.ErrVerifyUnsupported // skip verification by default
}

// ── helpers ───────────────────────────────────────────────────────────────────

// newCredsVaultService constructs a vault.Service backed by the provided pool
// using the same 32-byte test KEK as vault_test.go so both can share secrets.
func newCredsVaultService(t *testing.T, pool *pgxpool.Pool) *vault.Service {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	ring, err := vault.KeyringFromConfig(vault.KeyConfig{
		EncryptionKey: "vault-integration-test-kek-00000",
	})
	require.NoError(t, err, "build test keyring")
	db := &database.PostgresDB{Pool: pool}
	svc, err := vault.NewService(db, ring, nil, 5*time.Minute, logger)
	require.NoError(t, err, "construct vault Service")
	return svc
}

// newCredsService builds a credentials.Service with the provided fake rotator.
func newCredsService(t *testing.T, pool *pgxpool.Pool, vaultSvc *vault.Service, fake *fakeDirectoryRotator) *credentials.Service {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	db := &database.PostgresDB{Pool: pool}
	return credentials.NewService(db, vaultSvc, []credentials.Rotator{fake}, nil, 24, logger)
}

// seedCredsPolicy inserts a credential_rotation_policies row directly under
// bypass (RLS force-reject raw inserts without a scoped context) and returns
// the policy UUID. connector_type must be "directory" to match the fake rotator.
func seedCredsPolicy(t *testing.T, admin *pgxpool.Pool, orgID, secretID string, rotateOnCheckout bool) string {
	t.Helper()
	var policyID string
	bypassExec(t, admin,
		`INSERT INTO credential_rotation_policies
		   (org_id, secret_id, connector_type, connector_config, generation_policy,
		    interval_seconds, rotate_on_checkout, enabled)
		 VALUES ($1,$2,'directory',
		         '{"directory_id":"test-dir","username":"svc-acct"}'::jsonb,
		         '{}'::jsonb, 0, $3, true)
		 RETURNING id`,
		orgID, secretID, rotateOnCheckout)
	// bypassExec is fire-and-forget; query the id separately.
	ctx := context.Background()
	tx, err := admin.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
	require.NoError(t, err)
	err = tx.QueryRow(ctx,
		`SELECT id FROM credential_rotation_policies WHERE org_id=$1 AND secret_id=$2 ORDER BY created_at DESC LIMIT 1`,
		orgID, secretID).Scan(&policyID)
	require.NoError(t, err, "seed creds policy: read back id")
	require.NoError(t, tx.Commit(ctx))
	return policyID
}

// rlsRolePoolForCreds extends rlsRolePool's grants to include the two creds tables.
func rlsRolePoolForCreds(t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	for _, stmt := range []string{
		`GRANT SELECT, INSERT, UPDATE, DELETE ON credential_rotation_policies TO openidx_rls_test`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON credential_rotations TO openidx_rls_test`,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Logf("creds grant (may be pre-existing): %v", err)
		}
	}
	// Also grant vault tables required by the creds engine queries.
	for _, stmt := range []string{
		`GRANT SELECT, INSERT, UPDATE, DELETE ON vault_secrets TO openidx_rls_test`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON vault_secret_versions TO openidx_rls_test`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON vault_checkouts TO openidx_rls_test`,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Logf("vault grant (may be pre-existing): %v", err)
		}
	}
	return rlsRolePool(t, admin)
}

// skipIfCredsMigrationNotApplied skips the test when v57 tables are absent.
func skipIfCredsMigrationNotApplied(t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	var exists bool
	err := db.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname='credential_rotation_policies' AND relkind='r')`).
		Scan(&exists)
	require.NoError(t, err)
	if !exists {
		t.Skip("credential_rotation_policies table not found — migration v57 not applied in this DB")
	}
}

// ── TestRotationMigrationApplies ─────────────────────────────────────────────

// TestRotationMigrationApplies asserts that migration v57 has been applied:
// both credential_rotation_policies and credential_rotations have FORCE ROW
// LEVEL SECURITY (relforcerowsecurity = true).
func TestRotationMigrationApplies(t *testing.T) {
	db := integrationDB(t)
	defer db.Close()
	skipIfCredsMigrationNotApplied(t, db)

	ctx := context.Background()
	tables := []string{
		"credential_rotation_policies",
		"credential_rotations",
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
				t.Fatalf("table %s not found in pg_class (migration v57 not applied?): %v", tbl, err)
			}
			assert.True(t, rls, "table %s must have relrowsecurity = true", tbl)
			assert.True(t, forced, "table %s must have relforcerowsecurity = true (FORCE ROW LEVEL SECURITY)", tbl)
		})
	}
}

// ── TestRotateNowDirectory ────────────────────────────────────────────────────

// TestRotateNowDirectory exercises the full on-demand rotation happy path:
//  1. Seed an org + vault secret (version 1).
//  2. Seed a directory rotation policy pointing at that secret.
//  3. Call credentials.Service.RotateSecret(ctx, policyID, "on_demand").
//  4. Assert the ledger row is status='succeeded', version_from=1, version_to=2.
//  5. Assert vault_secrets.current_version is now 2.
//  6. Assert the fake rotator's Apply was called once with a 24-char value.
func TestRotateNowDirectory(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()
	skipIfCredsMigrationNotApplied(t, admin)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgID := seedOrg(t, admin, "rot-now-"+suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM credential_rotation_policies WHERE org_id=$1`, orgID)
		bypassExec(t, admin, `DELETE FROM vault_secrets WHERE org_id=$1`, orgID)
		bypassExec(t, admin, `DELETE FROM organizations WHERE id=$1`, orgID)
	})

	vaultSvc := newCredsVaultService(t, admin)

	// Store vault secret (version 1) under org context.
	ctx := orgctx.With(orgctx.WithBypassRLS(context.Background()), orgctx.Org{ID: orgID})
	meta, err := vaultSvc.Store(ctx, vault.StoreInput{
		Name:  "rot-secret-" + suffix,
		Type:  "generic",
		Value: []byte("initial-value"),
	})
	require.NoError(t, err, "Store vault secret")
	assert.Equal(t, 1, meta.CurrentVersion, "initial current_version must be 1")

	policyID := seedCredsPolicy(t, admin, orgID, meta.ID, false)

	fake := &fakeDirectoryRotator{}
	credsSvc := newCredsService(t, admin, vaultSvc, fake)

	require.NoError(t, credsSvc.RotateSecret(context.Background(), policyID, "on_demand"))

	// 1. Fake rotator Apply was called exactly once.
	require.Len(t, fake.ApplyCalls, 1, "fake Apply must be called exactly once")
	assert.Len(t, fake.ApplyCalls[0], 24, "generated value must be 24 chars (default length)")

	// 2. Ledger row is succeeded with correct version_from/to.
	ctx2 := context.Background()
	var status string
	var vFrom, vTo int
	err = admin.QueryRow(ctx2,
		`SELECT status, COALESCE(version_from, 0), COALESCE(version_to, 0)
		 FROM credential_rotations
		 WHERE policy_id = $1
		 ORDER BY started_at DESC LIMIT 1`, policyID).Scan(&status, &vFrom, &vTo)
	require.NoError(t, err, "read ledger row")
	assert.Equal(t, "succeeded", status, "ledger status must be 'succeeded'")
	assert.Equal(t, 1, vFrom, "version_from must be 1 (was current before rotation)")
	assert.Equal(t, 2, vTo, "version_to must be 2 (new current_version after promote)")

	// 3. vault_secrets.current_version is now 2.
	var cv int
	err = admin.QueryRow(ctx2,
		`SELECT current_version FROM vault_secrets WHERE id = $1`, meta.ID).Scan(&cv)
	require.NoError(t, err, "read vault current_version")
	assert.Equal(t, 2, cv, "vault secret current_version must be 2 after rotation")

	// 4. Two version rows exist.
	var vcount int
	err = admin.QueryRow(ctx2,
		`SELECT COUNT(*) FROM vault_secret_versions WHERE secret_id = $1`, meta.ID).Scan(&vcount)
	require.NoError(t, err)
	assert.Equal(t, 2, vcount, "two version rows must exist after rotation (v1 + v2)")
}

// ── TestRotateFailureKeepsCurrent ────────────────────────────────────────────

// TestRotateFailureKeepsCurrent confirms that when the fake rotator's Apply
// returns an error the engine records a 'failed' ledger row and vault
// current_version stays at 1 (no promotion occurred).
func TestRotateFailureKeepsCurrent(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()
	skipIfCredsMigrationNotApplied(t, admin)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgID := seedOrg(t, admin, "rot-fail-"+suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM credential_rotation_policies WHERE org_id=$1`, orgID)
		bypassExec(t, admin, `DELETE FROM vault_secrets WHERE org_id=$1`, orgID)
		bypassExec(t, admin, `DELETE FROM organizations WHERE id=$1`, orgID)
	})

	vaultSvc := newCredsVaultService(t, admin)
	ctx := orgctx.With(orgctx.WithBypassRLS(context.Background()), orgctx.Org{ID: orgID})
	meta, err := vaultSvc.Store(ctx, vault.StoreInput{
		Name:  "rot-fail-secret-" + suffix,
		Type:  "generic",
		Value: []byte("original-value"),
	})
	require.NoError(t, err, "Store vault secret")

	policyID := seedCredsPolicy(t, admin, orgID, meta.ID, false)

	fake := &fakeDirectoryRotator{applyErr: fmt.Errorf("LDAP server unreachable")}
	credsSvc := newCredsService(t, admin, vaultSvc, fake)

	// RotateSecret should not return an error itself (failure is recorded in the ledger).
	require.NoError(t, credsSvc.RotateSecret(context.Background(), policyID, "on_demand"))

	// Ledger row must be 'failed'.
	var status string
	err = admin.QueryRow(context.Background(),
		`SELECT status FROM credential_rotations
		 WHERE policy_id = $1 ORDER BY started_at DESC LIMIT 1`, policyID).Scan(&status)
	require.NoError(t, err, "read ledger row")
	assert.Equal(t, "failed", status, "ledger status must be 'failed' when Apply errors")

	// vault current_version must still be 1.
	var cv int
	err = admin.QueryRow(context.Background(),
		`SELECT current_version FROM vault_secrets WHERE id = $1`, meta.ID).Scan(&cv)
	require.NoError(t, err)
	assert.Equal(t, 1, cv, "vault current_version must remain 1 after failed rotation")

	// Only one version row should exist.
	var vcount int
	err = admin.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM vault_secret_versions WHERE secret_id = $1`, meta.ID).Scan(&vcount)
	require.NoError(t, err)
	assert.Equal(t, 1, vcount, "only the initial version row should exist after failed rotation")
}

// ── TestRotateOnCheckoutSelection ────────────────────────────────────────────

// TestRotateOnCheckoutSelection verifies that a policy with rotate_on_checkout=true
// is returned by DuePolicies when a vault_checkouts row with status='expired' and
// returned_at > policy.last_run_at exists for the policy's secret.
//
// DuePolicies is the thin exported wrapper around the unexported dueUnsafe added
// in internal/credentials/scheduler.go for this test.
func TestRotateOnCheckoutSelection(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()
	skipIfCredsMigrationNotApplied(t, admin)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgID := seedOrg(t, admin, "rot-co-"+suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM credential_rotation_policies WHERE org_id=$1`, orgID)
		bypassExec(t, admin, `DELETE FROM vault_checkouts WHERE org_id=$1`, orgID)
		bypassExec(t, admin, `DELETE FROM vault_secrets WHERE org_id=$1`, orgID)
		bypassExec(t, admin, `DELETE FROM organizations WHERE id=$1`, orgID)
	})

	vaultSvc := newCredsVaultService(t, admin)
	ctx := orgctx.With(orgctx.WithBypassRLS(context.Background()), orgctx.Org{ID: orgID})
	meta, err := vaultSvc.Store(ctx, vault.StoreInput{
		Name:  "rot-co-secret-" + suffix,
		Type:  "generic",
		Value: []byte("checkout-secret"),
	})
	require.NoError(t, err, "Store vault secret")

	// Create policy with rotate_on_checkout=true, interval=0 (interval-only trigger off),
	// and last_run_at set to 1 hour ago so the checkout is "after" it.
	var policyID string
	adminCtx := context.Background()
	tx, err := admin.Begin(adminCtx)
	require.NoError(t, err)
	_, err = tx.Exec(adminCtx, `SELECT set_config('app.bypass_rls','on',true)`)
	require.NoError(t, err)
	err = tx.QueryRow(adminCtx,
		`INSERT INTO credential_rotation_policies
		   (org_id, secret_id, connector_type, connector_config, generation_policy,
		    interval_seconds, rotate_on_checkout, enabled, last_run_at)
		 VALUES ($1,$2,'directory',
		         '{"directory_id":"test-dir","username":"svc-acct"}'::jsonb,
		         '{}'::jsonb, 0, true, true, NOW() - INTERVAL '1 hour')
		 RETURNING id`,
		orgID, meta.ID).Scan(&policyID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(adminCtx))

	// Insert a vault_checkouts row with status='expired' and returned_at = NOW()
	// (after last_run_at which was 1 hour ago). Use bypass so FORCE RLS doesn't
	// block the raw insert.
	bypassExec(t, admin,
		`INSERT INTO vault_checkouts
		   (org_id, secret_id, secret_version, mode, reason, expires_at, status, returned_at)
		 VALUES ($1, $2, 1, 'reveal', 'integration test', NOW() - INTERVAL '5 minutes',
		         'expired', NOW())`,
		orgID, meta.ID)

	// Build a credentials.Service with a fake rotator.
	fake := &fakeDirectoryRotator{}
	credsSvc := newCredsService(t, admin, vaultSvc, fake)

	// DuePolicies runs under bypass so it can scan across orgs (scheduler behaviour).
	bypassCtx := orgctx.WithBypassRLS(context.Background())
	ids, err := credsSvc.DuePolicies(bypassCtx)
	require.NoError(t, err, "DuePolicies")

	// The policy we seeded must appear in the due list with trigger='checkout'.
	found := false
	for _, id := range ids {
		if id == policyID {
			found = true
			break
		}
	}
	assert.True(t, found,
		"policy with rotate_on_checkout=true and an expired checkout must appear in DuePolicies (got %v)", ids)
}

// ── TestRotationRLSIsolation ──────────────────────────────────────────────────

// TestRotationRLSIsolation verifies that a second org cannot see org A's
// credential_rotation_policies or credential_rotations rows via the FORCE RLS belt.
func TestRotationRLSIsolation(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()
	skipIfCredsMigrationNotApplied(t, admin)

	requireForceRLS(t, admin, "credential_rotation_policies")
	requireForceRLS(t, admin, "credential_rotations")

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgA := seedOrg(t, admin, "rot-rls-a-"+suffix)
	orgB := seedOrg(t, admin, "rot-rls-b-"+suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM credential_rotation_policies WHERE org_id IN ($1,$2)`, orgA, orgB)
		bypassExec(t, admin, `DELETE FROM vault_secrets WHERE org_id IN ($1,$2)`, orgA, orgB)
		bypassExec(t, admin, `DELETE FROM organizations WHERE id IN ($1,$2)`, orgA, orgB)
	})

	vaultSvc := newCredsVaultService(t, admin)

	// Seed a vault secret + rotation policy in org A.
	ctxA := orgctx.With(orgctx.WithBypassRLS(context.Background()), orgctx.Org{ID: orgA})
	metaA, err := vaultSvc.Store(ctxA, vault.StoreInput{
		Name:  "rls-secret-a-" + suffix,
		Type:  "generic",
		Value: []byte("org-a-secret"),
	})
	require.NoError(t, err, "Store vault secret for org A")

	policyID := seedCredsPolicy(t, admin, orgA, metaA.ID, false)

	// Run one rotation (succeeds) so we get a credential_rotations ledger row.
	fake := &fakeDirectoryRotator{}
	credsSvc := newCredsService(t, admin, vaultSvc, fake)
	require.NoError(t, credsSvc.RotateSecret(context.Background(), policyID, "on_demand"))

	// Open NOSUPERUSER pool (with cred-table + vault-table grants).
	rolePool := rlsRolePoolForCreds(t, admin)
	defer rolePool.Close()

	ctx := context.Background()
	conn, err := rolePool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()

	setScope := func(orgID, bypass string) {
		_, err := conn.Exec(ctx,
			`SELECT set_config('app.org_id', $1, false), set_config('app.bypass_rls', $2, false)`,
			orgID, bypass)
		require.NoError(t, err)
	}
	countPolicies := func() int {
		var n int
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM credential_rotation_policies WHERE org_id = $1`, orgA).Scan(&n))
		return n
	}
	countRuns := func() int {
		var n int
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM credential_rotations WHERE policy_id = $1`, policyID).Scan(&n))
		return n
	}

	t.Run("org A sees its own policy and ledger rows", func(t *testing.T) {
		setScope(orgA, "off")
		assert.Equal(t, 1, countPolicies(), "org A must see its own credential_rotation_policies row")
		assert.Equal(t, 1, countRuns(), "org A must see its own credential_rotations row")
	})

	t.Run("org B cannot see org A's policy or ledger rows (RLS filtered)", func(t *testing.T) {
		setScope(orgB, "off")
		assert.Equal(t, 0, countPolicies(), "org B must not see org A's credential_rotation_policies row")
		assert.Equal(t, 0, countRuns(), "org B must not see org A's credential_rotations row")
	})

	t.Run("no scope: fail-closed (0 rows)", func(t *testing.T) {
		setScope("", "off")
		assert.Equal(t, 0, countPolicies(), "unset app.org_id must return 0 credential_rotation_policies rows")
		assert.Equal(t, 0, countRuns(), "unset app.org_id must return 0 credential_rotations rows")
	})

	t.Run("bypass=on sees across orgs", func(t *testing.T) {
		setScope("", "on")
		assert.Equal(t, 1, countPolicies(), "app.bypass_rls='on' must reveal org A's policy")
		assert.Equal(t, 1, countRuns(), "app.bypass_rls='on' must reveal org A's ledger row")
	})
}
