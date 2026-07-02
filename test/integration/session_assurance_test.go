//go:build integration

package integration

// Session-assurance integration tests — Task 7 of
// 2026-07-02-pam-m4-session-assurance.md.
//
// Bootstrap model: identical to guacamole_injection_test.go / vault_test.go /
// rotation_test.go.
//   - integrationDB(t)              — admin (superuser) pool; skips if DATABASE_URL/POSTGRES_PASSWORD unset.
//   - rlsRolePoolForGuac(t, db)     — NOSUPERUSER pool with guac-table grants.
//   - rlsRolePoolForVault(t, db)    — NOSUPERUSER pool with vault-table grants.
//   - bypassExec / seedOrg          — from cross_org_test.go.
//   - seedProxyRoute / seedGuacConnection — from guacamole_injection_test.go.
//   - newVaultService / seedVaultSecret   — from vault_test.go.
//
// Since the M4 logic lives in unexported methods across internal/access and
// internal/admin, we test at the DB layer by replicating the exact SQL the
// code runs. The point is to validate the v60 schema, the session-end detection
// UPDATE, and the vault_access / rotation_policy attestation enumerate+revoke
// SQL semantics.
//
// Run: go test -tags=integration ./test/integration/ \
//
//	-run 'TestSessionAssurance|TestGuacSessionEnd|TestVaultAccessAttestation|TestRotationPolicyAttestation' -v

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── TestSessionAssuranceMigrationApplies ─────────────────────────────────────

// TestSessionAssuranceMigrationApplies asserts that migration v60 has been
// applied: guacamole_sessions now carries the two new columns added by v60:
// transcript_path and transcript_generated_at.
func TestSessionAssuranceMigrationApplies(t *testing.T) {
	db := integrationDB(t)
	defer db.Close()
	ctx := context.Background()

	for _, col := range []string{"transcript_path", "transcript_generated_at"} {
		col := col
		t.Run("guacamole_sessions_col_"+col, func(t *testing.T) {
			var count int
			err := db.QueryRow(ctx,
				`SELECT COUNT(*) FROM information_schema.columns
				 WHERE table_schema = 'public'
				   AND table_name   = 'guacamole_sessions'
				   AND column_name  = $1`, col).Scan(&count)
			require.NoError(t, err)
			assert.Equal(t, 1, count,
				"guacamole_sessions must have column %s (migration v60 not applied?)", col)
		})
	}
}

// ── TestGuacSessionEndDetection ──────────────────────────────────────────────

// TestGuacSessionEndDetection validates the session-end detection UPDATE used
// by access.RemoteSupportHandler.detectEndedGuacSessions at the DB layer:
//
//  1. A "stale" active session (started 10 minutes ago, not in the live set)
//     is updated to status='ended' with ended_at set.
//  2. A "fresh" active session (started just now) is excluded from the detection
//     SELECT by the 2-minute grace predicate.
func TestGuacSessionEndDetection(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()

	// Skip if guacamole_sessions table is missing or v59 not applied.
	requireForceRLS(t, admin, "guacamole_sessions")

	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	orgID := seedOrg(t, admin, "gsend-"+suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	routeID := seedProxyRoute(t, admin, orgID, "gsend-"+suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM proxy_routes WHERE id = $1`, routeID)
	})

	connID := seedGuacConnection(t, admin, routeID)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM guacamole_connections WHERE id = $1`, connID)
	})

	// Insert the stale session: status='active', started 10 minutes ago.
	// The detection sweep selects rows where started_at < NOW() - INTERVAL '2 minutes'.
	var staleID string
	func() {
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
		require.NoError(t, err)
		err = tx.QueryRow(ctx,
			`INSERT INTO guacamole_sessions (org_id, connection_id, recording_path, status, started_at)
			 VALUES ($1, $2, '/recordings/stale-gsend.mp4', 'active', NOW()-INTERVAL '10 minutes')
			 RETURNING id`,
			orgID, connID).Scan(&staleID)
		require.NoError(t, err, "insert stale guacamole_sessions row")
		require.NoError(t, tx.Commit(ctx))
	}()
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM guacamole_sessions WHERE id = $1`, staleID)
	})

	// Insert the fresh session: status='active', started just now.
	var freshID string
	func() {
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
		require.NoError(t, err)
		err = tx.QueryRow(ctx,
			`INSERT INTO guacamole_sessions (org_id, connection_id, recording_path, status)
			 VALUES ($1, $2, '/recordings/fresh-gsend.mp4', 'active')
			 RETURNING id`,
			orgID, connID).Scan(&freshID)
		require.NoError(t, err, "insert fresh guacamole_sessions row")
		require.NoError(t, tx.Commit(ctx))
	}()
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM guacamole_sessions WHERE id = $1`, freshID)
	})

	t.Run("stale session (>2m, not in live set) is marked ended", func(t *testing.T) {
		// Replicate the detection UPDATE from detectEndedGuacSessions.
		// In production the id comes from a SELECT that joined live connections.
		// Here we simulate "staleID is NOT in the live set" by running the UPDATE
		// directly for staleID.
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
		require.NoError(t, err)
		tag, err := tx.Exec(ctx,
			`UPDATE guacamole_sessions
			    SET status = 'ended', ended_at = NOW()
			  WHERE id = $1 AND status = 'active'`,
			staleID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		assert.Equal(t, int64(1), tag.RowsAffected(), "detection UPDATE must affect 1 row for stale session")

		// Verify the row state.
		var status string
		var endedAt *time.Time
		require.NoError(t, admin.QueryRow(ctx,
			`SELECT status, ended_at FROM guacamole_sessions WHERE id = $1`, staleID).
			Scan(&status, &endedAt))
		assert.Equal(t, "ended", status, "stale session status must be 'ended' after detection")
		require.NotNil(t, endedAt, "ended_at must be set after detection UPDATE")
	})

	t.Run("fresh session (<2m grace) is excluded from detection SELECT", func(t *testing.T) {
		// The detection SELECT uses: started_at < NOW() - INTERVAL '2 minutes'.
		// A session started just now must NOT appear in this result set.
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
		require.NoError(t, err)

		var count int
		err = tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM guacamole_sessions
			  WHERE id = $1
			    AND status = 'active'
			    AND started_at < NOW() - INTERVAL '2 minutes'`,
			freshID).Scan(&count)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		assert.Equal(t, 0, count,
			"fresh session must NOT match the grace-filtered detection SELECT (started_at < NOW()-2m)")
	})

	t.Run("detection UPDATE is idempotent on already-ended session", func(t *testing.T) {
		// Running the UPDATE a second time on the now-ended row must affect 0 rows
		// (status='ended' ≠ 'active').
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
		require.NoError(t, err)
		tag, err := tx.Exec(ctx,
			`UPDATE guacamole_sessions
			    SET status = 'ended', ended_at = NOW()
			  WHERE id = $1 AND status = 'active'`,
			staleID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		assert.Equal(t, int64(0), tag.RowsAffected(),
			"second detection UPDATE on an already-ended session must be a no-op")
	})
}

// ── TestVaultAccessAttestation ───────────────────────────────────────────────

// TestVaultAccessAttestation validates the vault_access attestation campaign
// enumerate+revoke SQL from internal/admin/attestation.go at the DB layer:
//
//  1. Seed org + vault secret + a vault_access_grants row.
//  2. Run the enumerate SELECT → asserts the grant appears in the result set.
//  3. Run the revoke DELETE → asserts the grant is gone.
//  4. Assert cross-org invisibility via NOSUPERUSER role pool (RLS isolation).
func TestVaultAccessAttestation(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()

	// Skip if vault tables not present.
	var vaultExists bool
	err := admin.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname='vault_access_grants' AND relkind='r')`).
		Scan(&vaultExists)
	require.NoError(t, err)
	if !vaultExists {
		t.Skip("vault_access_grants table not found — migration v56 not applied in this DB")
	}

	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	orgID := seedOrg(t, admin, "vattest-"+suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	// Seed a vault secret via the vault.Service (same pattern as vault_test.go).
	vaultSvc := newVaultService(t, admin)
	vaultCtx := orgctx.With(orgctx.WithBypassRLS(context.Background()), orgctx.Org{ID: orgID})
	meta, err := vaultSvc.Store(vaultCtx, vault.StoreInput{
		Name:  "attest-secret-" + suffix,
		Type:  "generic",
		Value: []byte("attest-val"),
	})
	require.NoError(t, err, "Store vault secret for attestation test")
	t.Cleanup(func() { cleanupVaultSecret(t, admin, meta.ID) })

	// Seed a vault_access_grants row directly under bypass.
	principalID := "00000000-0000-0000-0099-" + fmt.Sprintf("%012d", time.Now().UnixNano()%1000000000000)
	var grantID string
	func() {
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
		require.NoError(t, err)
		err = tx.QueryRow(ctx,
			`INSERT INTO vault_access_grants
			   (org_id, secret_id, principal_type, principal_id, actions)
			 VALUES ($1, $2, 'user', $3::uuid, ARRAY['reveal'])
			 RETURNING id`,
			orgID, meta.ID, principalID).Scan(&grantID)
		require.NoError(t, err, "seed vault_access_grants row")
		require.NoError(t, tx.Commit(ctx))
	}()
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM vault_access_grants WHERE id = $1`, grantID)
	})

	t.Run("enumerate SELECT returns the grant", func(t *testing.T) {
		// Replicate the vault_access enumerate query from attestation.go Task 5.
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
		require.NoError(t, err)

		var gotGrantID, gotSecretName, gotPrincipalID, gotActions string
		err = tx.QueryRow(ctx,
			`SELECT vag.id, s.name, vag.principal_id::text, array_to_string(vag.actions, ',')
			 FROM vault_access_grants vag
			 JOIN vault_secrets s ON s.id = vag.secret_id
			 WHERE vag.org_id = $1
			   AND (vag.expires_at IS NULL OR vag.expires_at > NOW())
			   AND vag.id = $2`,
			orgID, grantID).Scan(&gotGrantID, &gotSecretName, &gotPrincipalID, &gotActions)
		require.NoError(t, err, "enumerate SELECT must find the seeded vault_access_grants row")
		require.NoError(t, tx.Commit(ctx))

		assert.Equal(t, grantID, gotGrantID, "enumerate SELECT must return the correct grant id")
		assert.Equal(t, "attest-secret-"+suffix, gotSecretName, "enumerate SELECT must return the secret name")
		assert.Equal(t, principalID, gotPrincipalID, "enumerate SELECT must return the principal_id")
		assert.Equal(t, "reveal", gotActions, "enumerate SELECT must return actions='reveal'")
	})

	t.Run("revoke DELETE removes the grant", func(t *testing.T) {
		// Replicate the vault_access revoke DELETE from attestation.go Task 5.
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
		require.NoError(t, err)
		tag, err := tx.Exec(ctx,
			`DELETE FROM vault_access_grants WHERE id = $1 AND org_id = $2`,
			grantID, orgID)
		require.NoError(t, err, "revoke DELETE must not error")
		require.NoError(t, tx.Commit(ctx))
		assert.Equal(t, int64(1), tag.RowsAffected(), "revoke DELETE must affect exactly 1 row")

		// Confirm the row is gone.
		var count int
		require.NoError(t, admin.QueryRow(ctx,
			`SELECT COUNT(*) FROM vault_access_grants WHERE id = $1`, grantID).Scan(&count))
		assert.Equal(t, 0, count, "vault_access_grants row must be absent after revoke DELETE")
	})

	t.Run("RLS: cross-org vault_access_grants invisibility", func(t *testing.T) {
		// Re-seed the grant (the revoke sub-test deleted it).
		var regrantID string
		func() {
			tx, err := admin.Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)
			_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
			require.NoError(t, err)
			err = tx.QueryRow(ctx,
				`INSERT INTO vault_access_grants
				   (org_id, secret_id, principal_type, principal_id, actions)
				 VALUES ($1, $2, 'user', $3::uuid, ARRAY['reveal'])
				 RETURNING id`,
				orgID, meta.ID, principalID).Scan(&regrantID)
			require.NoError(t, err, "re-seed vault_access_grants for RLS sub-test")
			require.NoError(t, tx.Commit(ctx))
		}()
		t.Cleanup(func() {
			bypassExec(t, admin, `DELETE FROM vault_access_grants WHERE id = $1`, regrantID)
		})

		orgB := seedOrg(t, admin, "vattest-b-"+suffix)
		t.Cleanup(func() {
			bypassExec(t, admin, `DELETE FROM organizations WHERE id = $1`, orgB)
		})

		rolePool := rlsRolePoolForVault(t, admin)
		defer rolePool.Close()

		conn, err := rolePool.Acquire(ctx)
		require.NoError(t, err)
		defer conn.Release()

		setScope := func(org, bypass string) {
			_, err := conn.Exec(ctx,
				`SELECT set_config('app.org_id', $1, false), set_config('app.bypass_rls', $2, false)`,
				org, bypass)
			require.NoError(t, err)
		}
		countGrant := func() int {
			var n int
			require.NoError(t, conn.QueryRow(ctx,
				`SELECT COUNT(*) FROM vault_access_grants WHERE id = $1`, regrantID).Scan(&n))
			return n
		}

		// Org A must see its own grant.
		setScope(orgID, "off")
		assert.Equal(t, 1, countGrant(), "org A must see its own vault_access_grants row")

		// Org B must NOT see org A's grant (RLS belt).
		setScope(orgB, "off")
		assert.Equal(t, 0, countGrant(), "org B must not see org A's vault_access_grants row (RLS filtered)")

		// Bypass reveals it.
		setScope("", "on")
		assert.Equal(t, 1, countGrant(), "app.bypass_rls='on' must reveal org A's grant row")
	})
}

// ── TestRotationPolicyAttestation ────────────────────────────────────────────

// TestRotationPolicyAttestation validates the rotation_policy attestation
// campaign enumerate+revoke SQL from internal/admin/attestation.go Task 5 at
// the DB layer:
//
//  1. Seed org + vault secret + credential_rotation_policies row (enabled=true).
//  2. Run the enumerate SELECT → asserts the policy appears.
//  3. Run the revoke UPDATE (enabled=false) → asserts enabled=false.
func TestRotationPolicyAttestation(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()

	// Skip if creds migration not applied.
	skipIfCredsMigrationNotApplied(t, admin)

	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	orgID := seedOrg(t, admin, "rptest-"+suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	// Seed a vault secret.
	vaultSvc := newVaultService(t, admin)
	vaultCtx := orgctx.With(orgctx.WithBypassRLS(context.Background()), orgctx.Org{ID: orgID})
	meta, err := vaultSvc.Store(vaultCtx, vault.StoreInput{
		Name:  "rp-secret-" + suffix,
		Type:  "generic",
		Value: []byte("rp-val"),
	})
	require.NoError(t, err, "Store vault secret for rotation-policy attestation test")
	t.Cleanup(func() { cleanupVaultSecret(t, admin, meta.ID) })

	// Seed a credential_rotation_policies row (enabled=true) via seedCredsPolicy
	// (reused from rotation_test.go via the same package).
	policyID := seedCredsPolicy(t, admin, orgID, meta.ID, false)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM credential_rotation_policies WHERE id = $1`, policyID)
	})

	t.Run("enumerate SELECT returns the enabled policy", func(t *testing.T) {
		// Replicate the rotation_policy enumerate query from attestation.go Task 5.
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
		require.NoError(t, err)

		var gotPolicyID, gotSecretName, gotConnectorType string
		err = tx.QueryRow(ctx,
			`SELECT p.id, s.name, p.connector_type
			 FROM credential_rotation_policies p
			 JOIN vault_secrets s ON s.id = p.secret_id
			 WHERE p.org_id = $1
			   AND p.enabled = true
			   AND p.id = $2`,
			orgID, policyID).Scan(&gotPolicyID, &gotSecretName, &gotConnectorType)
		require.NoError(t, err, "enumerate SELECT must find the seeded rotation policy row")
		require.NoError(t, tx.Commit(ctx))

		assert.Equal(t, policyID, gotPolicyID, "enumerate SELECT must return the correct policy id")
		assert.Equal(t, "rp-secret-"+suffix, gotSecretName, "enumerate SELECT must return the secret name")
		assert.Equal(t, "directory", gotConnectorType, "enumerate SELECT must return the connector_type")
	})

	t.Run("revoke UPDATE sets enabled=false", func(t *testing.T) {
		// Replicate the rotation_policy revoke UPDATE from attestation.go Task 5.
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
		require.NoError(t, err)
		tag, err := tx.Exec(ctx,
			`UPDATE credential_rotation_policies
			    SET enabled = false, updated_at = NOW()
			  WHERE id = $1 AND org_id = $2`,
			policyID, orgID)
		require.NoError(t, err, "revoke UPDATE must not error")
		require.NoError(t, tx.Commit(ctx))
		assert.Equal(t, int64(1), tag.RowsAffected(), "revoke UPDATE must affect exactly 1 row")

		// Confirm enabled flipped to false.
		var enabled bool
		require.NoError(t, admin.QueryRow(ctx,
			`SELECT enabled FROM credential_rotation_policies WHERE id = $1`, policyID).Scan(&enabled))
		assert.False(t, enabled, "credential_rotation_policies.enabled must be false after revoke UPDATE")
	})

	t.Run("enumerate SELECT does not return disabled policy", func(t *testing.T) {
		// After the revoke, the policy must NOT appear in an enumerate that filters
		// enabled=true (confirming the revoke is semantically correct).
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
		require.NoError(t, err)

		var count int
		err = tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM credential_rotation_policies
			  WHERE org_id = $1 AND enabled = true AND id = $2`,
			orgID, policyID).Scan(&count)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		assert.Equal(t, 0, count,
			"disabled policy must not appear in an enabled=true enumerate SELECT")
	})
}
