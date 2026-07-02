//go:build integration

package integration

// Guacamole session-injection integration tests — Task 9 of
// 2026-07-02-pam-m3-session-injection.md.
//
// Bootstrap model: identical to vault_test.go / rotation_test.go.
//   - integrationDB(t)             — admin (superuser) pool; skips if DATABASE_URL/POSTGRES_PASSWORD unset.
//   - rlsRolePoolForGuac(t, db)    — NOSUPERUSER pool with guac-table grants for real RLS assertions.
//   - bypassExec / seedOrg         — from cross_org_test.go.
//   - requireForceRLS              — from cross_org_test.go.
//
// Since checkAndConsumeApproval and recordGuacSession are unexported in
// internal/access, we replicate their SQL directly. The point is to validate the
// schema, RLS belt, and approval-consume semantics at the DB layer.
//
// Run: go test -tags=integration ./test/integration/ -run TestGuac -v

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rlsRolePoolForGuac extends rlsRolePool's grant set to include the two guac
// session tables so the NOSUPERUSER role can run DML assertions on them.
func rlsRolePoolForGuac(t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	for _, stmt := range []string{
		`GRANT SELECT, INSERT, UPDATE, DELETE ON guacamole_session_requests TO openidx_rls_test`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON guacamole_sessions TO openidx_rls_test`,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Logf("guac grant (may be pre-existing): %v", err)
		}
	}
	return rlsRolePool(t, admin)
}

// seedProxyRoute inserts a minimal proxy_routes row under bypass and returns its UUID.
// guacamole_connections has a FK to proxy_routes(id), so a parent row is required.
func seedProxyRoute(t *testing.T, admin *pgxpool.Pool, orgID, suffix string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := admin.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
	require.NoError(t, err)
	var routeID string
	err = tx.QueryRow(ctx,
		`INSERT INTO proxy_routes (name, from_url, to_url, org_id)
		 VALUES ($1,$2,$3,$4) RETURNING id`,
		"guac-test-route-"+suffix,
		"https://guac-test-"+suffix+".example.test",
		"http://guac-upstream.test",
		orgID).Scan(&routeID)
	require.NoError(t, err, "seed proxy_routes for guac test")
	require.NoError(t, tx.Commit(ctx))
	return routeID
}

// seedGuacConnection inserts a guacamole_connections row under bypass and
// returns its UUID. guacamole_connections is NOT RLS-belted (no org_id column)
// so a raw admin exec is sufficient; we still use bypass for consistency.
func seedGuacConnection(t *testing.T, admin *pgxpool.Pool, routeID string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := admin.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
	require.NoError(t, err)
	var connID string
	err = tx.QueryRow(ctx,
		`INSERT INTO guacamole_connections
		   (route_id, guacamole_connection_id, protocol, hostname, port,
		    require_approval, record_session)
		 VALUES ($1, 'guac-ext-id-'||$1::text, 'rdp', '10.0.0.1', 3389, true, true)
		 RETURNING id`,
		routeID).Scan(&connID)
	require.NoError(t, err, "seed guacamole_connections")
	require.NoError(t, tx.Commit(ctx))
	return connID
}

// seedSessionRequest inserts a guacamole_session_requests row under bypass.
// status defaults to 'pending'; pass overrideStatus='approved' etc. as needed.
// Returns the request UUID.
func seedSessionRequest(t *testing.T, admin *pgxpool.Pool, orgID, connectionID, requesterID, status string, expiresAt *time.Time) string {
	t.Helper()
	ctx := context.Background()
	tx, err := admin.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
	require.NoError(t, err)
	var reqID string
	if expiresAt != nil {
		err = tx.QueryRow(ctx,
			`INSERT INTO guacamole_session_requests
			   (org_id, connection_id, requester_id, reason, status, expires_at)
			 VALUES ($1,$2,$3,'integration test',$4,$5) RETURNING id`,
			orgID, connectionID, requesterID, status, expiresAt).Scan(&reqID)
	} else {
		err = tx.QueryRow(ctx,
			`INSERT INTO guacamole_session_requests
			   (org_id, connection_id, requester_id, reason, status)
			 VALUES ($1,$2,$3,'integration test',$4) RETURNING id`,
			orgID, connectionID, requesterID, status).Scan(&reqID)
	}
	require.NoError(t, err, "seed guacamole_session_requests")
	require.NoError(t, tx.Commit(ctx))
	return reqID
}

// consumeApprovalSQL is the exact SQL from access.checkAndConsumeApproval.
// connectionID=$1, userID=$2.
const consumeApprovalSQL = `
UPDATE guacamole_session_requests SET status = 'consumed'
 WHERE id = (
       SELECT id FROM guacamole_session_requests
        WHERE connection_id = $1
          AND requester_id  = $2
          AND status        = 'approved'
          AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY created_at DESC
        LIMIT 1
 )
 RETURNING id`

// ── TestGuacInjectionMigrationApplies ────────────────────────────────────────

// TestGuacInjectionMigrationApplies asserts that migration v59 has been applied:
//   - guacamole_session_requests and guacamole_sessions exist and have
//     relrowsecurity=true AND relforcerowsecurity=true (FORCE RLS).
//   - guacamole_connections has the four new columns added by v59.
func TestGuacInjectionMigrationApplies(t *testing.T) {
	db := integrationDB(t)
	defer db.Close()
	ctx := context.Background()

	// 1. Force-RLS check for the two new belted tables.
	for _, tbl := range []string{"guacamole_session_requests", "guacamole_sessions"} {
		tbl := tbl
		t.Run(tbl+"_force_rls", func(t *testing.T) {
			var rls, forced bool
			err := db.QueryRow(ctx,
				`SELECT relrowsecurity, relforcerowsecurity
				 FROM pg_class
				 WHERE relname = $1 AND relkind = 'r'`, tbl).Scan(&rls, &forced)
			if err != nil {
				t.Fatalf("table %s not found in pg_class (migration v59 not applied?): %v", tbl, err)
			}
			assert.True(t, rls, "table %s must have relrowsecurity=true", tbl)
			assert.True(t, forced, "table %s must have relforcerowsecurity=true (FORCE ROW LEVEL SECURITY)", tbl)
		})
	}

	// 2. guacamole_connections must have the four v59 columns.
	for _, col := range []string{"vault_secret_id", "inject_username", "require_approval", "record_session"} {
		col := col
		t.Run("guacamole_connections_col_"+col, func(t *testing.T) {
			var count int
			err := db.QueryRow(ctx,
				`SELECT COUNT(*) FROM information_schema.columns
				 WHERE table_name = 'guacamole_connections'
				   AND column_name = $1
				   AND table_schema = 'public'`, col).Scan(&count)
			require.NoError(t, err)
			assert.Equal(t, 1, count, "guacamole_connections must have column %s (migration v59 not applied?)", col)
		})
	}
}

// ── TestGuacApprovalConsume ──────────────────────────────────────────────────

// TestGuacApprovalConsume validates the approval-consume SQL used by
// access.checkAndConsumeApproval at the DB layer:
//  1. An 'approved' unexpired request is consumed on first run (RETURNING id).
//  2. A second run returns no rows (single-use).
//  3. An expired 'approved' request is NOT consumed.
func TestGuacApprovalConsume(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()

	// Skip if migration v59 is not applied.
	requireForceRLS(t, admin, "guacamole_session_requests")

	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	orgID := seedOrg(t, admin, "gapprove-"+suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	routeID := seedProxyRoute(t, admin, orgID, suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM proxy_routes WHERE id = $1`, routeID)
	})

	connID := seedGuacConnection(t, admin, routeID)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM guacamole_connections WHERE id = $1`, connID)
	})

	// A synthetic user UUID — no FK on requester_id.
	userID := "00000000-0000-0000-0001-" + fmt.Sprintf("%012d", time.Now().UnixNano()%1000000000000)

	// checkAndConsumeApproval runs under the org's app.org_id GUC. Because the
	// admin pool is a superuser (bypasses FORCE RLS inherently) we set the GUC
	// manually on a single acquired connection to simulate the production path.
	conn, err := admin.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()

	// Scope the acquired connection to our org (bypass_rls stays off; the
	// superuser ignores RLS anyway, but setting org_id mirrors production intent).
	_, err = conn.Exec(ctx, `SELECT set_config('app.org_id',$1,false), set_config('app.bypass_rls','on',false)`, orgID)
	require.NoError(t, err)

	t.Run("approved request is consumed on first call", func(t *testing.T) {
		reqID := seedSessionRequest(t, admin, orgID, connID, userID, "approved", nil)
		t.Cleanup(func() {
			bypassExec(t, admin, `DELETE FROM guacamole_session_requests WHERE id = $1`, reqID)
		})

		var returnedID string
		err := conn.QueryRow(ctx, consumeApprovalSQL, connID, userID).Scan(&returnedID)
		require.NoError(t, err, "consume UPDATE must return a row for an approved request")
		assert.Equal(t, reqID, returnedID, "returned id must match the seeded request")

		// Verify status flipped to 'consumed' in the DB.
		var status string
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT status FROM guacamole_session_requests WHERE id = $1`, reqID).Scan(&status))
		assert.Equal(t, "consumed", status, "status must be 'consumed' after first call")
	})

	t.Run("second call returns no rows (single-use)", func(t *testing.T) {
		reqID := seedSessionRequest(t, admin, orgID, connID, userID, "approved", nil)
		t.Cleanup(func() {
			bypassExec(t, admin, `DELETE FROM guacamole_session_requests WHERE id = $1`, reqID)
		})

		// First consume — must succeed.
		var firstID string
		err := conn.QueryRow(ctx, consumeApprovalSQL, connID, userID).Scan(&firstID)
		require.NoError(t, err, "first consume must succeed")

		// Second consume — must return no rows.
		var secondID string
		err = conn.QueryRow(ctx, consumeApprovalSQL, connID, userID).Scan(&secondID)
		require.Error(t, err, "second consume must return pgx.ErrNoRows")
		assert.Empty(t, secondID)
	})

	t.Run("expired approved request is NOT consumed", func(t *testing.T) {
		expiredAt := time.Now().Add(-1 * time.Hour) // 1 hour in the past
		reqID := seedSessionRequest(t, admin, orgID, connID, userID, "approved", &expiredAt)
		t.Cleanup(func() {
			bypassExec(t, admin, `DELETE FROM guacamole_session_requests WHERE id = $1`, reqID)
		})

		var returnedID string
		err := conn.QueryRow(ctx, consumeApprovalSQL, connID, userID).Scan(&returnedID)
		require.Error(t, err, "expired approved request must NOT be consumed (ErrNoRows expected)")
		assert.Empty(t, returnedID)

		// Row must still be 'approved' (untouched).
		var status string
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT status FROM guacamole_session_requests WHERE id = $1`, reqID).Scan(&status))
		assert.Equal(t, "approved", status, "expired row must remain 'approved', not consumed")
	})
}

// ── TestGuacSessionRecordAndRetention ────────────────────────────────────────

// TestGuacSessionRecordAndRetention validates the recordGuacSession INSERT
// (from access.recordGuacSession) and the retention-sweep UPDATE at the DB
// layer:
//  1. A guacamole_sessions row is inserted and returned.
//  2. A retention-sweep UPDATE marks old ended rows as purged.
//  3. A recently-ended row is NOT marked purged by the same sweep.
func TestGuacSessionRecordAndRetention(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()

	requireForceRLS(t, admin, "guacamole_sessions")

	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	orgID := seedOrg(t, admin, "gsess-"+suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	routeID := seedProxyRoute(t, admin, orgID, suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM proxy_routes WHERE id = $1`, routeID)
	})

	connID := seedGuacConnection(t, admin, routeID)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM guacamole_connections WHERE id = $1`, connID)
	})

	userID := "00000000-0000-0000-0002-" + fmt.Sprintf("%012d", time.Now().UnixNano()%1000000000000)
	recPath := "/var/recordings/guac-test-" + suffix + ".mp4"

	// Use the exact SQL from access.recordGuacSession.
	var sessionID string
	err := func() error {
		tx, err := admin.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`); err != nil {
			return err
		}
		err = tx.QueryRow(ctx,
			`INSERT INTO guacamole_sessions (org_id, connection_id, user_id, recording_path, status)
			 VALUES ($1,$2,NULLIF($3,'')::uuid,$4,'active') RETURNING id`,
			orgID, connID, userID, recPath).Scan(&sessionID)
		if err != nil {
			return err
		}
		return tx.Commit(ctx)
	}()
	require.NoError(t, err, "recordGuacSession INSERT must succeed")
	require.NotEmpty(t, sessionID, "INSERT must return a UUID")

	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM guacamole_sessions WHERE id = $1`, sessionID)
	})

	// Mark the session as ended in the far past to simulate a stale recording.
	bypassExec(t, admin,
		`UPDATE guacamole_sessions SET status='ended', ended_at=NOW()-INTERVAL '100 days' WHERE id=$1`,
		sessionID)

	// Insert a recent session (ended just now) that must NOT be swept.
	var recentID string
	func() {
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
		require.NoError(t, err)
		err = tx.QueryRow(ctx,
			`INSERT INTO guacamole_sessions (org_id, connection_id, user_id, recording_path, status, ended_at)
			 VALUES ($1,$2,NULLIF($3,'')::uuid,$4,'ended',NOW()) RETURNING id`,
			orgID, connID, userID, recPath+"-recent").Scan(&recentID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	}()
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM guacamole_sessions WHERE id = $1`, recentID)
	})

	t.Run("retention sweep marks old recording purged", func(t *testing.T) {
		// Sweep: mark recording_purged_at on sessions ended > 90 days ago.
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
		require.NoError(t, err)
		tag, err := tx.Exec(ctx,
			`UPDATE guacamole_sessions
			    SET recording_purged_at = NOW()
			  WHERE status = 'ended'
			    AND ended_at < NOW() - INTERVAL '90 days'
			    AND recording_purged_at IS NULL
			    AND id = $1`,
			sessionID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		assert.Equal(t, int64(1), tag.RowsAffected(), "stale recording must be swept")

		var purgedAt *time.Time
		require.NoError(t, admin.QueryRow(ctx,
			`SELECT recording_purged_at FROM guacamole_sessions WHERE id = $1`, sessionID).
			Scan(&purgedAt))
		require.NotNil(t, purgedAt, "recording_purged_at must be set after sweep")
	})

	t.Run("recent recording is NOT swept", func(t *testing.T) {
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
		require.NoError(t, err)
		tag, err := tx.Exec(ctx,
			`UPDATE guacamole_sessions
			    SET recording_purged_at = NOW()
			  WHERE status = 'ended'
			    AND ended_at < NOW() - INTERVAL '90 days'
			    AND recording_purged_at IS NULL
			    AND id = $1`,
			recentID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		assert.Equal(t, int64(0), tag.RowsAffected(), "recently-ended recording must NOT be swept")

		var purgedAt *time.Time
		require.NoError(t, admin.QueryRow(ctx,
			`SELECT recording_purged_at FROM guacamole_sessions WHERE id = $1`, recentID).
			Scan(&purgedAt))
		assert.Nil(t, purgedAt, "recording_purged_at must remain NULL for a recent session")
	})
}

// ── TestGuacRLSIsolation ─────────────────────────────────────────────────────

// TestGuacRLSIsolation verifies the FORCE RLS belt on the two new tables:
//   - A guacamole_session_requests row seeded in org A is invisible under
//     org B's app.org_id GUC on a NOSUPERUSER connection.
//   - A guacamole_sessions row seeded in org A is invisible under org B.
//   - Both rows are visible under app.bypass_rls='on'.
//   - Both rows are visible when the connection is scoped to org A.
//
// Mirrors TestVaultRLSIsolation and TestRLSBelt exactly.
func TestGuacRLSIsolation(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()

	requireForceRLS(t, admin, "guacamole_session_requests")
	requireForceRLS(t, admin, "guacamole_sessions")

	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	orgA := seedOrg(t, admin, "grls-a-"+suffix)
	orgB := seedOrg(t, admin, "grls-b-"+suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM organizations WHERE id IN ($1,$2)`, orgA, orgB)
	})

	routeID := seedProxyRoute(t, admin, orgA, "grls-"+suffix)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM proxy_routes WHERE id = $1`, routeID)
	})

	connID := seedGuacConnection(t, admin, routeID)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM guacamole_connections WHERE id = $1`, connID)
	})

	userID := "00000000-0000-0000-0003-" + fmt.Sprintf("%012d", time.Now().UnixNano()%1000000000000)

	// Seed one guacamole_session_requests row in org A.
	reqID := seedSessionRequest(t, admin, orgA, connID, userID, "pending", nil)
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM guacamole_session_requests WHERE id = $1`, reqID)
	})

	// Seed one guacamole_sessions row in org A.
	var sessID string
	func() {
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls','on',true)`)
		require.NoError(t, err)
		err = tx.QueryRow(ctx,
			`INSERT INTO guacamole_sessions (org_id, connection_id, recording_path, status)
			 VALUES ($1,$2,'/recordings/grls-test.mp4','active') RETURNING id`,
			orgA, connID).Scan(&sessID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	}()
	t.Cleanup(func() {
		bypassExec(t, admin, `DELETE FROM guacamole_sessions WHERE id = $1`, sessID)
	})

	// Open NOSUPERUSER role pool (with guac-table grants).
	rolePool := rlsRolePoolForGuac(t, admin)
	defer rolePool.Close()

	conn, err := rolePool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()

	setScope := func(orgID, bypass string) {
		_, err := conn.Exec(ctx,
			`SELECT set_config('app.org_id',$1,false), set_config('app.bypass_rls',$2,false)`,
			orgID, bypass)
		require.NoError(t, err)
	}
	countReq := func() int {
		var n int
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM guacamole_session_requests WHERE id = $1`, reqID).Scan(&n))
		return n
	}
	countSess := func() int {
		var n int
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM guacamole_sessions WHERE id = $1`, sessID).Scan(&n))
		return n
	}

	t.Run("scoped to org A: sees its own rows", func(t *testing.T) {
		setScope(orgA, "off")
		assert.Equal(t, 1, countReq(), "org A must see its own guacamole_session_requests row")
		assert.Equal(t, 1, countSess(), "org A must see its own guacamole_sessions row")
	})

	t.Run("scoped to org B: cannot see org A's rows (0 rows)", func(t *testing.T) {
		setScope(orgB, "off")
		assert.Equal(t, 0, countReq(), "org B must not see org A's guacamole_session_requests row (RLS filtered)")
		assert.Equal(t, 0, countSess(), "org B must not see org A's guacamole_sessions row (RLS filtered)")
	})

	t.Run("no scope set: fail-closed (0 rows)", func(t *testing.T) {
		setScope("", "off")
		assert.Equal(t, 0, countReq(), "unset app.org_id must be fail-closed on guacamole_session_requests")
		assert.Equal(t, 0, countSess(), "unset app.org_id must be fail-closed on guacamole_sessions")
	})

	t.Run("bypass=on: sees across orgs", func(t *testing.T) {
		setScope("", "on")
		assert.Equal(t, 1, countReq(), "app.bypass_rls='on' must reveal org A's session request from any scope")
		assert.Equal(t, 1, countSess(), "app.bypass_rls='on' must reveal org A's session from any scope")
	})
}
