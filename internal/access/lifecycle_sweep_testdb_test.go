package access

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// THE LIFECYCLE SWEEP RUNS IN EVERY REPLICA, and its own comment says that is
// fine: "Idempotent: every statement only touches still-active rows, so repeat
// ticks (or replicas racing) are harmless."
//
// That is a claim about SQL under concurrency, which is exactly the kind this
// programme keeps finding to be true of one process and false of several. The
// sweeps census records it as safe-by-idempotence rather than leader-gated or
// claim-based, and an entry in that register is only worth its line if someone
// checked. This checks it: the sweep runs twice, and the second pass must
// change nothing.
//
// TWO PROPERTIES, MEASURED SEPARATELY, because they are not the same claim:
//
//   - repetition converges: running the finished sweep again changes nothing,
//     which is what makes a missed tick or a restart free;
//   - CONCURRENT replicas converge to the same place, which is the claim the
//     register actually rests on and which sequential repetition does NOT
//     establish. The dangerous interleaving is several replicas reading the
//     same rows before any of them writes, and only running them at once
//     produces it.
//
// The second is the one that matters. Where it holds it holds for a reason
// worth naming: the sweep's writes are `UPDATE ... WHERE <still active>`, and
// under READ COMMITTED a second updater blocks on the row lock and then
// re-evaluates its predicate against the committed row -- so it matches
// nothing rather than applying twice. The database is doing the coordinating,
// which is why no leader or claim is needed here.

func openLifecyclePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the lifecycle sweep idempotence test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// seedLifecycle builds the columns the sweep actually reads, and nothing else.
// The real tables carry far more; a sweep test that needed the whole schema
// would be a migration test wearing a different name.
func seedLifecycle(t *testing.T, pool *pgxpool.Pool) (*Service, string) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS vault_checkouts, vault_access_grants, guacamole_sessions,
			access_requests, user_roles, group_memberships, user_application_assignments, users;
		CREATE TABLE users (id uuid primary key, enabled boolean NOT NULL DEFAULT true);
		CREATE TABLE vault_checkouts (
			id uuid primary key, principal_id uuid, status text NOT NULL, returned_at timestamptz);
		CREATE TABLE vault_access_grants (
			id uuid primary key, principal_type text NOT NULL, principal_id uuid, expires_at timestamptz);
		CREATE TABLE guacamole_sessions (
			id uuid primary key, user_id uuid, status text NOT NULL,
			guac_session_uuid text, ended_at timestamptz);
		CREATE TABLE access_requests (
			id uuid primary key, requester_id uuid, resource_type text, resource_id uuid,
			org_id uuid, status text NOT NULL, expires_at timestamptz, updated_at timestamptz);
		CREATE TABLE user_roles (user_id uuid, role_id uuid, org_id uuid);
		CREATE TABLE group_memberships (user_id uuid, group_id uuid, org_id uuid);
		CREATE TABLE user_application_assignments (user_id uuid, application_id uuid, org_id uuid);`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS vault_checkouts,
			vault_access_grants, guacamole_sessions, access_requests, user_roles,
			group_memberships, user_application_assignments, users;`)
	})

	org := uuid.NewString()
	disabled, stillEnabled := uuid.NewString(), uuid.NewString()
	roleID := uuid.NewString()
	// One statement per Exec: pgx prepares parameterised statements, and a
	// prepared statement carries exactly one command.
	twoUsers := []any{disabled, stillEnabled}
	fourArgs := []any{disabled, stillEnabled, roleID, org}
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users (id, enabled) VALUES ($1, false), ($2, true)`, twoUsers},
		{`INSERT INTO vault_checkouts (id, principal_id, status)
			VALUES (gen_random_uuid(), $1, 'active'), (gen_random_uuid(), $2, 'active')`, twoUsers},
		{`INSERT INTO vault_access_grants (id, principal_type, principal_id, expires_at)
			VALUES (gen_random_uuid(), 'user', $1, NULL), (gen_random_uuid(), 'user', $2, NULL)`, twoUsers},
		{`INSERT INTO guacamole_sessions (id, user_id, status, guac_session_uuid)
			VALUES (gen_random_uuid(), $1, 'active', ''), (gen_random_uuid(), $2, 'active', '')`, twoUsers},
		{`INSERT INTO access_requests (id, requester_id, resource_type, resource_id, org_id, status, expires_at)
			VALUES (gen_random_uuid(), $1, 'role', $3, $4, 'fulfilled', NOW() + interval '1 day'),
			       (gen_random_uuid(), $2, 'role', $3, $4, 'fulfilled', NOW() + interval '1 day')`, fourArgs},
		{`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1, $3, $4), ($2, $3, $4)`, fourArgs},
	} {
		_, err = pool.Exec(ctx, seed.sql, seed.args...)
		require.NoError(t, err, seed.sql)
	}

	// guacamoleClient stays nil: the sweep handles that path explicitly, and a
	// live broker is not what this test is about.
	return &Service{db: &database.PostgresDB{Pool: database.NewScopedPool(pool)}, logger: zap.NewNop()}, disabled
}

// lifecycleState is everything the sweep can change, read back so a
// before/after comparison is a single value rather than a list of assertions
// that can quietly stop covering a column.
//
// The timestamp DIGESTS are not decoration. A first draft counted rows only --
// "how many checkouts carry a returned_at" -- and a mutation that dropped the
// `status = 'active'` predicate passed it: the sweep rewrote returned_at with a
// fresh NOW() on every pass and the count never moved. The predicate is exactly
// what makes the statement idempotent, so the test has to look at the VALUES it
// would rewrite, not at how many rows have one.
func lifecycleState(t *testing.T, pool *pgxpool.Pool) map[string]string {
	t.Helper()
	ctx := context.Background()
	out := map[string]string{}
	for name, q := range map[string]string{
		"active_checkouts": `SELECT count(*)::text FROM vault_checkouts WHERE status = 'active'`,
		"live_grants":      `SELECT count(*)::text FROM vault_access_grants WHERE expires_at IS NULL OR expires_at > NOW()`,
		"fulfilled_reqs":   `SELECT count(*)::text FROM access_requests WHERE status = 'fulfilled'`,
		"role_assignments": `SELECT count(*)::text FROM user_roles`,
		"active_sessions":  `SELECT count(*)::text FROM guacamole_sessions WHERE status = 'active'`,

		// Every mutable timestamp the sweep writes, by row, digested.
		"checkout_digest": `SELECT COALESCE(md5(string_agg(
			id::text || '|' || status || '|' || COALESCE(returned_at::text, ''), ',' ORDER BY id)), '')
			FROM vault_checkouts`,
		"grant_digest": `SELECT COALESCE(md5(string_agg(
			id::text || '|' || COALESCE(expires_at::text, ''), ',' ORDER BY id)), '')
			FROM vault_access_grants`,
		"session_digest": `SELECT COALESCE(md5(string_agg(
			id::text || '|' || status || '|' || COALESCE(ended_at::text, ''), ',' ORDER BY id)), '')
			FROM guacamole_sessions`,
		"request_digest": `SELECT COALESCE(md5(string_agg(
			id::text || '|' || status || '|' || COALESCE(updated_at::text, ''), ',' ORDER BY id)), '')
			FROM access_requests`,
	} {
		var v string
		require.NoError(t, pool.QueryRow(ctx, q).Scan(&v), name)
		out[name] = v
	}
	return out
}

func TestTheLifecycleSweepIsIdempotentAcrossReplicas(t *testing.T) {
	pool := openLifecyclePool(t)
	svc, _ := seedLifecycle(t, pool)
	ctx := orgctx.WithBypassRLS(context.Background())

	before := lifecycleState(t, pool)
	require.Equal(t, "2", before["active_checkouts"])
	require.Equal(t, "2", before["live_grants"])
	require.Equal(t, "2", before["fulfilled_reqs"])
	require.Equal(t, "2", before["role_assignments"])

	svc.runLifecycleEnforcement(ctx)
	afterFirst := lifecycleState(t, pool)

	// The disabled user's access is gone and the enabled user's is untouched --
	// which is the sweep doing its job, and the precondition for the claim
	// being interesting at all.
	assert.Equal(t, "1", afterFirst["active_checkouts"], "the disabled user's checkout was revoked")
	assert.Equal(t, "1", afterFirst["live_grants"], "the disabled user's grant was expired")
	assert.Equal(t, "1", afterFirst["fulfilled_reqs"], "the disabled user's elevation was ended")
	assert.Equal(t, "1", afterFirst["role_assignments"], "the disabled user's role was revoked")

	// THE CLAIM: a second replica running the same sweep changes nothing.
	// Three more passes, because "harmless once" and "harmless always" are
	// different statements and the register records the second one.
	for i := 0; i < 3; i++ {
		svc.runLifecycleEnforcement(ctx)
		assert.Equal(t, afterFirst, lifecycleState(t, pool),
			"pass %d changed state the first pass had already settled", i+2)
	}
}

// The enabled user must survive every pass. An idempotent sweep that converges
// on the wrong state converges just as reliably.
func TestTheLifecycleSweepNeverTouchesAnEnabledUser(t *testing.T) {
	pool := openLifecyclePool(t)
	svc, disabled := seedLifecycle(t, pool)
	ctx := orgctx.WithBypassRLS(context.Background())

	for i := 0; i < 3; i++ {
		svc.runLifecycleEnforcement(ctx)
	}

	var enabledCheckouts, enabledRoles int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM vault_checkouts vc JOIN users u ON u.id = vc.principal_id
		  WHERE u.enabled = true AND vc.status = 'active'`).Scan(&enabledCheckouts))
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_roles ur JOIN users u ON u.id = ur.user_id
		  WHERE u.enabled = true`).Scan(&enabledRoles))
	assert.Equal(t, 1, enabledCheckouts, "an enabled user's privileged access must survive the sweep")
	assert.Equal(t, 1, enabledRoles)

	var disabledLeft int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_roles WHERE user_id = $1`, disabled).Scan(&disabledLeft))
	assert.Equal(t, 0, disabledLeft)
}

// THE CLAIM THE REGISTER RESTS ON: eight replicas sweeping at once reach the
// right state, and reach a SETTLED one -- nothing left half-applied by the race
// for a later tick to finish or repeat.
func TestEightConcurrentLifecycleSweepsConvergeTheSameWay(t *testing.T) {
	pool := openLifecyclePool(t)
	svc, _ := seedLifecycle(t, pool)
	ctx := orgctx.WithBypassRLS(context.Background())

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svc.runLifecycleEnforcement(ctx)
		}()
	}
	wg.Wait()

	after := lifecycleState(t, pool)

	// The right state: exactly the disabled user's access is gone, which is
	// the same outcome one replica produces.
	assert.Equal(t, "1", after["active_checkouts"])
	assert.Equal(t, "1", after["live_grants"])
	assert.Equal(t, "1", after["fulfilled_reqs"])
	assert.Equal(t, "1", after["role_assignments"])

	// And a settled one. If the race had left anything half-applied -- a
	// revocation without its status change, an elevation ended but not marked
	// -- this further pass would finish it and the digests would move.
	svc.runLifecycleEnforcement(ctx)
	assert.Equal(t, after, lifecycleState(t, pool),
		"the concurrent sweeps left work for a later tick to do")
}
