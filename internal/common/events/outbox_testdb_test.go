package events

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Measured against a real PostgreSQL, because every claim this file makes is
// about transactions and row-level security -- atomicity, visibility before
// commit, a policy that hides another tenant's rows. A fake satisfies all three
// by construction and proves none of them.
func openOutboxPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the outbox tests (they need a real Postgres)")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	// The same negative control the RLS suite uses: a superuser is exempt from
	// every policy, so the isolation assertions below would pass with the belt
	// cut -- which is worse than no test, because it reads as evidence.
	var isSuper, canBypass bool
	require.NoError(t, pool.QueryRow(context.Background(),
		"SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").Scan(&isSuper, &canBypass))
	require.Falsef(t, isSuper || canBypass,
		"TEST_POSTGRES_DSN connects as a role that bypasses RLS (superuser=%t bypassrls=%t)", isSuper, canBypass)
	return pool
}

// seedOutbox applies migration v192's real SQL. organizations is created here
// only as the foreign key's target: this package's tests are about the outbox,
// and pulling in the whole migration chain to get one referenced table would
// make them a migration test with a different name.
func seedOutbox(t *testing.T, pool *pgxpool.Pool) (*database.PostgresDB, string, string) {
	t.Helper()
	ctx := context.Background()

	_, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS outbox;
		CREATE TABLE IF NOT EXISTS organizations (id uuid primary key, slug text);`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, registeredMigrationSQL(t, 192))
	require.NoError(t, err, "apply v192")
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP TABLE IF EXISTS outbox")
	})

	orgA, orgB := uuid.NewString(), uuid.NewString()
	for _, id := range []string{orgA, orgB} {
		_, err = pool.Exec(ctx,
			"INSERT INTO organizations (id, slug) VALUES ($1,$2) ON CONFLICT DO NOTHING", id, "org-"+id[:8])
		require.NoError(t, err)
	}
	return &database.PostgresDB{Pool: database.NewScopedPool(pool)}, orgA, orgB
}

// registeredMigrationSQL applies what the loader actually ships, not a copy of
// it. A v192 that stops being registered -- or whose SQL is edited without the
// tests being looked at -- fails here rather than passing against a duplicate.
func registeredMigrationSQL(t *testing.T, version int) string {
	t.Helper()
	for _, m := range migrations.All() {
		if m.Version == version {
			return m.UpSQL
		}
	}
	t.Fatalf("migration v%d is not registered", version)
	return ""
}

func tenantCtx(orgID string) context.Context {
	return orgctx.With(context.Background(), orgctx.Org{ID: orgID, Slug: "t-" + orgID[:8]})
}

func testEvent(t string) Event {
	return NewEvent(t, "outbox-test", map[string]interface{}{"k": "v"})
}

// THE GUARANTEE. The event and the state change are one write: roll back and
// neither happened.
func TestAnOutboxEventRollsBackWithTheWriteItDescribes(t *testing.T) {
	pool := openOutboxPool(t)
	db, orgA, _ := seedOutbox(t, pool)
	bus := NewOutboxBus()
	ctx := tenantCtx(orgA)

	wantErr := fmt.Errorf("the business logic failed after the event was written")
	err := db.WithTxCtx(ctx, func(txCtx context.Context, tx pgx.Tx) error {
		if _, perr := bus.Publish(txCtx, testEvent("user.created")); perr != nil {
			return perr
		}
		return wantErr // whatever this transaction was doing, it did not finish
	})
	require.ErrorIs(t, err, wantErr)

	assert.Equal(t, 0, countOutbox(t, pool, orgA),
		"the event committed without the work it describes")
}

func TestAnOutboxEventCommitsWithTheWriteItDescribes(t *testing.T) {
	pool := openOutboxPool(t)
	db, orgA, _ := seedOutbox(t, pool)
	bus := NewOutboxBus()
	ctx := tenantCtx(orgA)

	var id int64
	require.NoError(t, db.WithTxCtx(ctx, func(txCtx context.Context, tx pgx.Tx) error {
		var perr error
		id, perr = bus.Publish(txCtx, testEvent("user.created"))
		return perr
	}))
	assert.Greater(t, id, int64(0))
	assert.Equal(t, 1, countOutbox(t, pool, orgA))
}

// Publishing outside a transaction is an error, not a best effort. This is the
// refusal the whole design rests on: an event that cannot be atomic with its
// state change is not publishable.
func TestPublishingOutsideATransactionIsRefused(t *testing.T) {
	pool := openOutboxPool(t)
	_, orgA, _ := seedOutbox(t, pool)
	bus := NewOutboxBus()

	_, err := bus.Publish(tenantCtx(orgA), testEvent("user.created"))
	require.ErrorIs(t, err, ErrNoTransaction)
	assert.Equal(t, 0, countOutbox(t, pool, orgA))
}

// The closure keeps the OUTER context in scope, and the outer context does not
// carry the transaction. That mistake has to fail loudly, because it is the one
// a reader cannot see: the code looks identical and the event lands outside the
// transaction, or -- as here -- not at all.
func TestPublishingOnTheOuterContextIsRefused(t *testing.T) {
	pool := openOutboxPool(t)
	db, orgA, _ := seedOutbox(t, pool)
	bus := NewOutboxBus()
	outer := tenantCtx(orgA)

	err := db.WithTxCtx(outer, func(txCtx context.Context, tx pgx.Tx) error {
		_, perr := bus.Publish(outer, testEvent("user.created")) // outer, not txCtx
		return perr
	})
	require.ErrorIs(t, err, ErrNoTransaction)
	assert.Equal(t, 0, countOutbox(t, pool, orgA))
}

// A row with no tenant would not be global under FORCE RLS -- it would be
// invisible. An event nobody can read is worse than an event that was refused.
func TestPublishingWithoutATenantIsRefused(t *testing.T) {
	pool := openOutboxPool(t)
	db, _, _ := seedOutbox(t, pool)
	bus := NewOutboxBus()

	err := db.WithTxCtx(context.Background(), func(txCtx context.Context, tx pgx.Tx) error {
		_, perr := bus.Publish(txCtx, testEvent("user.created"))
		return perr
	})
	require.ErrorIs(t, err, ErrNoTenant)
}

// One tenant's events are not another's, enforced by the database rather than
// by the query.
func TestOneTenantCannotReadAnothersEvents(t *testing.T) {
	pool := openOutboxPool(t)
	db, orgA, orgB := seedOutbox(t, pool)
	bus := NewOutboxBus()

	for _, org := range []string{orgA, orgA, orgB} {
		ctx := tenantCtx(org)
		require.NoError(t, db.WithTxCtx(ctx, func(txCtx context.Context, tx pgx.Tx) error {
			_, perr := bus.Publish(txCtx, testEvent("user.created"))
			return perr
		}))
	}

	assert.Equal(t, 2, countOutbox(t, pool, orgA))
	assert.Equal(t, 1, countOutbox(t, pool, orgB))

	// And the belt, not the WHERE clause, is what does it: a query naming no
	// tenant returns nothing rather than everything.
	var n int
	require.NoError(t, db.WithTx(tenantCtx(orgA), func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT count(*) FROM outbox").Scan(&n)
	}))
	assert.Equal(t, 2, n, "an unqualified count under tenant A's scope must see only tenant A's rows")
}

// countOutbox reads under the tenant's own scope, which is what a service would
// see -- not under a bypass, which would make every isolation assertion above
// vacuous.
func countOutbox(t *testing.T, pool *pgxpool.Pool, orgID string) int {
	t.Helper()
	db := &database.PostgresDB{Pool: database.NewScopedPool(pool)}
	var n int
	ctx, cancel := context.WithTimeout(tenantCtx(orgID), 10*time.Second)
	defer cancel()
	require.NoError(t, db.WithTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM outbox WHERE org_id = $1", orgID).Scan(&n)
	}))
	return n
}

// WHY THE RELAY MUST NOT PAGE BY id, measured rather than asserted.
//
// A bigserial hands out its number at INSERT time; a transaction becomes
// visible at COMMIT. Those are different moments, and they can be in different
// orders. A relay that remembers "I have published up to N" therefore has a
// hole in it: an id below N that had not committed when it looked will never be
// above N again.
//
// This drives the two transactions by hand because the race has to be exact --
// the lower id must still be open when the cursor relay reads, which is the
// only interesting case and the one a load test would hit by accident.
func TestASequenceIdIsNotACommitOrderAndACursorRelayLosesTheGap(t *testing.T) {
	pool := openOutboxPool(t)
	_, orgA, _ := seedOutbox(t, pool)
	ctx := context.Background()

	// Two connections, because one transaction has to stay open while the
	// other commits.
	slow, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer slow.Release()
	quick, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer quick.Release()

	insert := func(tx pgx.Tx, typ string) int64 {
		var id int64
		require.NoError(t, tx.QueryRow(ctx,
			`INSERT INTO outbox (org_id, event_id, event_type, source, payload)
			 VALUES ($1,$2,$3,'test','{}'::jsonb) RETURNING id`,
			orgA, uuid.NewString(), typ).Scan(&id))
		return id
	}
	scoped := func(tx pgx.Tx) {
		_, err := tx.Exec(ctx, "select set_config('app.org_id', $1, true)", orgA)
		require.NoError(t, err)
	}

	slowTx, err := slow.Begin(ctx)
	require.NoError(t, err)
	scoped(slowTx)
	lowID := insert(slowTx, "the.slow.one") // id taken, NOT committed

	quickTx, err := quick.Begin(ctx)
	require.NoError(t, err)
	scoped(quickTx)
	highID := insert(quickTx, "the.quick.one")
	require.NoError(t, quickTx.Commit(ctx))

	require.Less(t, lowID, highID, "the slow transaction must hold the lower id for this to be the interesting case")

	// A cursor relay runs now. It cannot see lowID -- that transaction has not
	// committed -- so it advances past it.
	cursor := cursorRelayPass(t, pool, orgA, 0)
	require.Equal(t, []int64{highID}, cursor, "the uncommitted row is correctly invisible")
	lastSeen := highID

	// The slow transaction now commits. The row is there, below the cursor.
	require.NoError(t, slowTx.Commit(ctx))

	assert.Empty(t, cursorRelayPass(t, pool, orgA, lastSeen),
		"a cursor relay never sees the committed-late row again: it is LOST, and nothing in the table says so")

	// The claim-based relay -- what v192 is shaped for -- finds it, because it
	// asks about STATE rather than position.
	claimed := claimRelayPass(t, pool, orgA)
	assert.Equal(t, []int64{lowID, highID}, claimed,
		"claiming by published_at IS NULL delivers both, in id order, with no cursor to fall behind")
}

// cursorRelayPass is the WRONG relay, here only so the loss is demonstrated
// rather than argued. It is not used by anything that ships.
func cursorRelayPass(t *testing.T, pool *pgxpool.Pool, orgID string, after int64) []int64 {
	t.Helper()
	return outboxIDs(t, pool, orgID,
		`SELECT id FROM outbox WHERE org_id = $1 AND id > $2 ORDER BY id`, orgID, after)
}

// claimRelayPass is the shape the relay actually takes: by state, oldest first,
// skipping rows another worker holds.
func claimRelayPass(t *testing.T, pool *pgxpool.Pool, orgID string) []int64 {
	t.Helper()
	return outboxIDs(t, pool, orgID,
		`SELECT id FROM outbox WHERE published_at IS NULL ORDER BY id FOR UPDATE SKIP LOCKED`)
}

func outboxIDs(t *testing.T, pool *pgxpool.Pool, orgID, sql string, args ...any) []int64 {
	t.Helper()
	ctx := context.Background()
	db := &database.PostgresDB{Pool: database.NewScopedPool(pool)}
	var ids []int64
	require.NoError(t, db.WithTx(tenantCtx(orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	}))
	return ids
}

// The table's shape is a set of decisions, and three of them are invisible at
// runtime until the day they matter: a full index instead of a partial one
// costs nothing until the table is large, a nullable tenant column costs
// nothing until a row is written without one, and a missing UNIQUE costs
// nothing until a consumer has to recognise a redelivery.
func TestTheOutboxTableKeepsTheDecisionsItWasShapedAround(t *testing.T) {
	pool := openOutboxPool(t)
	seedOutbox(t, pool)
	ctx := context.Background()

	// The backlog index must be PARTIAL. Without the predicate it grows with
	// the table while the query it answers -- the backlog -- does not.
	var def string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_outbox_unpublished'").Scan(&def))
	assert.Contains(t, def, "WHERE (published_at IS NULL)",
		"the backlog index is not partial; it will grow with the whole table")

	// The tenant column is NOT NULL. Under FORCE RLS a NULL-org row does not
	// leak, it disappears -- an event no tenant-scoped reader can see.
	var nullable string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT is_nullable FROM information_schema.columns
		  WHERE table_name = 'outbox' AND column_name = 'org_id'`).Scan(&nullable))
	assert.Equal(t, "NO", nullable)

	// The belt is on, and FORCED -- the application connects as the table's
	// owner, and an owner is exempt from its own policies without FORCE.
	var enabled, forced bool
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'outbox'").Scan(&enabled, &forced))
	assert.True(t, enabled, "row-level security is not enabled on outbox")
	assert.True(t, forced, "row-level security is not FORCED on outbox; the owner would bypass its own policy")

	// A redelivery has to be recognisable, per tenant.
	var uniq bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT indisunique FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
		  WHERE c.relname = 'idx_outbox_org_event_id'`).Scan(&uniq))
	assert.True(t, uniq)
}

// The same event id twice in one tenant is a bug in the publisher, and the
// database says so rather than storing two rows a consumer cannot tell apart.
func TestOneTenantCannotPublishTheSameEventIdTwice(t *testing.T) {
	pool := openOutboxPool(t)
	db, orgA, orgB := seedOutbox(t, pool)
	bus := NewOutboxBus()

	ev := testEvent("user.created")
	publish := func(org string, e Event) error {
		return db.WithTxCtx(tenantCtx(org), func(txCtx context.Context, tx pgx.Tx) error {
			_, perr := bus.Publish(txCtx, e)
			return perr
		})
	}
	require.NoError(t, publish(orgA, ev))
	require.Error(t, publish(orgA, ev), "the same event id twice in one tenant must be refused")

	// Across tenants it is a coincidence, not a duplicate: one tenant's write
	// must not fail on another's.
	require.NoError(t, publish(orgB, ev))
}
