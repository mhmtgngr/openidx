package webhooks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
)

// THE QUEUE IS REDIS AND THE RECORD IS POSTGRESQL, and the sweep that bridges
// them re-reads rather than claims.
//
// Publish INSERTs a delivery row as `pending` and then nudges Redis. If the
// nudge is lost -- a Redis blip, a restart between the two -- the row would
// never be delivered, so processRetryBatch scans for pending rows and pushes
// them back onto the queue. That backstop is right, and its comment says so.
//
// What it does not do is mark what it pushed. A row stays `pending` for its
// whole life in the queue AND for the whole HTTP call, so a delivery the
// consumer has not reached yet still matches on the next tick, and the one
// after that. Every thirty seconds the entire undrained backlog is enqueued
// again -- and each of those entries is a real HTTP POST to the customer's
// endpoint once it is consumed.
//
// That is not "at-least-once". At-least-once is a delivery that may repeat;
// this is a feedback loop whose output is proportional to how far behind the
// consumer is, which means it grows fastest exactly when the consumer is
// already struggling.

func openWebhookPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the webhook retry tests (they need a real Postgres)")
	}
	schema := "wh_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")

	bootstrap, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	_, err = bootstrap.Exec(context.Background(), `CREATE SCHEMA `+schema)
	bootstrap.Close()
	require.NoError(t, err, "the test DSN must be allowed to create a schema")

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	// At least two connections: one test runs two sweeps at once on purpose.
	cfg.MinConns = 2
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		pool.Close()
		drop, derr := pgxpool.New(context.Background(), dsn)
		if derr == nil {
			_, _ = drop.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
			drop.Close()
		}
	})
	return pool
}

func openWebhookRedis(t *testing.T) *goredis.Client {
	t.Helper()
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	// A real Redis, because the defect is about what the QUEUE holds after the
	// sweep runs, and the queue is a Redis list.
	c := goredis.NewClient(&goredis.Options{Addr: addr, DB: 15})
	if err := c.Ping(context.Background()).Err(); err != nil {
		t.Skipf("no Redis at %s: %v", addr, err)
	}
	require.NoError(t, c.FlushDB(context.Background()).Err())
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// seedWebhooks builds the two tables the delivery path touches and one active
// subscription pointing at the given URL.
func seedWebhooks(t *testing.T, pool *pgxpool.Pool, rdb *goredis.Client, url string) (*Service, string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		CREATE TABLE webhook_subscriptions (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			name varchar(255) NOT NULL, url text NOT NULL, secret varchar(255) NOT NULL,
			events text[] NOT NULL, status varchar(50) DEFAULT 'active',
			created_by uuid, org_id uuid,
			created_at timestamptz DEFAULT NOW(), updated_at timestamptz DEFAULT NOW());
		CREATE TABLE webhook_deliveries (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			subscription_id uuid NOT NULL, event_type varchar(100) NOT NULL,
			payload jsonb NOT NULL, response_status integer, response_body text,
			attempt integer DEFAULT 1, status varchar(50) DEFAULT 'pending',
			next_retry_at timestamptz, queued_at timestamptz, org_id uuid,
			created_at timestamptz DEFAULT NOW(), delivered_at timestamptz);`)
	require.NoError(t, err)

	org := uuid.NewString()
	subID := uuid.NewString()
	_, err = pool.Exec(context.Background(), `
		INSERT INTO webhook_subscriptions (id, name, url, secret, events, status, org_id)
		VALUES ($1, 'test', $2, 'shh', ARRAY['user.created'], 'active', $3)`, subID, url, org)
	require.NoError(t, err)

	svc := &Service{
		db:     &database.PostgresDB{Pool: database.NewScopedPool(pool)},
		redis:  &database.RedisClient{Client: rdb},
		logger: zap.NewNop(),
		client: NewService(nil, nil, zap.NewNop(), nil).client,
		cipher: secretcrypt.NewNoop(),
	}
	return svc, org
}

// receiver counts what actually reaches the customer's endpoint.
type receiver struct {
	hits atomic.Int64
	srv  *httptest.Server
}

func newReceiver(t *testing.T, status int) *receiver {
	t.Helper()
	r := &receiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.hits.Add(1)
		w.WriteHeader(status)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func queueLen(t *testing.T, rdb *goredis.Client) int64 {
	t.Helper()
	n, err := rdb.LLen(context.Background(), "webhook:deliveries").Result()
	require.NoError(t, err)
	return n
}

// backdate ages every pending delivery past both of the sweep's windows -- the
// thirty-second grace for a row nobody claimed, and the claim window for one
// that was queued and not reached. That is what "the consumer is minutes
// behind" means, and it is the state the sweep exists for.
func backdate(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`UPDATE webhook_deliveries
		    SET created_at = NOW() - INTERVAL '5 minutes',
		        queued_at = CASE WHEN queued_at IS NULL THEN NULL ELSE NOW() - INTERVAL '5 minutes' END
		  WHERE status = 'pending'`)
	require.NoError(t, err)
}

func bypassCtx() context.Context { return orgctx.WithBypassRLS(context.Background()) }

// THE PROPERTY. A delivery already waiting in the queue is not put there again.
func TestTheRetrySweepDoesNotReEnqueueADeliveryItAlreadyQueued(t *testing.T) {
	pool := openWebhookPool(t)
	rdb := openWebhookRedis(t)
	rcv := newReceiver(t, 200)
	svc, org := seedWebhooks(t, pool, rdb, rcv.srv.URL)

	require.NoError(t, svc.Publish(orgctx.With(context.Background(), orgctx.Org{ID: org}),
		"user.created", map[string]string{"id": "u1"}))
	require.Equal(t, int64(1), queueLen(t, rdb), "one event, one subscription, one queue entry")

	// The consumer has not got to it yet: past the thirty-second grace, but
	// well inside the claim window, which is exactly the state a backlog is in.
	_, err := pool.Exec(context.Background(),
		`UPDATE webhook_deliveries SET created_at = NOW() - INTERVAL '5 minutes' WHERE status = 'pending'`)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		svc.processRetryBatch(bypassCtx())
	}

	require.Equal(t, int64(1), queueLen(t, rdb),
		"the sweep enqueued a delivery that was already in the queue, once per tick. "+
			"Every thirty seconds the whole undrained backlog is duplicated, and each duplicate "+
			"is a real POST to the customer's endpoint -- an amplification loop that grows fastest "+
			"when the consumer is already behind.")
}

// The same fact measured where the customer feels it: HTTP requests.
func TestABackloggedDeliveryFiresOnceNotOncePerSweepTick(t *testing.T) {
	pool := openWebhookPool(t)
	rdb := openWebhookRedis(t)
	rcv := newReceiver(t, 200)
	svc, org := seedWebhooks(t, pool, rdb, rcv.srv.URL)

	require.NoError(t, svc.Publish(orgctx.With(context.Background(), orgctx.Org{ID: org}),
		"user.created", map[string]string{"id": "u1"}))
	backdate(t, pool)
	for i := 0; i < 3; i++ {
		svc.processRetryBatch(bypassCtx())
	}

	// Drain whatever the queue holds, the way the consumer would.
	ctx := bypassCtx()
	for queueLen(t, rdb) > 0 {
		res, err := rdb.BRPop(ctx, time.Second, "webhook:deliveries").Result()
		require.NoError(t, err)
		_ = svc.deliverWebhook(ctx, res[1])
	}

	require.Equal(t, int64(1), rcv.hits.Load(),
		"the customer's endpoint was called %d times for one published event", rcv.hits.Load())
}

// VACUITY, and the reason the sweep exists at all: a delivery whose Redis nudge
// was lost must still be recovered. A sweep that enqueues nothing satisfies
// every assertion above.
func TestADeliveryWhoseNudgeWasLostIsStillRecovered(t *testing.T) {
	pool := openWebhookPool(t)
	rdb := openWebhookRedis(t)
	rcv := newReceiver(t, 200)
	svc, org := seedWebhooks(t, pool, rdb, rcv.srv.URL)

	require.NoError(t, svc.Publish(orgctx.With(context.Background(), orgctx.Org{ID: org}),
		"user.created", map[string]string{"id": "u1"}))
	// The blip: the row is in PostgreSQL, the nudge is gone from Redis.
	require.NoError(t, rdb.Del(context.Background(), "webhook:deliveries").Err())
	require.Equal(t, int64(0), queueLen(t, rdb))

	// Recovery now waits out the claim window rather than the old thirty-second
	// grace, because the sweep cannot tell a lost nudge from a consumer that is
	// merely slow -- and guessing wrong in the other direction is what
	// multiplied the queue. A minute to recover a blip is the price.
	backdate(t, pool)
	svc.processRetryBatch(bypassCtx())

	require.Equal(t, int64(1), queueLen(t, rdb),
		"a delivery PostgreSQL holds and the queue lost was never recovered; the DB is supposed to be the backstop")
}

// A FAILED DELIVERY MUST STILL COME BACK. scheduleRetry sets its own
// next_retry_at, and once that time passes the sweep owes it another attempt --
// so whatever keeps the sweep from re-enqueueing a queued row must not also
// keep it from re-enqueueing a due one.
func TestADeliveryThatFailedIsQueuedAgainOnceItsRetryIsDue(t *testing.T) {
	pool := openWebhookPool(t)
	rdb := openWebhookRedis(t)
	rcv := newReceiver(t, 500) // the customer's endpoint is down
	svc, org := seedWebhooks(t, pool, rdb, rcv.srv.URL)

	ctx := bypassCtx()
	require.NoError(t, svc.Publish(orgctx.With(context.Background(), orgctx.Org{ID: org}),
		"user.created", map[string]string{"id": "u1"}))
	res, err := rdb.BRPop(ctx, time.Second, "webhook:deliveries").Result()
	require.NoError(t, err)
	_ = svc.deliverWebhook(ctx, res[1]) // fails, schedules a retry
	require.Equal(t, int64(1), rcv.hits.Load())

	var due time.Time
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT next_retry_at FROM webhook_deliveries WHERE id = $1`, res[1]).Scan(&due))
	require.True(t, due.After(time.Now()), "a failed delivery must be scheduled into the future")

	// scheduleRetry already nudges Redis, so clear the queue and ask the sweep
	// alone whether it owes this delivery another attempt once it comes due.
	require.NoError(t, rdb.Del(context.Background(), "webhook:deliveries").Err())
	_, err = pool.Exec(context.Background(),
		`UPDATE webhook_deliveries SET next_retry_at = NOW() - INTERVAL '1 second' WHERE id = $1`, res[1])
	require.NoError(t, err)

	svc.processRetryBatch(ctx)
	require.Equal(t, int64(1), queueLen(t, rdb), "a due retry was not re-queued; failed deliveries would never be retried")
}

// AND THE COORDINATION IS NOT ONLY THE LEADER GATE. ProcessRetries is leader-
// gated, and a Redis outage drops that gate to "every replica sweeps" -- which
// is stated to be safe. Asking whether it is.
func TestTwoSweepsAtOnceEnqueueEachDeliveryOnce(t *testing.T) {
	pool := openWebhookPool(t)
	rdb := openWebhookRedis(t)
	rcv := newReceiver(t, 200)
	svc, org := seedWebhooks(t, pool, rdb, rcv.srv.URL)

	orgCtx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	for i := 0; i < 20; i++ {
		require.NoError(t, svc.Publish(orgCtx, "user.created", map[string]int{"i": i}))
	}
	require.NoError(t, rdb.Del(context.Background(), "webhook:deliveries").Err())
	backdate(t, pool)

	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() { defer func() { done <- struct{}{} }(); svc.processRetryBatch(bypassCtx()) }()
	}
	for i := 0; i < 4; i++ {
		<-done
	}

	require.Equal(t, int64(20), queueLen(t, rdb),
		"four sweeps enqueued %d entries for 20 deliveries; without the leader gate (which a Redis "+
			"outage removes) the sweep multiplies the backlog by the replica count", queueLen(t, rdb))
}

// THE BACKOFF IS WRITTEN DOWN AND THEN DEFEATED ONE LINE LATER.
//
// scheduleRetry computes next_retry_at as one, five and thirty minutes out,
// stores it -- and then pushes the delivery id straight back onto the Redis
// queue. The consumer is blocked on BRPop, so it picks the id up within
// milliseconds and sends again. Nothing on the consumer side reads
// next_retry_at.
//
// The consequence is not that a failing endpoint gets hammered; the attempt
// cap is three, so it is bounded. It is that the three attempts are ALL SPENT
// IN UNDER A SECOND, and the delivery is marked `failed` -- so a retry policy
// whose whole purpose is to ride out a thirty-six minute outage rides out
// nothing at all. A customer endpoint that restarts in ten seconds has already
// lost the event.
func TestAFailedDeliveryWaitsForItsBackoffInsteadOfSpendingEveryAttemptAtOnce(t *testing.T) {
	pool := openWebhookPool(t)
	rdb := openWebhookRedis(t)
	rcv := newReceiver(t, 500) // down, and about to come back
	svc, org := seedWebhooks(t, pool, rdb, rcv.srv.URL)

	ctx := bypassCtx()
	require.NoError(t, svc.Publish(orgctx.With(context.Background(), orgctx.Org{ID: org}),
		"user.created", map[string]string{"id": "u1"}))

	// The consumer loop, exactly as ProcessDeliveries runs it: take whatever the
	// queue holds and deliver it. It stops when the queue is empty.
	started := time.Now()
	for i := 0; i < 20; i++ {
		res, err := rdb.BRPop(ctx, 300*time.Millisecond, "webhook:deliveries").Result()
		if err != nil {
			break // queue drained
		}
		_ = svc.deliverWebhook(ctx, res[1])
	}
	elapsed := time.Since(started)

	var status string
	var attempt int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT status, attempt FROM webhook_deliveries LIMIT 1`).Scan(&status, &attempt))

	require.Equal(t, int64(1), rcv.hits.Load(),
		"the endpoint was called %d times in %s. The backoff is one, five and thirty minutes; "+
			"scheduleRetry stores it and then pushes the delivery straight back onto the queue, "+
			"so every attempt is spent at once and a thirty-six minute retry policy rides out nothing.",
		rcv.hits.Load(), elapsed.Round(time.Millisecond))

	require.NotEqual(t, "failed", status,
		"the delivery was given up on after %d attempts in %s, without ever waiting out a backoff",
		attempt, elapsed.Round(time.Millisecond))
}

// AND THE IDEMPOTENCY GUARD IS A READ, NOT A CLAIM.
//
// deliverWebhook returns early when the row already says `delivered`, which
// absorbs a duplicate consumed AFTER the first one finished -- verified, and
// the reason the amplification above does not show up as duplicate POSTs in a
// single-consumer drain. It cannot absorb duplicates consumed AT THE SAME
// TIME: the check is a SELECT and the send happens between it and the UPDATE.
// The queue entries the sweep multiplies are separate entries, and separate
// consumers take them, so this is the shape the amplification actually
// reaches the customer in.
func TestTheSameDeliveryTakenByTwoConsumersAtOnceIsSentOnce(t *testing.T) {
	pool := openWebhookPool(t)
	rdb := openWebhookRedis(t)

	var inFlight atomic.Int64
	rcv := &receiver{}
	rcv.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rcv.hits.Add(1)
		inFlight.Add(1)
		time.Sleep(150 * time.Millisecond) // the window between the read and the UPDATE
		inFlight.Add(-1)
		w.WriteHeader(200)
	}))
	t.Cleanup(rcv.srv.Close)

	svc, org := seedWebhooks(t, pool, rdb, rcv.srv.URL)
	require.NoError(t, svc.Publish(orgctx.With(context.Background(), orgctx.Org{ID: org}),
		"user.created", map[string]string{"id": "u1"}))

	var deliveryID string
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT id::text FROM webhook_deliveries LIMIT 1`).Scan(&deliveryID))

	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() { defer func() { done <- struct{}{} }(); _ = svc.deliverWebhook(bypassCtx(), deliveryID) }()
	}
	for i := 0; i < 4; i++ {
		<-done
	}

	require.Equal(t, int64(1), rcv.hits.Load(),
		"four consumers took the same delivery at once and the endpoint saw it %d times; "+
			"the `status == delivered` check is a read, and the send happens between it and the UPDATE",
		rcv.hits.Load())
}

// failOnce publishes an event, lets one attempt fail against a dead endpoint,
// and hands back the delivery id with its backoff scheduled into the future.
func failOnce(t *testing.T, svc *Service, pool *pgxpool.Pool, rdb *goredis.Client, org string) string {
	t.Helper()
	ctx := bypassCtx()
	require.NoError(t, svc.Publish(orgctx.With(context.Background(), orgctx.Org{ID: org}),
		"user.created", map[string]string{"id": "u1"}))
	res, err := rdb.BRPop(ctx, time.Second, "webhook:deliveries").Result()
	require.NoError(t, err)
	_ = svc.deliverWebhook(ctx, res[1])

	var due time.Time
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT next_retry_at FROM webhook_deliveries WHERE id = $1`, res[1]).Scan(&due))
	require.True(t, due.After(time.Now()), "the attempt must have scheduled a backoff into the future")
	require.NoError(t, rdb.Del(context.Background(), "webhook:deliveries").Err())
	return res[1]
}

// THE SWEEP OWNS THE SCHEDULE, so it has to honour it. Everything that reaches
// the queue now arrives through this sweep, which makes its next_retry_at
// predicate the thing standing between a backoff and no backoff at all.
func TestTheSweepLeavesADeliveryAloneUntilItsRetryIsDue(t *testing.T) {
	pool := openWebhookPool(t)
	rdb := openWebhookRedis(t)
	rcv := newReceiver(t, 500)
	svc, org := seedWebhooks(t, pool, rdb, rcv.srv.URL)

	id := failOnce(t, svc, pool, rdb, org)

	// Age the row past every window EXCEPT its own retry time.
	_, err := pool.Exec(context.Background(),
		`UPDATE webhook_deliveries SET created_at = NOW() - INTERVAL '5 minutes' WHERE id = $1`, id)
	require.NoError(t, err)

	svc.processRetryBatch(bypassCtx())
	require.Equal(t, int64(0), queueLen(t, rdb),
		"the sweep queued a delivery whose backoff has not elapsed; the one, five and thirty minute "+
			"schedule is only real if the thing that enqueues reads it")

	// And once it IS due, the sweep owes it an attempt -- the other half of the
	// same predicate, without which nothing would ever be retried.
	_, err = pool.Exec(context.Background(),
		`UPDATE webhook_deliveries SET next_retry_at = NOW() - INTERVAL '1 second' WHERE id = $1`, id)
	require.NoError(t, err)
	svc.processRetryBatch(bypassCtx())
	require.Equal(t, int64(1), queueLen(t, rdb))
}

// AND THE CONSUMER CHECKS TOO, because "nothing puts a premature delivery on
// the queue" is a claim about the rest of the system rather than about this
// function. A stray entry -- an old queue drained after an upgrade, a retry
// nudge from a replica still running the previous build -- must not turn into
// an early send.
func TestAConsumerRefusesADeliveryWhoseBackoffHasNotElapsed(t *testing.T) {
	pool := openWebhookPool(t)
	rdb := openWebhookRedis(t)
	rcv := newReceiver(t, 500)
	svc, org := seedWebhooks(t, pool, rdb, rcv.srv.URL)

	id := failOnce(t, svc, pool, rdb, org)
	require.Equal(t, int64(1), rcv.hits.Load(), "one attempt so far")

	// The stray entry, put on the queue by something other than the sweep.
	require.NoError(t, rdb.LPush(context.Background(), "webhook:deliveries", id).Err())
	res, err := rdb.BRPop(bypassCtx(), time.Second, "webhook:deliveries").Result()
	require.NoError(t, err)
	require.NoError(t, svc.deliverWebhook(bypassCtx(), res[1]),
		"a delivery that is not this consumer's to send is an ordinary outcome, not an error")

	require.Equal(t, int64(1), rcv.hits.Load(),
		"the endpoint was called again before the backoff elapsed; the consumer sent a delivery "+
			"that was not due because something else had put it on the queue")
}
