package events

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// recordingSink is a broker that can be turned off. It records what it accepted
// in order, so a test can ask not only "how many" but "which, and how often".
type recordingSink struct {
	mu       sync.Mutex
	accepted []string // event ids, in acceptance order
	down     bool
	fail     error
}

func (s *recordingSink) Publish(_ context.Context, d Delivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		if s.fail != nil {
			return s.fail
		}
		return errors.New("sink is down")
	}
	s.accepted = append(s.accepted, d.EventID)
	return nil
}

func (s *recordingSink) setDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

func (s *recordingSink) ids() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.accepted))
	copy(out, s.accepted)
	return out
}

// produce writes n events, each in its own transaction, the way a service does.
func produce(t *testing.T, db *database.PostgresDB, orgID string, n int) []string {
	t.Helper()
	bus := NewOutboxBus()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ev := NewEvent(EventSessionRevoked, "relay-test", map[string]interface{}{"n": i})
		require.NoError(t, db.WithTxCtx(tenantCtx(orgID), func(txCtx context.Context, tx pgx.Tx) error {
			_, err := bus.Publish(txCtx, ev)
			return err
		}))
		ids = append(ids, ev.ID)
	}
	return ids
}

func unpublishedCount(t *testing.T, db *database.PostgresDB) int {
	t.Helper()
	var n int
	require.NoError(t, db.WithTx(bypassCtx(), func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT count(*) FROM outbox WHERE published_at IS NULL").Scan(&n)
	}))
	return n
}

// THE ACCEPTANCE CRITERION for task 3.1: the relay is down for the length of an
// outage, and when it comes back the loss is zero and the delivered count
// equals the produced count.
//
// The outage is simulated by a sink that refuses rather than by sleeping ten
// minutes: what makes it an outage is that every attempt fails, and the relay
// cannot tell a refusal that lasted ten minutes from one that lasted ten
// seconds. What IS measured over the real interval is the thing that could
// break -- the rows stay claimable and the attempt counter does not run away.
func TestAnOutageLosesNothingAndDeliversEveryEventExactlyOnce(t *testing.T) {
	pool := openOutboxPool(t)
	db, orgA, _ := seedOutbox(t, pool)
	sink := &recordingSink{down: true}
	// MaxAttempts is high enough that the outage's failed attempts do not
	// exhaust it; the poison-row bound is tested separately.
	relay := NewRelay(db, sink, RelayConfig{BatchSize: 10, MaxAttempts: 1000}, zap.NewNop())

	const produced = 25
	want := produce(t, db, orgA, produced)

	// The broker is down. Drain repeatedly: nothing is delivered, and nothing
	// is lost either -- every row is still in the backlog.
	for i := 0; i < 5; i++ {
		n, err := relay.DrainOnce(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 10, n, "the relay keeps claiming a full batch; a refused row is not consumed")
	}
	assert.Empty(t, sink.ids())
	assert.Equal(t, produced, unpublishedCount(t, db), "an outage must leave the backlog intact")

	// The broker comes back.
	sink.setDown(false)
	for {
		n, err := relay.DrainOnce(context.Background())
		require.NoError(t, err)
		if n == 0 {
			break
		}
	}

	assert.Equal(t, 0, unpublishedCount(t, db), "the backlog must drain completely")
	assert.ElementsMatch(t, want, sink.ids(), "delivered set must equal produced set")
	assert.Len(t, sink.ids(), produced, "and each exactly once")
}

// AT-LEAST-ONCE, DEMONSTRATED. The sink accepts and the transaction then fails,
// which is the one ordering that can duplicate -- and the one chosen, because
// the alternative loses events instead. An idempotent consumer swallows it;
// this shows both halves.
func TestACrashAfterTheSinkAcceptsRedeliversAndAnIdempotentConsumerAbsorbsIt(t *testing.T) {
	pool := openOutboxPool(t)
	db, orgA, _ := seedOutbox(t, pool)
	sink := &recordingSink{}
	relay := NewRelay(db, sink, RelayConfig{BatchSize: 10, MaxAttempts: 1000}, zap.NewNop())

	want := produce(t, db, orgA, 3)

	// The crash: the sink takes all three, and the transaction that would have
	// marked them rolls back. That is exactly what a process death between the
	// two does.
	err := db.WithTx(bypassCtx(), func(tx pgx.Tx) error {
		batch, cerr := relay.claim(context.Background(), tx)
		require.NoError(t, cerr)
		require.Len(t, batch, 3)
		for _, d := range batch {
			relay.deliver(context.Background(), tx, d)
		}
		return errors.New("the relay died before committing")
	})
	require.Error(t, err)

	assert.Len(t, sink.ids(), 3, "the sink has them")
	assert.Equal(t, 3, unpublishedCount(t, db), "and the outbox does not know that, which is the designed direction")

	// The next drain redelivers all three.
	_, err = relay.DrainOnce(context.Background())
	require.NoError(t, err)
	assert.Len(t, sink.ids(), 6, "at-least-once: the same three arrive again")
	assert.Equal(t, 0, unpublishedCount(t, db))

	// An idempotent consumer sees six deliveries and three events, because
	// event_id is what identifies an event -- not its arrival.
	seen := map[string]int{}
	for _, id := range sink.ids() {
		seen[id]++
	}
	assert.Len(t, seen, 3, "three distinct events")
	assert.ElementsMatch(t, want, keysOf(seen))
	for id, n := range seen {
		assert.Equal(t, 2, n, "event %s was delivered twice, which the consumer must absorb", id)
	}
}

// NO LEADER IS NEEDED, measured. Four relays drain the same table at once and
// every event is delivered exactly once: SKIP LOCKED is the coordination, so
// the lease a leader would need -- and the gap between a leader dying and its
// lease expiring -- buys nothing here.
func TestFourConcurrentRelaysDeliverEveryEventExactlyOnce(t *testing.T) {
	pool := openOutboxPool(t)
	db, orgA, _ := seedOutbox(t, pool)
	sink := &recordingSink{}

	const produced = 60
	want := produce(t, db, orgA, produced)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			relay := NewRelay(db, sink, RelayConfig{BatchSize: 7, MaxAttempts: 1000}, zap.NewNop())
			for {
				n, err := relay.DrainOnce(context.Background())
				if err != nil || n == 0 {
					return
				}
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 0, unpublishedCount(t, db))
	got := sink.ids()
	assert.Len(t, got, produced, "exactly once across four relays: no row was claimed twice")
	assert.ElementsMatch(t, want, got)
}

// A poison event -- one the sink will never accept -- must stop consuming the
// relay's capacity, and must stay in the table where somebody can find it.
func TestAPoisonEventStopsBeingRetriedAndKeepsItsError(t *testing.T) {
	pool := openOutboxPool(t)
	db, orgA, _ := seedOutbox(t, pool)
	sink := &recordingSink{down: true, fail: errors.New("this event will never be accepted")}
	relay := NewRelay(db, sink, RelayConfig{BatchSize: 10, MaxAttempts: 3}, zap.NewNop())

	produce(t, db, orgA, 1)

	for i := 0; i < 10; i++ {
		if _, err := relay.DrainOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	var attempts int
	var lastErr *string
	require.NoError(t, db.WithTx(bypassCtx(), func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			"SELECT attempts, last_error FROM outbox WHERE published_at IS NULL").Scan(&attempts, &lastErr)
	}))
	assert.Equal(t, 3, attempts, "the row stops being claimed at MaxAttempts rather than retrying forever")
	require.NotNil(t, lastErr)
	assert.Contains(t, *lastErr, "never be accepted", "the reason stays on the row")

	// And it is still there, which is the point: a poison event is a thing to
	// investigate, not a thing to delete.
	assert.Equal(t, 1, unpublishedCount(t, db))
}

// The relay reads every tenant's rows, because there is one relay for the
// install. The bypass is what allows that, and this fails if it is removed --
// which would look like "the relay delivers nothing" in production.
func TestTheRelayDrainsEveryTenant(t *testing.T) {
	pool := openOutboxPool(t)
	db, orgA, orgB := seedOutbox(t, pool)
	sink := &recordingSink{}
	relay := NewRelay(db, sink, RelayConfig{BatchSize: 50, MaxAttempts: 10}, zap.NewNop())

	a := produce(t, db, orgA, 4)
	b := produce(t, db, orgB, 3)

	_, err := relay.DrainOnce(context.Background())
	require.NoError(t, err)
	assert.ElementsMatch(t, append(append([]string{}, a...), b...), sink.ids())
}

func keysOf(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// bypassCtx reads the table the way the relay does: cross-tenant, because one
// relay serves the whole install.
func bypassCtx() context.Context {
	return orgctx.WithBypassRLS(context.Background())
}
