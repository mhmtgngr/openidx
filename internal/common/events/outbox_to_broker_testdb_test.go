package events

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// THE WHOLE PATH, ONCE, WITH NOTHING MOCKED.
//
// Every piece of this has been measured on its own: the outbox commits with the
// write it describes (task 3.1a), the relay claims and marks without losing a
// row (3.1b), the sink returns only once the broker has the event (3.2). What
// none of them proves is that the pieces FIT -- that an event written inside a
// business transaction comes out the other end, on the subject a consumer
// subscribes to, carrying the tenant it was written under.
//
// That gap is not hypothetical. It is exactly the gap the plan left open in as
// many words: "no production code writes to this outbox and no process runs the
// relay". cmd/event-relay closes it by composing these three; this test is that
// composition, measured, so the composition cannot quietly stop working.
//
// Needs BOTH a real Postgres and a real broker, and skips otherwise -- a mock
// on either side would be measuring the mock.
func TestAnEventWrittenInATransactionReachesTheBroker(t *testing.T) {
	pool := openOutboxPool(t)
	nc := natsTestConn(t)
	ctx := context.Background()

	db, orgA, orgB := seedOutbox(t, pool)
	sink, js := newTestSink(t, nc, "OUTBOX_E2E_TEST")
	relay := NewRelay(db, sink, RelayConfig{BatchSize: 10}, zap.NewNop())
	bus := NewOutboxBus()

	// Write the events the way a service would: inside the transaction that
	// carries the state change, under a tenant scope.
	write := func(orgID string, evs ...Event) {
		t.Helper()
		require.NoError(t, db.WithTxCtx(tenantCtx(orgID), func(txCtx context.Context, _ pgx.Tx) error {
			for _, ev := range evs {
				if _, err := bus.Publish(txCtx, ev); err != nil {
					return err
				}
			}
			return nil
		}))
	}
	evA1 := NewEvent("user.created", "identity", map[string]interface{}{"user_id": "u1"})
	evA2 := NewEvent("session.revoked", "oauth", map[string]interface{}{"sid": "s1"})
	evB1 := NewEvent("user.created", "identity", map[string]interface{}{"user_id": "u2"})
	write(orgA, evA1, evA2)
	write(orgB, evB1)

	// Nothing is in the broker yet: the outbox's whole point is that the write
	// is durable BEFORE anything leaves the process.
	stream, err := js.Stream(ctx, "OUTBOX_E2E_TEST")
	require.NoError(t, err)
	info, err := stream.Info(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(0), info.State.Msgs,
		"events reached the broker before the relay ran; the outbox is supposed to be the only path out")

	claimed, err := relay.DrainOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, claimed)

	info, err = stream.Info(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(3), info.State.Msgs, "all three events should be in the stream after one drain")

	// Read them back and check each landed where a consumer would look for it.
	// The subject carries the tenant because a consumer subscribes per tenant;
	// the body carries it too, because trusting the subject means trusting a
	// routing decision to hold a tenant boundary.
	bySubject := map[string]natsEnvelope{}
	for seq := uint64(1); seq <= 3; seq++ {
		msg, gerr := stream.GetMsg(ctx, seq)
		require.NoError(t, gerr)
		var env natsEnvelope
		require.NoError(t, json.Unmarshal(msg.Data, &env))
		bySubject[msg.Subject] = env
		assert.Equal(t, env.OrgID, subjectOrg(t, msg.Subject),
			"the org in the body and the org in the subject disagree for %s", msg.Subject)
	}
	require.Len(t, bySubject, 3, "three distinct subjects; got %v", subjectsOf(bySubject))

	assert.Equal(t, evA1.ID, bySubject["openidxtest."+orgA+".user.created"].EventID)
	assert.Equal(t, evA2.ID, bySubject["openidxtest."+orgA+".session.revoked"].EventID)
	assert.Equal(t, evB1.ID, bySubject["openidxtest."+orgB+".user.created"].EventID)

	// And the rows are marked, so a second drain is a no-op rather than a
	// redelivery of everything that already went.
	second, err := relay.DrainOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, second, "a second drain claimed rows that were already delivered")
	info, err = stream.Info(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(3), info.State.Msgs)
}

// A broker that refuses leaves the rows where they are. This is the property
// that makes the outbox worth its table: an outage is a pause, not a loss, and
// what proves it is that the SAME rows are still claimable afterwards.
func TestABrokerOutageLeavesTheBacklogIntactAndDeliversItAfterwards(t *testing.T) {
	pool := openOutboxPool(t)
	nc := natsTestConn(t)
	ctx := context.Background()

	db, orgA, _ := seedOutbox(t, pool)
	realSink, js := newTestSink(t, nc, "OUTBOX_OUTAGE_TEST")
	gate := &gatedSink{inner: realSink, open: false}
	relay := NewRelay(db, gate, RelayConfig{BatchSize: 10}, zap.NewNop())
	bus := NewOutboxBus()

	require.NoError(t, db.WithTxCtx(tenantCtx(orgA), func(txCtx context.Context, _ pgx.Tx) error {
		for i := 0; i < 5; i++ {
			if _, err := bus.Publish(txCtx, NewEvent("user.created", "identity", nil)); err != nil {
				return err
			}
		}
		return nil
	}))

	// Three full drains against a sink that refuses every attempt. An outage is
	// what makes every attempt fail; a sink that sleeps would only measure the
	// test's patience.
	for i := 0; i < 3; i++ {
		claimed, err := relay.DrainOnce(ctx)
		require.NoError(t, err)
		assert.Equal(t, 5, claimed, "drain %d should still find all five rows", i+1)
	}
	stream, err := js.Stream(ctx, "OUTBOX_OUTAGE_TEST")
	require.NoError(t, err)
	info, err := stream.Info(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(0), info.State.Msgs, "a refusing sink must deliver nothing")

	gate.open = true
	claimed, err := relay.DrainOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, 5, claimed)

	info, err = stream.Info(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(5), info.State.Msgs,
		"after the outage every row should have been delivered exactly once")
}

// gatedSink is an outage with a switch: closed, every publish fails; open, the
// real sink handles it. Wrapping the REAL sink rather than counting calls is
// what keeps the second half of the test a measurement of the broker.
type gatedSink struct {
	inner Sink
	open  bool
}

func (g *gatedSink) Publish(ctx context.Context, d Delivery) error {
	if !g.open {
		return assert.AnError
	}
	return g.inner.Publish(ctx, d)
}

func subjectOrg(t *testing.T, subject string) string {
	t.Helper()
	// openidxtest.<org>.<type...>
	const prefix = "openidxtest."
	require.True(t, len(subject) > len(prefix), "subject %q has no tenant token", subject)
	rest := subject[len(prefix):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '.' {
			return rest[:i]
		}
	}
	t.Fatalf("subject %q has no type token after the tenant", subject)
	return ""
}

func subjectsOf(m map[string]natsEnvelope) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
