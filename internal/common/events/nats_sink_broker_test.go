package events

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// THE SINK'S CONTRACT, MEASURED AGAINST A REAL BROKER RATHER THAN ASSERTED.
//
// Sink.Publish promises that a nil return means the broker has ACCEPTED the
// event, because the relay deletes the outbox row on that nil. The only way to
// know whether a client call keeps that promise is to ask the server what it
// holds AT THE INSTANT the call returns -- which is what the first test does,
// and what showed that two of the three publish APIs do not: 33 and 60 of 200
// against js.Publish's 200.
//
// No mock can answer this question. A fake sink returns whatever it is written
// to return; the whole point is what the network and the server do.
func natsTestConn(t *testing.T) *nats.Conn {
	t.Helper()
	url := os.Getenv("TEST_NATS_URL")
	if url == "" {
		t.Skip("TEST_NATS_URL not set; skipping the broker-backed sink tests")
	}
	nc, err := nats.Connect(url)
	require.NoError(t, err, "connect to %s", url)
	t.Cleanup(nc.Close)
	return nc
}

func newTestSink(t *testing.T, nc *nats.Conn, stream string) (*NATSSink, jetstream.JetStream) {
	t.Helper()
	ctx := context.Background()
	js, err := jetstream.New(nc)
	require.NoError(t, err)
	_ = js.DeleteStream(ctx, stream)
	t.Cleanup(func() { _ = js.DeleteStream(context.Background(), stream) })

	sink, err := NewNATSSink(ctx, nc, NATSSinkConfig{Stream: stream, Prefix: "openidxtest"})
	require.NoError(t, err)
	return sink, js
}

func delivery(i int) Delivery {
	return Delivery{
		ID:        int64(i),
		OrgID:     "org-1",
		EventID:   fmt.Sprintf("evt-%d", i),
		EventType: "user_created",
		Source:    "identity",
		Payload:   json.RawMessage(`{"user_id":"u1"}`),
		CreatedAt: time.Now().UTC(),
	}
}

func TestPublishReturnsOnlyAfterTheBrokerHasTheEvent(t *testing.T) {
	nc := natsTestConn(t)
	ctx := context.Background()
	sink, js := newTestSink(t, nc, "SINK_SYNC_TEST")

	const n = 200
	start := time.Now()
	for i := 0; i < n; i++ {
		require.NoError(t, sink.Publish(ctx, delivery(i)))
	}
	elapsed := time.Since(start)

	stream, err := js.Stream(ctx, "SINK_SYNC_TEST")
	require.NoError(t, err)
	info, err := stream.Info(ctx)
	require.NoError(t, err)

	// The assertion the contract is made of: no sleep, no retry, no eventual
	// consistency. Every event the sink said it published is already in the
	// stream, because that is what "accepted" has to mean for the relay to be
	// allowed to delete the row.
	assert.Equal(t, uint64(n), info.State.Msgs,
		"the sink returned nil for %d events but the stream holds %d. A sink that returns before the broker has the event turns the relay's at-least-once into at-most-once, silently",
		n, info.State.Msgs)

	t.Logf("%d synchronous publishes in %s (%.0fus each)", n, elapsed, float64(elapsed.Microseconds())/n)
}

// The relay is at-least-once BY DESIGN: it publishes, then commits the mark, and
// a crash between the two redelivers. That is the right trade -- a duplicate is
// recognisable and a lost event is not -- and it makes duplicates ordinary
// traffic rather than an incident. The message id is what keeps them from
// reaching a consumer.
func TestARedeliveredEventIsNotDuplicatedInTheStream(t *testing.T) {
	nc := natsTestConn(t)
	ctx := context.Background()
	sink, js := newTestSink(t, nc, "SINK_DEDUPE_TEST")

	d := delivery(1)
	require.NoError(t, sink.Publish(ctx, d))
	require.NoError(t, sink.Publish(ctx, d), "a redelivery must not be an error; the relay will do this after a crash")

	stream, err := js.Stream(ctx, "SINK_DEDUPE_TEST")
	require.NoError(t, err)
	info, err := stream.Info(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), info.State.Msgs,
		"the same event id was published twice and the stream holds %d messages; the broker's duplicate window is what makes the relay's designed redelivery invisible to a consumer", info.State.Msgs)

	// And a DIFFERENT event is not swallowed by the same window -- the
	// deduplication has to be on the id and not on the subject, or the second
	// event of a busy tenant disappears.
	other := delivery(2)
	require.NoError(t, sink.Publish(ctx, other))
	info, err = stream.Info(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), info.State.Msgs,
		"a second, distinct event on the same subject was suppressed; deduplication must key on the event id")
}

// What the consumer will actually read, and where. Both are part of the
// contract: the subject is what a permission matches, and the body is what a
// consumer trusts for the tenant rather than trusting a routing decision.
func TestTheEventLandsOnItsOwnSubjectCarryingItsOwnTenant(t *testing.T) {
	nc := natsTestConn(t)
	ctx := context.Background()
	sink, js := newTestSink(t, nc, "SINK_SUBJECT_TEST")

	require.NoError(t, sink.Publish(ctx, delivery(7)))

	stream, err := js.Stream(ctx, "SINK_SUBJECT_TEST")
	require.NoError(t, err)
	msg, err := stream.GetMsg(ctx, 1)
	require.NoError(t, err)

	assert.Equal(t, "openidxtest.org-1.user_created", msg.Subject)

	var env natsEnvelope
	require.NoError(t, json.Unmarshal(msg.Data, &env))
	assert.Equal(t, "evt-7", env.EventID)
	assert.Equal(t, "org-1", env.OrgID, "the tenant travels in the body too; a consumer that reads it off the subject is trusting routing to carry a tenant boundary")
	assert.Equal(t, "identity", env.Source)
	assert.JSONEq(t, `{"user_id":"u1"}`, string(env.Payload))
}

// The retention the plan asks for is a property of the STREAM, so it is the
// stream that has to be asked. Reading it back also catches the case this
// package cares about most: a stream somebody else created first, with
// different settings, which would change what the relay guarantees without
// changing a line of the relay.
func TestTheStreamKeepsWhatTheSinkClaimsItKeeps(t *testing.T) {
	nc := natsTestConn(t)
	ctx := context.Background()
	_, js := newTestSink(t, nc, "SINK_RETENTION_TEST")

	stream, err := js.Stream(ctx, "SINK_RETENTION_TEST")
	require.NoError(t, err)
	info, err := stream.Info(ctx)
	require.NoError(t, err)

	assert.Equal(t, 7*24*time.Hour, info.Config.MaxAge, "the plan's seven days")
	assert.Equal(t, 2*time.Minute, info.Config.Duplicates, "a duplicate window shorter than a relay restart buys nothing")
	assert.Equal(t, jetstream.FileStorage, info.Config.Storage, "memory storage loses acknowledged events on restart")
	assert.Equal(t, []string{"openidxtest.>"}, info.Config.Subjects)
}

// A subject token carrying structure is refused before it reaches the broker.
// The unit test covers the shapes; this one proves the refusal happens on the
// path a real publish takes, and that nothing lands when it does.
func TestAnEventWhoseTypeCarriesAWildcardIsNeverPublished(t *testing.T) {
	nc := natsTestConn(t)
	ctx := context.Background()
	sink, js := newTestSink(t, nc, "SINK_WILDCARD_TEST")

	d := delivery(1)
	d.EventType = "user.>"
	require.Error(t, sink.Publish(ctx, d))

	stream, err := js.Stream(ctx, "SINK_WILDCARD_TEST")
	require.NoError(t, err)
	info, err := stream.Info(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), info.State.Msgs, "the refusal has to happen before the publish, not after it")
}
