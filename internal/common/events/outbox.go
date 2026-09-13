package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// THE TRANSACTIONAL OUTBOX (global-scale plan task 3.1, ADR-6).
//
// This is the opposite of the in-memory bus in bus.go, and the difference is
// the entire point. An in-memory bus delivers to whoever is subscribed in this
// process, right now, and loses everything if the process dies -- which is
// acceptable for a cache hint and unacceptable for "this session was revoked".
// An outbox writes the event to the SAME TRANSACTION as the state change, so
// the two commit together or neither does, and a separate relay delivers it
// afterwards with at-least-once semantics.
//
// WHAT PUBLISHING OUTSIDE A TRANSACTION WOULD MEAN. Write the row, then
// publish: a crash in between loses the event, and nothing in the database
// remembers that it was owed. Publish, then write: the platform has announced a
// revocation that did not happen, and consumers acted on it. Neither is fixed
// by retrying, because the process that would retry is the one that died. So
// Publish REFUSES when there is no transaction on the context: an event that
// cannot be atomic is an error, not a best effort. That refusal is the
// guarantee -- everything else here is bookkeeping.
//
// DELIVERY IS AT-LEAST-ONCE, and it has to be. The relay marks a row published
// after the broker accepts it, and a crash between those two facts redelivers.
// Making it exactly-once would need the broker and this database to commit
// together, which they cannot. So every consumer must be idempotent, and
// event_id (unique per tenant) is what lets it recognise a redelivery.
//
// ORDER IS NOT PROMISED. The id is a sequence value taken at INSERT time, and
// transactions commit in whatever order they finish, so id order is not commit
// order. The relay claims by state rather than by cursor for exactly this
// reason (see migration v192), and a consumer that needs ordering must get it
// from the payload -- a version, a timestamp it already trusts -- not from the
// order of arrival.

// ErrNoTransaction is returned by Publish when the context carries no open
// transaction. It is deliberately not wrapped into a "could not publish"
// message: the caller has a bug in its transaction handling, not a failed
// write, and the two want different fixes.
var ErrNoTransaction = errors.New("events: publish requires an open transaction on the context " +
	"(use PostgresDB.WithTxCtx); an event that cannot commit with the state change it describes is not publishable")

// ErrNoTenant is returned when the context carries no organization. Every
// outbox row is tenant-scoped, and a row written without one would be invisible
// under the table's RLS policy rather than global -- an event nobody can read
// and nobody can explain.
var ErrNoTenant = errors.New("events: publish requires a resolved organization on the context")

// OutboxBus writes events into the outbox table.
//
// It has no Subscribe: nothing consumes from here in-process. Delivery is the
// relay's job, and a subscriber inside the publishing process would be the
// in-memory bus again, with the same loss on crash and a table to make it look
// durable.
type OutboxBus struct{}

// NewOutboxBus returns a publisher. It holds no state: the transaction comes
// from the context at each call, which is what stops one being cached.
func NewOutboxBus() *OutboxBus { return &OutboxBus{} }

const insertOutboxSQL = `
INSERT INTO outbox (org_id, event_id, event_type, source, payload, metadata)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id`

// Publish writes ev into the outbox, inside the transaction ctx carries.
//
// It returns ErrNoTransaction when there is none. The row is not visible to
// anything -- including the relay -- until that transaction commits, which is
// the property being bought.
func (b *OutboxBus) Publish(ctx context.Context, ev Event) (int64, error) {
	tx, ok := database.TxFrom(ctx)
	if !ok {
		return 0, ErrNoTransaction
	}
	org, err := orgctx.From(ctx)
	if err != nil || org.ID == "" {
		return 0, ErrNoTenant
	}
	if ev.ID == "" || ev.Type == "" {
		return 0, fmt.Errorf("events: an outbox event needs an id and a type (got id=%q type=%q)", ev.ID, ev.Type)
	}

	payload, err := json.Marshal(ev.Payload)
	if err != nil {
		return 0, fmt.Errorf("events: marshal payload: %w", err)
	}
	metadata, err := json.Marshal(outboxMetadata(ev))
	if err != nil {
		return 0, fmt.Errorf("events: marshal metadata: %w", err)
	}

	var id int64
	if err := tx.QueryRow(ctx, insertOutboxSQL,
		org.ID, ev.ID, ev.Type, ev.Source, payload, metadata).Scan(&id); err != nil {
		return 0, fmt.Errorf("events: write outbox row: %w", err)
	}
	outboxPublishedTotal.WithLabelValues(ev.Type).Inc()
	return id, nil
}

// outboxMetadata folds the event's own metadata together with the two fields
// that are on the Event struct rather than in its map. They go into the same
// JSONB column because a consumer reads them the same way, and keeping them as
// separate columns would mean a migration every time the envelope grows.
func outboxMetadata(ev Event) map[string]string {
	m := make(map[string]string, len(ev.Metadata)+2)
	for k, v := range ev.Metadata {
		m[k] = v
	}
	if ev.TraceID != "" {
		m["trace_id"] = ev.TraceID
	}
	if ev.UserID != "" {
		m["user_id"] = ev.UserID
	}
	return m
}
