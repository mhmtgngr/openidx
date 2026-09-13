package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// THE RELAY: the half of the outbox that delivers.
//
// The publisher's job is to make the event durable with the state change. This
// one's job is to get it out, and its only hard requirement is that it must not
// lose anything -- an outbox that drops a row has bought nothing over
// publishing inline, at the cost of a table.
//
// NO LEADER, AND THIS IS A DELIBERATE DEPARTURE FROM THE PLAN, which specified
// leader election. `FOR UPDATE SKIP LOCKED` already IS the coordination: a row
// another relay holds is invisible to this one, so any number of relays drain
// the same table safely and no two deliver the same row concurrently. A leader
// would add a lease, and a lease adds a failure mode the current design does
// not have -- between a leader dying and its lease expiring, NOBODY relays, and
// the backlog grows for exactly as long as the lease was set to. What a leader
// would buy is global ordering, which this outbox explicitly does not promise
// (see outbox.go: the id is a sequence value, not a commit order). Paying an
// availability gap for a guarantee we do not make is the wrong trade. Measured:
// four relays draining concurrently deliver every event exactly once.
//
// CLAIM, PUBLISH AND MARK ARE ONE TRANSACTION. The row lock taken by SKIP
// LOCKED lasts until that transaction ends, so there is no claim column, no
// "processing" state, and no sweeper for rows a dead relay left claimed --
// dying rolls the transaction back and the row is simply unlocked again. The
// cost is that the transaction stays open across the network publish, which is
// the thing the EVENT plane's idle_in_transaction budget (300s, task 2.4) is
// sized for: a batch of a hundred at single-digit milliseconds each is well
// inside it, and a sink slow enough to breach it is a sink the relay should be
// shouting about rather than quietly holding a transaction for.
//
// AT-LEAST-ONCE, precisely. The sink accepts, and then the transaction commits.
// A crash between those two redelivers, because the mark was never committed.
// The reverse order would lose events instead, which is worse in every case:
// a consumer can recognise a duplicate by event_id, and cannot recover an event
// that was never sent.

// Delivery is one outbox row on its way out.
type Delivery struct {
	ID        int64
	OrgID     string
	EventID   string
	EventType string
	Source    string
	Payload   json.RawMessage
	Metadata  json.RawMessage
	CreatedAt time.Time
	Attempts  int
}

// Sink is where deliveries go. NATS JetStream is the intended one (task 3.2);
// the interface exists so the relay's guarantees can be measured without a
// broker, which is also what lets a deployment run the relay against a
// different transport without touching this file.
type Sink interface {
	// Publish must be synchronous: returning nil means the broker has ACCEPTED
	// the event. A sink that returns before then turns this relay's
	// at-least-once into at-most-once, silently.
	Publish(ctx context.Context, d Delivery) error
}

// RelayConfig tunes the drain.
type RelayConfig struct {
	// BatchSize is how many rows one transaction claims. Larger batches
	// amortise the round trip and hold the transaction open longer.
	BatchSize int
	// PollInterval is how long Run waits after an EMPTY drain. A drain that
	// filled its batch goes straight round again, because a full batch means
	// there is probably more.
	PollInterval time.Duration
	// MaxAttempts bounds redelivery. Past it a row is left unpublished with its
	// last error recorded rather than retried forever: a poison event that
	// cannot be published must stop consuming the relay's capacity, and it must
	// remain in the table where someone can find it.
	MaxAttempts int
}

const (
	defaultRelayBatchSize    = 100
	defaultRelayPollInterval = time.Second
	defaultRelayMaxAttempts  = 10
)

// Relay drains the outbox into a Sink.
type Relay struct {
	db   *database.PostgresDB
	sink Sink
	cfg  RelayConfig
	log  *zap.Logger
}

// NewRelay returns a relay. It does not start anything; call Run.
func NewRelay(db *database.PostgresDB, sink Sink, cfg RelayConfig, log *zap.Logger) *Relay {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultRelayBatchSize
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultRelayPollInterval
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultRelayMaxAttempts
	}
	return &Relay{db: db, sink: sink, cfg: cfg, log: log}
}

// claimSQL takes the oldest unpublished rows this relay can lock. Rows another
// relay holds are skipped rather than waited for, which is what makes running
// several of them safe. attempts < $2 keeps a poison row from being claimed
// forever; it stays in the table, unpublished, with its error.
const claimSQL = `
SELECT id, org_id::text, event_id::text, event_type, source, payload, metadata, created_at, attempts
  FROM outbox
 WHERE published_at IS NULL AND attempts < $2
 ORDER BY id
 LIMIT $1
 FOR UPDATE SKIP LOCKED`

// Run drains until ctx is cancelled.
func (r *Relay) Run(ctx context.Context) {
	for {
		n, err := r.DrainOnce(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			r.log.Warn("outbox drain failed; the rows stay unpublished and are retried", zap.Error(err))
		}
		// A full batch means there is probably more behind it, so do not sleep
		// through a backlog.
		if n == r.cfg.BatchSize {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(r.cfg.PollInterval):
		}
	}
}

// DrainOnce claims one batch, publishes it and marks what the sink accepted.
// It returns how many rows it CLAIMED, which is what tells Run whether to go
// straight round again -- not how many were delivered, because a batch that
// failed entirely is still a batch that was there.
func (r *Relay) DrainOnce(ctx context.Context) (int, error) {
	// The relay is cross-tenant by design: one relay serves every tenant, and
	// the tenant travels on each claimed row. This is the same bypass the SCIM
	// outbound worker and the SSF transmitter run under.
	ctx = orgctx.WithBypassRLS(ctx)

	var claimed int
	err := r.db.WithTx(ctx, func(tx pgx.Tx) error {
		batch, err := r.claim(ctx, tx)
		if err != nil {
			return err
		}
		claimed = len(batch)
		for _, d := range batch {
			r.deliver(ctx, tx, d)
		}
		return nil
	})
	return claimed, err
}

func (r *Relay) claim(ctx context.Context, tx pgx.Tx) ([]Delivery, error) {
	//orgscope:ignore outbox relay (runs under bypass_rls) claiming by state alone; one relay serves every tenant and the tenant travels on each claimed row
	rows, err := tx.Query(ctx, claimSQL, r.cfg.BatchSize, r.cfg.MaxAttempts)
	if err != nil {
		return nil, fmt.Errorf("claim outbox batch: %w", err)
	}
	defer rows.Close()

	var batch []Delivery
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.OrgID, &d.EventID, &d.EventType, &d.Source,
			&d.Payload, &d.Metadata, &d.CreatedAt, &d.Attempts); err != nil {
			return nil, fmt.Errorf("scan outbox row: %w", err)
		}
		batch = append(batch, d)
	}
	return batch, rows.Err()
}

// deliver publishes one row and records the outcome. A failure is recorded and
// the row stays unpublished: the next drain picks it up, because the only thing
// that takes a row out of the backlog is published_at.
func (r *Relay) deliver(ctx context.Context, tx pgx.Tx, d Delivery) {
	if err := r.sink.Publish(ctx, d); err != nil {
		outboxRelayFailedTotal.WithLabelValues(d.EventType).Inc()
		if _, uerr := tx.Exec(ctx,
			//orgscope:ignore outbox relay (runs under bypass_rls) recording a failure on a row it already claimed by primary key
			`UPDATE outbox SET attempts = attempts + 1, last_error = $2 WHERE id = $1`,
			d.ID, err.Error()); uerr != nil {
			r.log.Error("could not record an outbox delivery failure",
				zap.Int64("outbox_id", d.ID), zap.Error(uerr))
		}
		return
	}

	if _, err := tx.Exec(ctx,
		//orgscope:ignore outbox relay (runs under bypass_rls) marking a row it already claimed by primary key
		`UPDATE outbox SET published_at = NOW(), last_error = NULL WHERE id = $1`, d.ID); err != nil {
		// The sink took it and this did not commit, so it will be redelivered.
		// That is the designed direction of the failure, and the log says so
		// rather than leaving someone to infer it from a duplicate.
		r.log.Warn("the sink accepted an event but the outbox row could not be marked; it will be redelivered",
			zap.Int64("outbox_id", d.ID), zap.String("event_id", d.EventID), zap.Error(err))
		return
	}
	outboxRelayDeliveredTotal.WithLabelValues(d.EventType).Inc()
	outboxRelayLagSeconds.Observe(time.Since(d.CreatedAt).Seconds())
}
