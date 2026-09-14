package audit

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// Usage metering (Wave A4): the MSP billing substrate. A background aggregator
// consumes the Ziti fabric events already ingested into unified_audit_events
// (overlay logins, service dials) past a cursor and upserts per-(org, user,
// service, metric, day) counters in usage_metering_daily.

const (
	metricOverlayLogin = "overlay_login"
	metricServiceDial  = "service_dial"
	zeroUUID           = "00000000-0000-0000-0000-000000000000"
	meteringBatchSize  = 500
)

type meteringWorker struct {
	svc    *Service
	logger *zap.Logger
}

// StartUsageMetering launches the metering aggregator. Idle-safe: no-op batches
// when there are no new fabric events. Bypasses RLS so it can roll up all orgs.
func (s *Service) StartUsageMetering(ctx context.Context) {
	w := &meteringWorker{svc: s, logger: s.logger.With(zap.String("component", "usage-metering"))}
	w.logger.Info("usage metering aggregator starting")
	go w.run(orgctx.WithBypassRLS(ctx))
}

func (w *meteringWorker) run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	// Run one pass promptly at startup so a restart doesn't stall a window.
	w.aggregateBatch(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Drain fully each tick so a backlog catches up.
			for {
				n, err := w.aggregateBatch(ctx)
				if err != nil {
					w.logger.Warn("usage metering batch failed; will retry", zap.Error(err))
					break
				}
				if n < meteringBatchSize {
					break
				}
			}
		}
	}
}

// aggregateBatch reads the next window of fabric events past the cursor, rolls
// them into daily counters, advances the cursor, and returns the number of rows
// processed.
//
// ONE TRANSACTION, HOLDING THE CURSOR ROW, because this counter is money.
//
// The rollup is an INCREMENT (count = count + 1), not an idempotent write, and
// the cursor was read with no lock. audit-service runs three replicas in
// production and autoscales to ten, so all of them read the same cursor, fetched
// the same batch, incremented every counter, and advanced the cursor to the same
// place: the daily usage a customer is billed from was inflated by the replica
// count. The comment below the fetch used to say "the cursor guarantees each
// event is rolled up at most once", which is true of one process and false of
// three.
//
// The lock is taken on the cursor row rather than through leader.RunPeriodic,
// which is what the rest of this tree uses for periodic sweeps. Leader election
// here runs on Redis, and IsLeaderForTick with no Redis client lets EVERY
// replica run -- acceptable for a sweep that merely repeats work, and not
// acceptable for a counter that must not double-count during a Redis outage.
// The row lock lives in the same database as the number it protects.
//
// SKIP LOCKED rather than waiting: a replica that cannot have the cursor should
// skip this tick, not queue behind a five-hundred-row batch and then run a
// second one immediately.
func (w *meteringWorker) aggregateBatch(ctx context.Context) (int, error) {
	var processed int
	err := w.svc.db.WithTx(ctx, func(tx pgx.Tx) error {
		var err error
		processed, err = w.aggregateLockedBatch(ctx, tx)
		return err
	})
	return processed, err
}

func (w *meteringWorker) aggregateLockedBatch(ctx context.Context, tx pgx.Tx) (int, error) {
	var lastTS time.Time
	var lastID *string
	//orgscope:ignore install-wide billing cursor (runs under bypass_rls) claimed with FOR UPDATE SKIP LOCKED; there is one cursor row for the install
	err := tx.QueryRow(ctx,
		`SELECT last_ts, last_id FROM usage_metering_cursor WHERE id = 1 FOR UPDATE SKIP LOCKED`).
		Scan(&lastTS, &lastID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Either another replica holds the cursor -- the normal case, and this
		// tick is theirs -- or the row is missing, which is an operational
		// problem that must not look like "nothing to do for ever".
		var exists bool
		//orgscope:ignore install-wide billing cursor presence check (runs under bypass_rls)
		if cerr := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM usage_metering_cursor WHERE id = 1)`).Scan(&exists); cerr == nil && !exists {
			w.logger.Error("usage metering cursor row is missing; no fabric usage is being rolled up")
		}
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	lastIDArg := zeroUUID
	if lastID != nil {
		lastIDArg = *lastID
	}

	// Fetch fabric events strictly after the cursor, ordered by (created_at, id)
	// so the cursor is a total order.
	//
	// Org attribution reads the event's own org_id (v142) rather than joining
	// users. That is not just tidier: a fabric event carries a service, not
	// always a user, and the join yielded '' for every user-less one — so
	// overlay traffic on a tenant's own route was billed to the zero-UUID
	// bucket nobody owns. The ingest derives org_id from the route, so those
	// now land on the tenant that ran them.
	//orgscope:ignore install-wide billing rollup running under WithBypassRLS; it must read every org's fabric events to attribute each one, and org_id is selected per row below
	rows, err := tx.Query(ctx, `
        SELECT e.id, e.created_at, e.event_type, COALESCE(e.user_id::text,''),
               e.org_id::text, COALESCE(e.details->>'service',''),
               COALESCE(e.details->>'service_name','')
          FROM unified_audit_events e
         WHERE e.source = 'ziti'
           AND e.event_type IN ('ziti.api_session.created', 'ziti.service.dialed')
           AND (e.created_at, e.id) > ($1, $2::uuid)
         ORDER BY e.created_at ASC, e.id ASC
         LIMIT $3`, lastTS, lastIDArg, meteringBatchSize)
	if err != nil {
		return 0, err
	}

	type row struct {
		id        string
		ts        time.Time
		eventType string
		userID    string
		orgID     string
		service   string
	}
	var batch []row
	for rows.Next() {
		var r row
		var svc1, svc2 string
		if err := rows.Scan(&r.id, &r.ts, &r.eventType, &r.userID, &r.orgID, &svc1, &svc2); err != nil {
			rows.Close()
			return 0, err
		}
		r.service = svc1
		if r.service == "" {
			r.service = svc2
		}
		batch = append(batch, r)
	}
	rows.Close()
	if len(batch) == 0 {
		return 0, nil
	}

	// Upsert each event into its daily counter. The cursor rolls each event up
	// at most once -- which holds because this transaction holds the cursor
	// row, and did not hold before it did.
	for _, r := range batch {
		metric := metricOverlayLogin
		service := ""
		if r.eventType == "ziti.service.dialed" {
			metric = metricServiceDial
			service = r.service
		}
		orgID := r.orgID
		if orgID == "" {
			orgID = zeroUUID
		}
		userID := r.userID
		if userID == "" {
			userID = zeroUUID
		}
		day := r.ts.UTC().Format("2006-01-02")
		if _, err := tx.Exec(ctx, `
            INSERT INTO usage_metering_daily (org_id, user_id, service, metric, day, count)
            VALUES ($1::uuid, $2::uuid, $3, $4, $5::date, 1)
            ON CONFLICT (org_id, user_id, service, metric, day)
            DO UPDATE SET count = usage_metering_daily.count + 1, updated_at = NOW()`,
			orgID, userID, service, metric, day); err != nil {
			return 0, err
		}
	}

	// Advance the cursor to the last event processed.
	last := batch[len(batch)-1]
	if _, err := tx.Exec(ctx,
		//orgscope:ignore install-wide billing cursor advance (runs under bypass_rls) on the row this transaction holds
		`UPDATE usage_metering_cursor SET last_ts = $1, last_id = $2::uuid, updated_at = NOW() WHERE id = 1`,
		last.ts, last.id); err != nil {
		return 0, err
	}

	w.logger.Debug("usage metering batch rolled up", zap.Int("events", len(batch)))
	return len(batch), nil
}
