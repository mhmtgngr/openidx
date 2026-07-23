package audit

import (
	"context"
	"time"

	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
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
func (w *meteringWorker) aggregateBatch(ctx context.Context) (int, error) {
	var lastTS time.Time
	var lastID *string
	if err := w.svc.db.Pool.QueryRow(ctx,
		`SELECT last_ts, last_id FROM usage_metering_cursor WHERE id = 1`).
		Scan(&lastTS, &lastID); err != nil {
		return 0, err
	}
	lastIDArg := zeroUUID
	if lastID != nil {
		lastIDArg = *lastID
	}

	// Fetch fabric events strictly after the cursor, ordered by (created_at, id)
	// so the cursor is a total order. Join users for org attribution.
	rows, err := w.svc.db.Pool.Query(ctx, `
        SELECT e.id, e.created_at, e.event_type, COALESCE(e.user_id::text,''),
               COALESCE(u.org_id::text,''), COALESCE(e.details->>'service',''),
               COALESCE(e.details->>'service_name','')
          FROM unified_audit_events e
          LEFT JOIN users u ON u.id = e.user_id
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

	// Upsert each event into its daily counter. Small batches keep this simple;
	// the cursor guarantees each event is rolled up at most once.
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
		if _, err := w.svc.db.Pool.Exec(ctx, `
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
	if _, err := w.svc.db.Pool.Exec(ctx,
		`UPDATE usage_metering_cursor SET last_ts = $1, last_id = $2::uuid, updated_at = NOW() WHERE id = 1`,
		last.ts, last.id); err != nil {
		return 0, err
	}

	w.logger.Debug("usage metering batch rolled up", zap.Int("events", len(batch)))
	return len(batch), nil
}
