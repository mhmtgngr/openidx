package admin

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// systemActorID is the actor recorded on data_subject_requests.processed_by
// when an automated processor (rather than a logged-in admin) executes a
// DSAR. Distinguishable in the audit trail from any real user id (which is
// a UUID).
const systemActorID = "system-dsar-processor"

// dsarAutoExecutableTypes is the allow-list of DSAR types the background
// processor will run unattended. We auto-execute `export` because it's
// non-destructive — the subject is just receiving their own data — and
// because the longer it sits in `pending` the worse our GDPR Article 12
// "without undue delay" obligation looks.
//
// `delete` and `restrict` deliberately stay manual: they change account
// state irreversibly (or visibly), and the operator should sign off on the
// exact moment they happen. A misfiring scheduler that wiped accounts on
// its own would be a far worse incident than a few hours of latency on
// admin click-through.
var dsarAutoExecutableTypes = map[string]struct{}{
	"export": {},
}

// StartDSARProcessor starts a background goroutine that periodically picks
// up pending DSARs and executes them. Modeled after the existing
// `StartRoleExpirationChecker` pattern in internal/identity, so the cmd/
// wiring is a single one-line call alongside the other background workers.
//
// The processor only auto-executes the types in `dsarAutoExecutableTypes`;
// destructive types (delete, restrict) stay manual and the processor logs
// a count of how many were skipped so admins can spot a queue building up.
func (s *Service) StartDSARProcessor(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		s.logger.Info("DSAR processor started",
			zap.Duration("interval", interval),
			zap.Any("auto_execute_types", keys(dsarAutoExecutableTypes)))
		// Process once on startup so a restarted service drains the backlog
		// immediately rather than waiting a full interval.
		s.processPendingDSARs(ctx)
		for {
			select {
			case <-ctx.Done():
				s.logger.Info("DSAR processor stopped")
				return
			case <-ticker.C:
				s.processPendingDSARs(ctx)
			}
		}
	}()
}

// processPendingDSARs is the per-tick body: enumerate pending requests,
// execute the auto-runnable ones, record stats. Each request runs against
// a per-iteration context with a generous timeout so a slow DB query on
// one request can't wedge the processor.
func (s *Service) processPendingDSARs(ctx context.Context) {
	tickCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	rows, err := s.db.Pool.Query(tickCtx,
		`SELECT id, user_id, request_type FROM data_subject_requests
		 WHERE status = 'pending'
		 ORDER BY created_at ASC
		 LIMIT 100`)
	if err != nil {
		s.logger.Error("DSAR processor: failed to list pending requests", zap.Error(err))
		return
	}
	defer rows.Close()

	type job struct {
		id, userID, requestType string
	}
	var batch []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.id, &j.userID, &j.requestType); err != nil {
			s.logger.Warn("DSAR processor: failed to scan pending row", zap.Error(err))
			continue
		}
		batch = append(batch, j)
	}
	if err := rows.Err(); err != nil {
		s.logger.Warn("DSAR processor: row iteration error", zap.Error(err))
	}
	// Release the rows iterator before we start kicking off per-request
	// work — each execute call runs more queries against the same pool.
	rows.Close()

	if len(batch) == 0 {
		return
	}

	var executed, skipped, failed int
	for _, j := range batch {
		if _, autoOK := dsarAutoExecutableTypes[j.requestType]; !autoOK {
			skipped++
			continue
		}
		// Re-fetch the full DSAR row for the executor — its delete/export
		// helpers want a *DataSubjectRequest with the same shape as the
		// gin handler path.
		dsar := DataSubjectRequest{
			ID:          j.id,
			UserID:      j.userID,
			RequestType: j.requestType,
			Status:      "pending",
		}
		// Use a per-request context with a shorter deadline so one stuck
		// request can't burn the whole tick budget.
		reqCtx, reqCancel := context.WithTimeout(ctx, 2*time.Minute)
		_, err := s.ExecuteDSAR(reqCtx, &dsar, systemActorID)
		reqCancel()
		if err != nil {
			failed++
			s.logger.Error("DSAR processor: execution failed",
				zap.String("dsar_id", j.id),
				zap.String("user_id", j.userID),
				zap.String("request_type", j.requestType),
				zap.Error(err))
			continue
		}
		executed++
	}

	s.logger.Info("DSAR processor tick",
		zap.Int("pending_seen", len(batch)),
		zap.Int("executed", executed),
		zap.Int("skipped_for_manual_review", skipped),
		zap.Int("failed", failed))
}

// keys returns the keys of a set-shaped map as a slice for logging.
func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
