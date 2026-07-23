package access

import (
	"context"
	"time"

	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// EDR ingestion worker: periodically polls every enabled EDR/MDM source that is
// due (per its poll_interval_minutes) and runs a sync pass. Each pass writes
// posture results the existing Ziti enforcement acts on. Idle when no sources
// are configured.

// StartEDRIngestionWorker launches the background poller. Bypasses RLS so it can
// drain sources across orgs.
func (s *Service) StartEDRIngestionWorker(ctx context.Context) {
	go s.runEDRIngestion(orgctx.WithBypassRLS(ctx))
	s.logger.Info("EDR ingestion worker starting")
}

func (s *Service) runEDRIngestion(ctx context.Context) {
	// Check for due sources every minute; each source runs on its own interval.
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runDueEDRSources(ctx)
		}
	}
}

// runDueEDRSources syncs every enabled source whose last_sync_at is older than
// its poll interval (or has never synced).
func (s *Service) runDueEDRSources(ctx context.Context) {
	rows, err := s.db.Pool.Query(ctx, `
        SELECT id::text FROM edr_posture_sources
         WHERE enabled
           AND posture_check_id IS NOT NULL
           AND (last_sync_at IS NULL
                OR last_sync_at < NOW() - (poll_interval_minutes || ' minutes')::interval)`)
	if err != nil {
		s.logger.Warn("EDR ingestion: query due sources failed", zap.Error(err))
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()

	for _, id := range ids {
		if _, err := s.syncEDRSource(ctx, id); err != nil {
			s.logger.Warn("EDR ingestion: source sync failed",
				zap.String("source", id), zap.Error(err))
		}
	}
}
