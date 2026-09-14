package access

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// EDR ingestion worker: periodically polls every enabled EDR/MDM source that is
// due (per its poll_interval_minutes) and runs a sync pass. Each pass writes
// posture results the existing Ziti enforcement acts on. Idle when no sources
// are configured.

// StartEDRIngestionWorker launches the background poller. Bypasses RLS so it can
// drain sources across orgs.
//
// LEADER-GATED, and it was not. This swept on a bare ticker in every replica,
// which multiplied the poll interval an operator configured by the replica
// count: access-service ships at two replicas and autoscales to eight in
// production, so a source set to poll every five minutes called the customer's
// CrowdStrike, Intune or Jamf tenant two to eight times in that window. The
// sweep claims nothing -- it selects sources whose last_sync_at is older than
// their interval and syncs them, and last_sync_at is only written when the sync
// FINISHES, so every replica sees the same source as due in the same minute.
//
// The cost is not only wasted calls. These are third-party APIs with their own
// rate limits, spent on the customer's quota, and each sync writes posture
// results that the Ziti enforcement path reads to revoke access.
//
// Twelve other periodic sweeps in this tree already run through
// leader.RunPeriodic; this one, the ES reconciler and the Guacamole audit sync
// were the three that did not. Nothing about them was special.
func (s *Service) StartEDRIngestionWorker(ctx context.Context) {
	ctx = orgctx.WithBypassRLS(ctx)
	var rdb *redis.Client
	if s.redis != nil {
		rdb = s.redis.Client
	}
	s.logger.Info("EDR ingestion worker starting")
	// Check for due sources every minute; each source runs on its own interval.
	leader.RunPeriodic(ctx, rdb, s.logger, "access:edr-ingestion", 1*time.Minute, s.runDueEDRSources)
}

// runDueEDRSources syncs every enabled source whose last_sync_at is older than
// its poll interval (or has never synced).
func (s *Service) runDueEDRSources(ctx context.Context) {
	//orgscope:ignore install-wide poll sweep (runs under bypass_rls): a source the sweep cannot see never polls, and a device that stops reporting must still age out to failing; each source's own organization then scopes everything the sync does
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
