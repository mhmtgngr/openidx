package vault

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// StartSweeper marks active checkouts past their expires_at as expired. Leader-
// gated so it runs once per interval cluster-wide. Runs under bypass-RLS since
// it sweeps across all orgs.
func (s *Service) StartSweeper(ctx context.Context, rdb *redis.Client) {
	ctx = orgctx.WithBypassRLS(ctx)
	s.logger.Info("Starting vault checkout sweeper")
	leader.RunPeriodic(ctx, rdb, s.logger, "vault:checkout-expiry", 60*time.Second, s.expireCheckouts)
}

func (s *Service) expireCheckouts(ctx context.Context) {
	ct, err := s.db.Pool.Exec(ctx,
		//orgscope:ignore background ticker expiring reveal leases across all orgs; no request/tenant context
		`UPDATE vault_checkouts SET status = 'expired'
		 WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= NOW()`)
	if err != nil {
		s.logger.Error("vault checkout sweep failed", zap.Error(err))
		return
	}
	if n := ct.RowsAffected(); n > 0 {
		s.logger.Info("Expired vault reveal leases", zap.Int64("count", n))
	}
}
