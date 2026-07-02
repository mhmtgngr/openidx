package credentials

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// StartScheduler starts the leader-gated background scheduler that triggers
// due rotation policies on an interval. interval <= 0 defaults to 60s.
func (s *Service) StartScheduler(ctx context.Context, rdb *redis.Client, interval time.Duration) {
	ctx = orgctx.WithBypassRLS(ctx)
	if interval <= 0 {
		interval = 60 * time.Second
	}
	s.logger.Info("Starting credential rotation scheduler")
	leader.RunPeriodic(ctx, rdb, s.logger, "credentials:rotation", interval, s.tick)
}

func (s *Service) tick(ctx context.Context) {
	ids, err := s.dueUnsafe(ctx)
	if err != nil {
		s.logger.Error("rotation scheduler due-scan failed", zap.Error(err))
		return
	}
	for _, p := range ids {
		if err := s.RotateSecret(ctx, p.policyID, p.trigger); err != nil {
			s.logger.Error("scheduled rotation failed", zap.String("policy_id", p.policyID), zap.Error(err))
		}
	}
}

type duePolicy struct {
	policyID string
	trigger  string
}

// DuePolicies returns the IDs of policies that are currently due for rotation,
// pairing each with its trigger reason ("scheduled" or "checkout"). This is a
// thin exported wrapper around dueUnsafe intended for testing. The caller is
// responsible for providing a bypass-RLS context when querying across orgs.
func (s *Service) DuePolicies(ctx context.Context) ([]string, error) {
	due, err := s.dueUnsafe(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(due))
	for i, d := range due {
		ids[i] = d.policyID
	}
	return ids, nil
}

// dueUnsafe returns policies whose interval is due OR whose rotate_on_checkout is set and a
// checkout concluded since last_run_at. Runs under bypass (background, cross-org).
func (s *Service) dueUnsafe(ctx context.Context) ([]duePolicy, error) {
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore background rotation scheduler scans due policies across all orgs; no request/tenant context
		`SELECT p.id,
		        CASE WHEN p.interval_seconds > 0 AND (p.next_run_at IS NULL OR p.next_run_at <= NOW())
		             THEN 'scheduled' ELSE 'checkout' END AS trigger
		 FROM credential_rotation_policies p
		 WHERE p.enabled AND (
		   (p.interval_seconds > 0 AND (p.next_run_at IS NULL OR p.next_run_at <= NOW()))
		   OR (p.rotate_on_checkout AND EXISTS (
		         SELECT 1 FROM vault_checkouts c
		         WHERE c.secret_id = p.secret_id
		           AND c.status IN ('returned','expired')
		           AND COALESCE(c.returned_at, c.leased_at) > COALESCE(p.last_run_at, 'epoch'::timestamptz)))
		 )
		 LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []duePolicy
	for rows.Next() {
		var d duePolicy
		if err := rows.Scan(&d.policyID, &d.trigger); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
