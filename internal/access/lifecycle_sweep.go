// Package access — cross-pillar lifecycle enforcement sweep.
//
// The PAM counterpart to ziti_user_sync.go's runDeprovisionSweep: where that
// sweep tears down Ziti identities of disabled/deleted IAM users, this one
// tears down their live *privileged* access. Identity's deprovisionUser
// already revokes PAM state inline on the API disable path; this sweep is the
// reconcile net for every other way a user can end up disabled (SCIM
// deactivation, directory sync, lifecycle policies, direct DB changes) — and
// it is the only place that can terminate a live Guacamole session, because
// the Guacamole client lives in the access-service.
//
// Together the three enforcement layers make the IAM⇄PAM⇄Ziti relation hold
// under all paths:
//
//	disable via API   → identity deprovisionUser (inline, immediate)
//	any disable path  → this sweep (PAM, ≤1 tick) + ziti deprovision sweep (network, ≤1 tick)
//	admin kill switch → kill_switch.go (all pillars, synchronous)
package access

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// StartLifecycleEnforcement starts the background sweep. Interval should match
// the Ziti user-sync poller (30s) so both halves of the deprovision converge
// within one tick.
func (s *Service) StartLifecycleEnforcement(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ctx = orgctx.WithBypassRLS(ctx)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		s.logger.Info("Cross-pillar lifecycle enforcement sweep started",
			zap.Duration("interval", interval))

		for {
			select {
			case <-ctx.Done():
				s.logger.Info("Lifecycle enforcement sweep stopped")
				return
			case <-ticker.C:
				s.runLifecycleEnforcement(ctx)
			}
		}
	}()
}

// runLifecycleEnforcement revokes live PAM access held by users who are
// disabled or deleted. Idempotent: every statement only touches still-active
// rows, so repeat ticks (or replicas racing) are harmless.
func (s *Service) runLifecycleEnforcement(ctx context.Context) {
	// Vault checkouts whose principal is disabled or gone.
	if tag, err := s.db.Pool.Exec(ctx,
		//orgscope:ignore install-wide lifecycle reconcile sweep (disabled/deleted users -> PAM teardown), same posture as the ziti deprovision sweep
		`UPDATE vault_checkouts vc SET status = 'revoked', returned_at = NOW()
		  WHERE vc.status = 'active' AND vc.principal_id IS NOT NULL
		    AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = vc.principal_id AND u.enabled = true)`); err != nil {
		s.logger.Warn("lifecycle sweep: vault checkout revocation failed", zap.Error(err))
	} else if n := tag.RowsAffected(); n > 0 {
		s.logger.Info("lifecycle sweep: revoked vault checkouts of disabled users", zap.Int64("count", n))
	}

	// Direct user vault grants of disabled/deleted principals.
	if tag, err := s.db.Pool.Exec(ctx,
		//orgscope:ignore install-wide lifecycle reconcile sweep (disabled/deleted users -> PAM teardown)
		`UPDATE vault_access_grants vg SET expires_at = NOW()
		  WHERE vg.principal_type = 'user'
		    AND (vg.expires_at IS NULL OR vg.expires_at > NOW())
		    AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = vg.principal_id AND u.enabled = true)`); err != nil {
		s.logger.Warn("lifecycle sweep: vault grant expiry failed", zap.Error(err))
	} else if n := tag.RowsAffected(); n > 0 {
		s.logger.Info("lifecycle sweep: expired vault grants of disabled users", zap.Int64("count", n))
	}

	// JIT elevations of disabled users (deleted users cascade via FK).
	if tag, err := s.db.Pool.Exec(ctx,
		//orgscope:ignore install-wide lifecycle reconcile sweep (disabled/deleted users -> PAM teardown)
		`UPDATE jit_grants jg SET status = 'revoked', revoked_at = NOW(), updated_at = NOW()
		  WHERE jg.status = 'active'
		    AND EXISTS (SELECT 1 FROM users u WHERE u.id = jg.user_id AND u.enabled = false)`); err != nil {
		s.logger.Warn("lifecycle sweep: jit grant revocation failed", zap.Error(err))
	} else if n := tag.RowsAffected(); n > 0 {
		s.logger.Info("lifecycle sweep: revoked JIT grants of disabled users", zap.Int64("count", n))
	}

	// Live privileged sessions of disabled/deleted users. Rows are marked
	// terminated only after Guacamole confirms the kill, so a configured-but-
	// unreachable Guacamole retries next tick instead of silently "succeeding".
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore install-wide lifecycle reconcile sweep (disabled/deleted users -> PAM teardown)
		`SELECT gs.id, COALESCE(gs.guac_session_uuid, ''), gs.user_id
		   FROM guacamole_sessions gs
		   LEFT JOIN users u ON u.id = gs.user_id
		  WHERE gs.status = 'active' AND gs.user_id IS NOT NULL
		    AND (u.id IS NULL OR u.enabled = false)
		  LIMIT 20`)
	if err != nil {
		s.logger.Warn("lifecycle sweep: guacamole session query failed", zap.Error(err))
		return
	}
	type sess struct{ rowID, uuid, userID string }
	var doomed []sess
	for rows.Next() {
		var d sess
		if err := rows.Scan(&d.rowID, &d.uuid, &d.userID); err == nil {
			doomed = append(doomed, d)
		}
	}
	rows.Close()

	if len(doomed) == 0 {
		return
	}
	if s.guacamoleClient == nil {
		s.logger.Warn("lifecycle sweep: active privileged sessions belong to disabled users but Guacamole is not configured",
			zap.Int("count", len(doomed)))
		return
	}

	for _, d := range doomed {
		if d.uuid != "" {
			if err := s.guacamoleClient.TerminateSession(ctx, d.uuid); err != nil {
				s.logger.Warn("lifecycle sweep: guacamole terminate failed (will retry next tick)",
					zap.String("user_id", d.userID), zap.Error(err))
				continue
			}
		}
		if _, err := s.db.Pool.Exec(ctx,
			//orgscope:ignore keyed by primary key resolved from the annotated install-wide sweep above
			`UPDATE guacamole_sessions SET status = 'terminated', ended_at = NOW()
			  WHERE id = $1 AND status = 'active'`, d.rowID); err != nil {
			s.logger.Warn("lifecycle sweep: session row update failed", zap.Error(err))
			continue
		}
		s.logger.Info("lifecycle sweep: terminated privileged session of disabled user",
			zap.String("user_id", d.userID))
	}
}
