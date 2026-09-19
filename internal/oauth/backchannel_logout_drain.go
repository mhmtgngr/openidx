package oauth

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// THE DRAINER: the half of sessionend that holds the key.
//
// A path in another binary ended a session and, before its own statement ran,
// captured the session's tenant, user, id and candidate clients into
// backchannel_logout_pending (migration v198, internal/common/sessionend).
// This resolves each capture against the tenant's registered
// back_channel_logout_uri values and delivers through the same
// deliverBackchannelTargets the in-process funnel uses, so a relying party is
// told the same way whichever binary ended the session.
//
// It is the SSF signal drainer's shape -- ticker, claim with UPDATE ...
// RETURNING under SKIP LOCKED, no leader -- for the same reason: the row lock
// IS the coordination, any number of replicas drain safely, and a leader would
// add an availability gap for an ordering guarantee nobody asked for.
//
// AT-LEAST-ONCE, in the stated direction. The row is marked published after
// delivery; a crash between the two re-drains it and a relying party may see
// one logout token twice. Back-Channel Logout 1.0 §2.6 requires the RP to
// treat a repeated jti as already handled, and telling a relying party twice
// that a session ended is harmless where telling it never is the defect this
// seam exists to remove. Delivery itself is one attempt per claim, as it is
// from the funnel: a relying party that refuses is counted as failed and the
// row is done; attempts bounds only how often a row whose delivery could not
// even be attempted (a database error mid-batch) is retried.

const (
	backchannelDrainBatch      = 50
	backchannelDrainMaxAttempt = 10
	backchannelDrainStaleAfter = 5 * time.Minute
)

// StartBackchannelLogoutDrainer starts the background drain. It runs under
// bypass-RLS the way StartSSFSignalDrainer does: one worker serves every
// tenant, and each claimed row carries its own org_id onward into the
// resolution and the audit record.
func (s *Service) StartBackchannelLogoutDrainer(ctx context.Context) {
	go s.runBackchannelLogoutDrain(orgctx.WithBypassRLS(ctx))
	s.logger.Info("back-channel logout drainer starting")
}

func (s *Service) runBackchannelLogoutDrain(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				n, err := s.drainBackchannelLogouts(ctx)
				if err != nil {
					s.logger.Warn("back-channel logout drain failed; the rows stay pending and are retried", zap.Error(err))
					break
				}
				if n == 0 {
					break
				}
			}
		}
	}
}

type pendingBackchannelLogout struct {
	id        int64
	orgID     string
	sessionID string
	userID    string
	clientIDs []string
}

// drainBackchannelLogouts claims one batch, announces each capture, and
// marks each published with what the fan-out achieved. It returns how many
// rows it claimed, so the caller keeps draining while the backlog is deep and
// sleeps when it is not.
func (s *Service) drainBackchannelLogouts(ctx context.Context) (int, error) {
	// A drainer that died mid-batch left rows claimed and unpublished. After
	// the grace they are anybody's again; attempts already counted the try.
	if _, err := s.db.Pool.Exec(ctx, `
		--orgscope:ignore install-wide drain: rows are handed back by state alone, never by org
		UPDATE backchannel_logout_pending SET claimed_at = NULL
		 WHERE published_at IS NULL AND claimed_at IS NOT NULL AND claimed_at < NOW() - $1::interval`,
		backchannelDrainStaleAfter.String()); err != nil {
		return 0, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		--orgscope:ignore install-wide drain: one worker serves every tenant, claims by state alone, and each claimed row carries its own org_id onward
		UPDATE backchannel_logout_pending p SET claimed_at = NOW(), attempts = attempts + 1
		 WHERE p.id IN (
		     SELECT id FROM backchannel_logout_pending
		      WHERE published_at IS NULL AND claimed_at IS NULL AND attempts < $2
		      ORDER BY id ASC LIMIT $1 FOR UPDATE SKIP LOCKED)
		RETURNING p.id, p.org_id::text, p.session_id::text, p.user_id::text, p.client_ids`,
		backchannelDrainBatch, backchannelDrainMaxAttempt)
	if err != nil {
		return 0, err
	}
	var batch []pendingBackchannelLogout
	for rows.Next() {
		var p pendingBackchannelLogout
		if err := rows.Scan(&p.id, &p.orgID, &p.sessionID, &p.userID, &p.clientIDs); err != nil {
			rows.Close()
			return 0, err
		}
		batch = append(batch, p)
	}
	rows.Close()

	for _, p := range batch {
		targets, err := s.resolveBackchannelTargets(ctx, p.orgID, p.userID, p.sessionID, p.clientIDs)
		if err != nil {
			// Not marked: the resolution itself failed (a database error), so
			// the row is handed back after the grace and tried again, up to
			// the attempts bound.
			s.logger.Warn("back-channel logout drain: could not resolve relying parties; the row stays pending",
				zap.Int64("id", p.id), zap.Error(err))
			continue
		}
		delivered, failed := s.deliverBackchannelTargets(ctx, targets)
		if s.backchannelObserver != nil {
			s.backchannelObserver(p.sessionID, delivered, failed)
		}
		if _, err := s.db.Pool.Exec(ctx, `
			--orgscope:ignore marking a row this drain already claimed above, addressed by its own id
			UPDATE backchannel_logout_pending SET published_at = NOW(), delivered = $2, failed = $3 WHERE id = $1`,
			p.id, delivered, failed); err != nil {
			// The tokens are sent; the row will be re-drained and they will be
			// sent again. That is the at-least-once direction, chosen above.
			s.logger.Warn("back-channel logouts delivered but the row was not marked published; it will be announced again",
				zap.Int64("id", p.id), zap.Error(err))
		}
	}
	return len(batch), nil
}
