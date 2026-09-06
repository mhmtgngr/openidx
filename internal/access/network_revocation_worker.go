package access

import (
	"context"
	"time"

	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// Network revocation worker (Wave B2): drains network_revocation_queue, which
// the governance service writes on an access-review/certification revoke or JIT
// expiry, and severs the subject's live Ziti circuits. This completes
// decision-to-packet: the grant is deleted (governance), the Ziti role attribute
// is detached (ziti-user-sync reconcile), and the live circuit is severed here.

// StartNetworkRevocationWorker launches the background drain loop. No-op-safe:
// idle when the queue is empty.
func (s *Service) StartNetworkRevocationWorker(ctx context.Context) {
	go s.runNetworkRevocation(orgctx.WithBypassRLS(ctx))
	s.logger.Info("network revocation worker starting")
}

func (s *Service) runNetworkRevocation(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.drainNetworkRevocations(ctx)
		}
	}
}

func (s *Service) drainNetworkRevocations(ctx context.Context) {
	// Claim a batch atomically so multiple access-service replicas don't collide.
	//orgscope:ignore network hand-off queue drain (runs under bypass_rls): one worker serves the whole install, claims by state and never by tenant, and each claimed row carries its own organization onward
	rows, err := s.db.Pool.Query(ctx, `
        UPDATE network_revocation_queue q SET state='processing', updated_at=NOW()
         WHERE q.id IN (
             SELECT id FROM network_revocation_queue
              WHERE state='pending'
              ORDER BY id ASC LIMIT 50 FOR UPDATE SKIP LOCKED)
        RETURNING q.id, q.user_id::text, q.reason, COALESCE(q.attribute,''),
                  q.attempts, COALESCE(q.org_id::text,'')`)
	if err != nil {
		s.logger.Warn("network revocation: claim failed", zap.Error(err))
		return
	}
	type item struct {
		id        int64
		userID    string
		reason    string
		attribute string
		attempts  int
		orgID     string
	}
	var items []item
	for rows.Next() {
		var it item
		// A dropped row here is a revocation the worker claimed and then forgot,
		// leaving it stuck in 'processing' with the circuit still open. org_id
		// is COALESCEd above for the same reason: v100 left the column nullable,
		// and a legacy NULL-tenant row must still be severed, not skipped.
		if err := rows.Scan(&it.id, &it.userID, &it.reason, &it.attribute, &it.attempts, &it.orgID); err != nil {
			s.logger.Warn("network revocation: claimed item skipped", zap.Error(err))
			continue
		}
		items = append(items, it)
	}
	rows.Close()

	for _, it := range items {
		// If this intent names a JIT attribute (Wave B1 expiry), remove it from
		// the user's Ziti identity first so the dial closes, then sever any
		// circuits it opened.
		//
		// Both of these used to be called for their side effect and the row was
		// then marked 'done' UNCONDITIONALLY -- so an access review revoked a
		// user, governance recorded the revocation, and this queue recorded the
		// severance as done even when the Ziti call failed or the controller was
		// unreachable. The user's live circuit stayed open and every record said
		// it had been cut. The sibling grant worker in the file next to this one
		// already checked its error; this direction did not.
		var failure error
		if it.attribute != "" {
			if err := s.removeUserZitiAttribute(ctx, it.userID, it.attribute); err != nil {
				failure = err
			}
		}
		if err := s.severUserZitiCircuits(ctx, it.userID, "governance:"+it.reason); err != nil && failure == nil {
			failure = err
		}
		if failure != nil {
			s.retryOrDeadLetterNetworkItem(ctx, "network_revocation_queue", it.id, it.attempts,
				it.orgID, it.userID, "reason="+it.reason, failure)
			continue
		}
		_, _ = s.db.Pool.Exec(ctx,
			//orgscope:ignore network hand-off queue drain (runs under bypass_rls) completing an item it already claimed by primary key
			`UPDATE network_revocation_queue SET state='done', updated_at=NOW() WHERE id=$1`, it.id)
	}
}
