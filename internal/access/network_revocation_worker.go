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
	rows, err := s.db.Pool.Query(ctx, `
        UPDATE network_revocation_queue q SET state='processing', updated_at=NOW()
         WHERE q.id IN (
             SELECT id FROM network_revocation_queue
              WHERE state='pending'
              ORDER BY id ASC LIMIT 50 FOR UPDATE SKIP LOCKED)
        RETURNING q.id, q.user_id::text, q.reason, COALESCE(q.attribute,'')`)
	if err != nil {
		s.logger.Warn("network revocation: claim failed", zap.Error(err))
		return
	}
	type item struct {
		id        int64
		userID    string
		reason    string
		attribute string
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.userID, &it.reason, &it.attribute); err == nil {
			items = append(items, it)
		}
	}
	rows.Close()

	for _, it := range items {
		// If this intent names a JIT attribute (Wave B1 expiry), remove it from
		// the user's Ziti identity first so the dial closes, then sever any
		// circuits it opened.
		if it.attribute != "" {
			s.removeUserZitiAttribute(ctx, it.userID, it.attribute)
		}
		// severUserZitiCircuits is a best-effort no-op when the overlay is off.
		s.severUserZitiCircuits(ctx, it.userID, "governance:"+it.reason)
		_, _ = s.db.Pool.Exec(ctx,
			`UPDATE network_revocation_queue SET state='done', updated_at=NOW() WHERE id=$1`, it.id)
	}
}
