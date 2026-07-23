package access

import (
	"context"
	"time"

	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// JIT network grant worker (Wave B1): drains network_grant_queue, which the
// governance service writes when a network_service access request is fulfilled,
// and adds the time-bound Ziti role attribute to the requester's identity so the
// dial opens. Expiry removal is handled by the network revocation worker via the
// attribute column (Wave B2 path).

// StartNetworkGrantWorker launches the grant drain loop. No-op-safe: idle when
// the queue is empty or the overlay is off.
func (s *Service) StartNetworkGrantWorker(ctx context.Context) {
	go s.runNetworkGrant(orgctx.WithBypassRLS(ctx))
	s.logger.Info("network grant worker starting")
}

func (s *Service) runNetworkGrant(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.drainNetworkGrants(ctx)
		}
	}
}

func (s *Service) drainNetworkGrants(ctx context.Context) {
	rows, err := s.db.Pool.Query(ctx, `
        UPDATE network_grant_queue q SET state='processing', updated_at=NOW()
         WHERE q.id IN (
             SELECT id FROM network_grant_queue
              WHERE state='pending'
              ORDER BY id ASC LIMIT 50 FOR UPDATE SKIP LOCKED)
        RETURNING q.id, q.user_id::text, q.attribute`)
	if err != nil {
		s.logger.Warn("network grant: claim failed", zap.Error(err))
		return
	}
	type item struct {
		id        int64
		userID    string
		attribute string
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.userID, &it.attribute); err == nil {
			items = append(items, it)
		}
	}
	rows.Close()

	for _, it := range items {
		if err := s.addUserZitiAttribute(ctx, it.userID, it.attribute); err != nil {
			s.logger.Warn("network grant: apply attribute failed",
				zap.String("user_id", it.userID), zap.String("attr", it.attribute), zap.Error(err))
			_, _ = s.db.Pool.Exec(ctx,
				`UPDATE network_grant_queue SET state='failed', last_error=$2, updated_at=NOW() WHERE id=$1`,
				it.id, err.Error())
			continue
		}
		_, _ = s.db.Pool.Exec(ctx,
			`UPDATE network_grant_queue SET state='done', updated_at=NOW() WHERE id=$1`, it.id)
	}
}

// addUserZitiAttribute adds a role attribute to the user's Ziti identity
// (idempotent set union). No-op when the overlay is off.
func (s *Service) addUserZitiAttribute(ctx context.Context, userID, attribute string) error {
	zm := s.ziti()
	if zm == nil || userID == "" || attribute == "" {
		return nil
	}
	zitiID := s.userZitiID(ctx, userID)
	if zitiID == "" {
		return nil // user has no overlay identity yet; nothing to grant
	}
	attrs, err := zm.GetIdentityRoleAttributes(ctx, zitiID)
	if err != nil {
		return err
	}
	for _, a := range attrs {
		if a == attribute {
			return nil // already present
		}
	}
	return zm.PatchIdentityRoleAttributes(ctx, zitiID, append(attrs, attribute))
}

// removeUserZitiAttribute removes a role attribute from the user's Ziti identity
// (idempotent set difference). No-op when the overlay is off.
func (s *Service) removeUserZitiAttribute(ctx context.Context, userID, attribute string) {
	zm := s.ziti()
	if zm == nil || userID == "" || attribute == "" {
		return
	}
	zitiID := s.userZitiID(ctx, userID)
	if zitiID == "" {
		return
	}
	attrs, err := zm.GetIdentityRoleAttributes(ctx, zitiID)
	if err != nil {
		s.logger.Warn("network grant: read attributes failed",
			zap.String("ziti_id", zitiID), zap.Error(err))
		return
	}
	next := make([]string, 0, len(attrs))
	removed := false
	for _, a := range attrs {
		if a == attribute {
			removed = true
			continue
		}
		next = append(next, a)
	}
	if !removed {
		return
	}
	if err := zm.PatchIdentityRoleAttributes(ctx, zitiID, next); err != nil {
		s.logger.Warn("network grant: remove attribute failed",
			zap.String("ziti_id", zitiID), zap.String("attr", attribute), zap.Error(err))
	}
}

// userZitiID resolves the user's Ziti controller identity id.
func (s *Service) userZitiID(ctx context.Context, userID string) string {
	var zitiID string
	if err := s.db.Pool.QueryRow(ctx,
		//orgscope:ignore JIT network grant; resolves the request user's own Ziti identity by user_id on the grant/revocation worker
		`SELECT ziti_id FROM ziti_identities WHERE user_id = $1 LIMIT 1`, userID).Scan(&zitiID); err != nil {
		return ""
	}
	return zitiID
}
