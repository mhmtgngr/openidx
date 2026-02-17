package governance

import (
	"context"
	"encoding/json"
	"time"

	"go.uber.org/zap"
)

// StartJITExpirationChecker runs a background goroutine that periodically
// revokes expired JIT (just-in-time) access grants.
func (s *Service) StartJITExpirationChecker(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		s.logger.Info("JIT access expiration checker started")

		for {
			select {
			case <-ctx.Done():
				s.logger.Info("JIT access expiration checker stopped")
				return
			case <-ticker.C:
				s.revokeExpiredJITAccess(ctx)
			}
		}
	}()
}

// revokeExpiredJITAccess finds fulfilled access requests that have passed their
// expiration time, revokes the granted access, and marks them as expired.
func (s *Service) revokeExpiredJITAccess(ctx context.Context) {
	// Find all fulfilled requests that have expired
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, requester_id, resource_type, resource_id, resource_name
		 FROM access_requests
		 WHERE status = 'fulfilled' AND expires_at IS NOT NULL AND expires_at < NOW()`)
	if err != nil {
		s.logger.Error("Failed to query expired JIT access requests", zap.Error(err))
		return
	}
	defer rows.Close()

	var revokedCount int
	for rows.Next() {
		var id, requesterID, resourceType, resourceID, resourceName string
		if err := rows.Scan(&id, &requesterID, &resourceType, &resourceID, &resourceName); err != nil {
			s.logger.Error("Failed to scan expired access request", zap.Error(err))
			continue
		}

		// Revoke the granted access based on resource type
		switch resourceType {
		case "role":
			_, err := s.db.Pool.Exec(ctx,
				`DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`,
				requesterID, resourceID)
			if err != nil {
				s.logger.Error("Failed to revoke expired role assignment",
					zap.String("request_id", id),
					zap.String("user_id", requesterID),
					zap.String("role_id", resourceID),
					zap.Error(err))
				continue
			}
		case "group":
			_, err := s.db.Pool.Exec(ctx,
				`DELETE FROM group_memberships WHERE user_id = $1 AND group_id = $2`,
				requesterID, resourceID)
			if err != nil {
				s.logger.Error("Failed to revoke expired group membership",
					zap.String("request_id", id),
					zap.String("user_id", requesterID),
					zap.String("group_id", resourceID),
					zap.Error(err))
				continue
			}
		default:
			s.logger.Warn("No revocation handler for resource type",
				zap.String("resource_type", resourceType))
		}

		// Mark the access request as expired
		_, err := s.db.Pool.Exec(ctx,
			`UPDATE access_requests SET status = 'expired', updated_at = NOW() WHERE id = $1`, id)
		if err != nil {
			s.logger.Error("Failed to mark access request as expired",
				zap.String("request_id", id),
				zap.Error(err))
			continue
		}

		// Insert audit event
		details, _ := json.Marshal(map[string]string{
			"request_id":    id,
			"resource_name": resourceName,
		})
		s.db.Pool.Exec(ctx,
			`INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, ip_address, target_id, target_type, details, created_at)
			 VALUES (gen_random_uuid(), 'access', 'provisioning', 'jit_access_expired', 'success', $1, '0.0.0.0', $2, $3, $4, NOW())`,
			requesterID, resourceID, resourceType, string(details))

		revokedCount++
		s.logger.Info("Revoked expired JIT access",
			zap.String("request_id", id),
			zap.String("user_id", requesterID),
			zap.String("resource_type", resourceType),
			zap.String("resource_name", resourceName))
	}

	if revokedCount > 0 {
		s.logger.Info("JIT expiration check complete",
			zap.Int("revoked_count", revokedCount))
	}

	// Also clean up expired temp access links
	result, err := s.db.Pool.Exec(ctx,
		`UPDATE temp_access_links SET status = 'expired' WHERE status = 'active' AND expires_at < NOW()`)
	if err != nil {
		s.logger.Error("Failed to expire temp access links", zap.Error(err))
	} else if result.RowsAffected() > 0 {
		s.logger.Info("Expired temp access links",
			zap.Int64("count", result.RowsAffected()))
	}
}
