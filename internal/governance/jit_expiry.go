package governance

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// StartJITExpirationChecker runs a background goroutine that periodically
// revokes expired JIT (just-in-time) access grants.
func (s *Service) StartJITExpirationChecker(ctx context.Context) {
	ctx = orgctx.WithBypassRLS(ctx)
	s.logger.Info("JIT access expiration checker started")

	// Leader-gated: revoke expired JIT grants once per interval cluster-wide.
	var rdb *redis.Client
	if s.redis != nil {
		rdb = s.redis.Client
	}
	leader.RunPeriodic(ctx, rdb, s.logger, "governance:jit-expiry", 5*time.Minute, s.revokeExpiredJITAccess)
}

// revokeExpiredJITAccess finds fulfilled access requests that have passed their
// expiration time, revokes the granted access, and marks them as expired.
func (s *Service) revokeExpiredJITAccess(ctx context.Context) {
	// Background cross-org sweep: find expired fulfilled requests across all orgs.
	// org_id is selected so each request's revocation/audit writes below stay scoped
	// to its own org (the ticker has no request context to read org from).
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, requester_id, resource_type, resource_id, resource_name, org_id
		 FROM access_requests
		 WHERE status = 'fulfilled' AND expires_at IS NOT NULL AND expires_at < NOW()`)
	if err != nil {
		s.logger.Error("Failed to query expired JIT access requests", zap.Error(err))
		return
	}
	defer rows.Close()

	var revokedCount int
	for rows.Next() {
		var id, requesterID, resourceType, resourceID, resourceName, orgID string
		if err := rows.Scan(&id, &requesterID, &resourceType, &resourceID, &resourceName, &orgID); err != nil {
			s.logger.Error("Failed to scan expired access request", zap.Error(err))
			continue
		}

		// Revoke the granted access based on resource type
		switch resourceType {
		case "role":
			_, err := s.db.Pool.Exec(ctx,
				`DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2 AND org_id = $3`,
				requesterID, resourceID, orgID)
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
				`DELETE FROM group_memberships WHERE user_id = $1 AND group_id = $2 AND org_id = $3`,
				requesterID, resourceID, orgID)
			if err != nil {
				s.logger.Error("Failed to revoke expired group membership",
					zap.String("request_id", id),
					zap.String("user_id", requesterID),
					zap.String("group_id", resourceID),
					zap.Error(err))
				continue
			}
		case "vault_credential":
			// Reveal grant auto-expires via its expires_at; here we only wake the
			// M1b rotation scheduler so the credential rotates on the next tick.
			if _, err := s.db.Pool.Exec(ctx,
				//orgscope:ignore background sweep across orgs; bounded by the row being expired
				`UPDATE credential_rotation_policies SET next_run_at = NOW()
				 WHERE secret_id = $1 AND rotate_on_checkout = true`, resourceID); err != nil {
				s.logger.Warn("vault_credential rotate-on-return bump failed",
					zap.String("secret_id", resourceID), zap.Error(err))
			}
			// Specific audit event for vault credential checkout expiry.
			credExpDetails, _ := json.Marshal(map[string]string{
				"request_id":    id,
				"resource_name": resourceName,
			})
			//orgscope:ignore background sweep across orgs; bounded by the row being expired
			if _, err := s.db.Pool.Exec(ctx,
				`INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, actor_ip, target_id, target_type, details, created_at, org_id)
				 VALUES (gen_random_uuid(), 'access', 'provisioning', 'jit_credential.checkout_expired', 'success', $1, '0.0.0.0', $2, 'vault_credential', $3, NOW(), $4)`,
				requesterID, resourceID, string(credExpDetails), orgID); err != nil {
				s.logger.Warn("Failed to write jit_credential.checkout_expired audit event",
					zap.String("request_id", id), zap.Error(err))
			}
		default:
			s.logger.Warn("No revocation handler for resource type",
				zap.String("resource_type", resourceType))
		}

		// Mark the access request as expired
		_, err := s.db.Pool.Exec(ctx,
			`UPDATE access_requests SET status = 'expired', updated_at = NOW() WHERE id = $1 AND org_id = $2`, id, orgID)
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
		if _, err := s.db.Pool.Exec(ctx,
			`INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, actor_ip, target_id, target_type, details, created_at, org_id)
			 VALUES (gen_random_uuid(), 'access', 'provisioning', 'jit_access_expired', 'success', $1, '0.0.0.0', $2, $3, $4, NOW(), $5)`,
			requesterID, resourceID, resourceType, string(details), orgID); err != nil {
			s.logger.Warn("Failed to write jit_access_expired audit event",
				zap.String("request_id", id), zap.Error(err))
		}

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
