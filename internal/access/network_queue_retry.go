package access

import (
	"context"
	"encoding/json"

	"go.uber.org/zap"
)

// Retry and dead-lettering for the two network hand-off queues, migration v166.
//
// v100 and v101 both gave their queue an `attempts` column and a `failed`
// state, and neither worker ever incremented the one or gave the other a
// reader. So a single transient controller error lost a grant or a revocation
// permanently, and the row recording that loss was one nothing in the tree ever
// selects: no handler, no console page, no alert. An administrator approving a
// network access request saw "granted" while the attribute was never added.
//
// The retry uses the column that was already there. The dead-letter writes an
// audit event under the queue row's own organization, which is what finally
// gives `failed` a reader — on a surface that is org-scoped and belted already.

// networkQueueMaxAttempts bounds the retry. Both workers tick on a short
// interval (10s and 15s), so this is roughly a minute of retrying before an
// item is dead-lettered — long enough to ride out a controller restart, short
// enough that a real failure reaches the audit trail while an operator is still
// looking at the request that caused it.
const networkQueueMaxAttempts = 5

// retryOrDeadLetterNetworkItem records one failed application of a queue item.
// Below the attempt bound it returns the item to 'pending' with the error and
// an incremented attempt count; at the bound it dead-letters the item and
// audits it.
//
// table is one of the two queue names and is never taken from a request.
func (s *Service) retryOrDeadLetterNetworkItem(
	ctx context.Context, table string, id int64, attempts int, orgID, userID, detail string, cause error,
) {
	next := attempts + 1
	if next < networkQueueMaxAttempts {
		//orgscope:ignore network hand-off queue drain (runs under bypass_rls) rescheduling an item the worker already claimed by primary key
		if _, err := s.db.Pool.Exec(ctx,
			"UPDATE "+table+" SET state='pending', attempts=$2, last_error=$3, updated_at=NOW() WHERE id=$1",
			id, next, cause.Error()); err != nil {
			s.logger.Warn("network queue: reschedule failed",
				zap.String("queue", table), zap.Int64("item", id), zap.Error(err))
		}
		return
	}

	//orgscope:ignore network hand-off queue drain (runs under bypass_rls) dead-lettering an item the worker already claimed by primary key
	if _, err := s.db.Pool.Exec(ctx,
		"UPDATE "+table+" SET state='failed', attempts=$2, last_error=$3, updated_at=NOW() WHERE id=$1",
		id, next, cause.Error()); err != nil {
		s.logger.Warn("network queue: dead-letter failed",
			zap.String("queue", table), zap.Int64("item", id), zap.Error(err))
	}

	s.logger.Error("network queue: item dead-lettered after exhausting attempts",
		zap.String("queue", table), zap.Int64("item", id),
		zap.String("user_id", userID), zap.Int("attempts", next), zap.Error(cause))

	action := "network.grant_failed"
	if table == "network_revocation_queue" {
		action = "network.revocation_failed"
	}
	details, _ := json.Marshal(map[string]any{
		"queue":    table,
		"item_id":  id,
		"attempts": next,
		"detail":   detail,
		"error":    cause.Error(),
	})
	// The audit trail is the reader 'failed' never had. Written under the queue
	// row's own organization so it lands on the right tenant's audit page; the
	// worker runs bypassed, so the org term has to come from the row. A legacy
	// row with no tenant (both columns were nullable before v166) has no audit
	// page to land on, so it stays with the log line above rather than being
	// written to somebody else's.
	if orgID == "" {
		s.logger.Warn("network queue: dead-lettered item has no organization; not audited",
			zap.String("queue", table), zap.Int64("item", id))
		return
	}
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, actor_ip,
		                          target_id, target_type, details, created_at, org_id)
		VALUES (gen_random_uuid(), 'access', 'provisioning', $1, 'failure', NULL, '0.0.0.0',
		        NULLIF($2,'')::uuid, 'user', $3, NOW(), $4::uuid)`,
		action, userID, string(details), orgID); err != nil {
		s.logger.Warn("network queue: failed to audit dead-letter",
			zap.String("queue", table), zap.Int64("item", id), zap.Error(err))
	}
}
