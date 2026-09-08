package access

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

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

// networkQueueStallTimeout is how long an item may sit in 'processing' before
// another drain takes it over.
//
// Both drains claim by setting state='processing' and both only ever select
// state='pending', so the write that moves a claimed item on was the only way
// out of that state -- and it was unchecked. An item whose outcome could not be
// written stayed 'processing' for good: not applied, not retried, not
// dead-lettered, and outside every count the queue reports. No database failure
// is needed either; being killed between the claim and the outcome does it.
//
// For a revocation that is a user who keeps their overlay attribute and their
// live circuits after governance took the access away, with the request showing
// as actioned. Fifteen minutes is far longer than a drain takes (both tick in
// seconds), so a requeue means the previous holder is gone rather than slow.
const networkQueueStallTimeout = 15 * time.Minute

// requeueStalledNetworkItems returns items abandoned mid-flight to 'pending'
// with the attempt counted, so one that keeps stalling reaches
// networkQueueMaxAttempts and dead-letters rather than cycling for ever.
//
// Items claimed moments ago are left alone: a worker is still applying them,
// and requeueing those is how the same attribute change is sent twice.
//
// table is one of the two queue names and is never taken from a request.
func (s *Service) requeueStalledNetworkItems(ctx context.Context, table string) {
	//orgscope:ignore network hand-off queue drain (runs under bypass_rls) recovering claims it made itself
	tag, err := s.db.Pool.Exec(ctx,
		"UPDATE "+table+` SET state='pending', attempts=attempts+1, updated_at=NOW()
		  WHERE state='processing' AND updated_at < NOW() - $1::interval`,
		fmt.Sprintf("%d seconds", int(networkQueueStallTimeout.Seconds())))
	if err != nil {
		s.logger.Warn("network queue: could not recover stalled items",
			zap.String("queue", table), zap.Error(err))
		return
	}
	if n := tag.RowsAffected(); n > 0 {
		s.logger.Warn("network queue: recovered items abandoned in 'processing'",
			zap.String("queue", table), zap.Int64("items", n))
	}
}

// completeNetworkItem marks a claimed item done, and says so when it cannot.
//
// The stall reaper above will pick the item back up, so the work is not lost --
// but it will be applied a second time, and both directions are idempotent
// precisely so that is safe. What is not acceptable is the fifteen minutes of
// silence in between.
//
// table is one of the two queue names and is never taken from a request.
func (s *Service) completeNetworkItem(ctx context.Context, table string, id int64) {
	//orgscope:ignore network hand-off queue drain (runs under bypass_rls) completing an item it already claimed by primary key
	if _, err := s.db.Pool.Exec(ctx,
		"UPDATE "+table+" SET state='done', updated_at=NOW() WHERE id=$1", id); err != nil {
		s.logger.Error("network queue: applied an item and could not record it as done; "+
			"it stays claimed until the stall reaper requeues it and applies it again",
			zap.String("queue", table), zap.Int64("item", id), zap.Error(err))
	}
}

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
