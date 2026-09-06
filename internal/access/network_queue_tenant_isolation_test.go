package access

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"
)

// The network hand-off queues, migration v166.
//
// v100 and v101 are the hand-off between two services: governance decides and
// the access-service, which owns the Ziti manager, applies. A grant row adds
// the time-bound role attribute that opens the dial; a revocation row removes
// an attribute and severs the user's live circuits.
//
// A REVOCATION THAT REPORTED DONE WHEN IT HAD DONE NOTHING.
// drainNetworkRevocations called removeUserZitiAttribute, which returned
// nothing at all, and severUserZitiCircuits, which logged a termination failure
// and carried on -- and then wrote `state='done'` unconditionally. So an access
// review revoked a user, governance recorded the revocation, and this queue
// recorded the circuit severance as done even when the Ziti call failed. Its
// own sibling, drainNetworkGrants in the file next to it, already checked its
// error.
//
// AND 'failed' HAD NO READER, AND NO RETRY: nothing in the tree reads state or
// last_error from either queue, and neither worker ever incremented the
// attempts column both DDLs provide.
const netQueueSchema = `
CREATE TABLE IF NOT EXISTS network_revocation_queue (
    id BIGSERIAL PRIMARY KEY, org_id UUID, user_id UUID NOT NULL, reason VARCHAR(64) NOT NULL,
    attribute VARCHAR(128), state VARCHAR(16) NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS network_grant_queue (
    id BIGSERIAL PRIMARY KEY, org_id UUID, user_id UUID NOT NULL, request_id UUID,
    attribute VARCHAR(128) NOT NULL, expires_at TIMESTAMPTZ,
    state VARCHAR(16) NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY, event_type VARCHAR(50), category VARCHAR(50), action VARCHAR(100),
    outcome VARCHAR(50), actor_id UUID, actor_ip VARCHAR(64), target_id UUID,
    target_type VARCHAR(50), details JSONB, created_at TIMESTAMPTZ DEFAULT NOW(), org_id UUID);`

func TestNetworkQueue_FailureIsRecordedAndRetried(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	if _, err := db.Pool.Exec(ctx, netQueueSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-0000000000f1"
	const userA = "00000000-0000-0000-0000-0000000000f2"
	s := &Service{db: db, logger: zap.NewNop()}

	seed := func(table string) int64 {
		t.Helper()
		var id int64
		q := `INSERT INTO network_revocation_queue (org_id, user_id, reason) VALUES ($1::uuid,$2::uuid,'access_review') RETURNING id`
		if table == "network_grant_queue" {
			q = `INSERT INTO network_grant_queue (org_id, user_id, attribute) VALUES ($1::uuid,$2::uuid,'jit-x') RETURNING id`
		}
		if err := db.Pool.QueryRow(ctx, q, orgA, userA).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", table, err)
		}
		return id
	}
	stateOf := func(table string, id int64) (string, int, string) {
		t.Helper()
		var state, lastErr string
		var attempts int
		if err := db.Pool.QueryRow(ctx,
			"SELECT state, attempts, COALESCE(last_error,'') FROM "+table+" WHERE id=$1", id).
			Scan(&state, &attempts, &lastErr); err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
		return state, attempts, lastErr
	}

	for _, table := range []string{"network_revocation_queue", "network_grant_queue"} {
		t.Run(table+": a failure is retried, not abandoned", func(t *testing.T) {
			id := seed(table)
			s.retryOrDeadLetterNetworkItem(ctx, table, id, 0, orgA, userA, "detail",
				errors.New("ziti controller unreachable"))

			state, attempts, lastErr := stateOf(table, id)
			if state != "pending" {
				t.Errorf("after one failure the item is %q, want pending. Neither worker "+
					"ever incremented the attempts column both DDLs provide, so a "+
					"single transient controller error lost the grant or the "+
					"revocation permanently", state)
			}
			if attempts != 1 {
				t.Errorf("attempts = %d, want 1", attempts)
			}
			if lastErr == "" {
				t.Error("the failure was recorded with no reason")
			}
		})

		t.Run(table+": exhausting the attempts dead-letters and audits", func(t *testing.T) {
			id := seed(table)
			s.retryOrDeadLetterNetworkItem(ctx, table, id, networkQueueMaxAttempts-1, orgA, userA,
				"detail", errors.New("ziti controller unreachable"))

			state, _, _ := stateOf(table, id)
			if state != "failed" {
				t.Errorf("after exhausting attempts the item is %q, want failed", state)
			}

			// The audit trail is the reader 'failed' never had.
			var n int
			var auditOrg string
			if err := db.Pool.QueryRow(ctx, `
				SELECT COUNT(*), COALESCE(MAX(org_id::text),'')
				  FROM audit_events
				 WHERE action IN ('network.grant_failed','network.revocation_failed')
				   AND details->>'queue' = $1`, table).Scan(&n, &auditOrg); err != nil {
				t.Fatalf("read audit: %v", err)
			}
			if n == 0 {
				t.Errorf("a dead-lettered %s item wrote no audit event. Nothing in the tree "+
					"reads state or last_error from these queues, so without this the "+
					"failure has no reader at all: the console says the request was "+
					"granted and the attribute was never added", table)
			}
			if auditOrg != orgA {
				t.Errorf("the dead-letter audit event carries organization %q, want the "+
					"queue row's own %q — the worker runs bypassed, so the tenant has "+
					"to come from the row", auditOrg, orgA)
			}
		})
	}

	// With no Ziti manager wired, both helpers are genuine no-ops and must
	// report success: a user with no overlay identity has no circuit to sever,
	// and that is not a failure to retry forever.
	t.Run("a no-op is success, not a failure", func(t *testing.T) {
		if err := s.severUserZitiCircuits(ctx, userA, "governance:access_review"); err != nil {
			t.Errorf("severing with no overlay returned %v, want nil", err)
		}
		if err := s.removeUserZitiAttribute(ctx, userA, "jit-x"); err != nil {
			t.Errorf("removing an attribute with no overlay returned %v, want nil", err)
		}
	})
}
