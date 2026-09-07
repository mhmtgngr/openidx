package provisioning

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// A leaver whose downstream account nobody disabled, and nobody retried.
//
// drainBatch claims an item by setting state='processing', and it only ever
// selects state='pending'. The three writes that move a claimed item on --
// done, dead-lettered, rescheduled -- all discarded their errors, so an item
// whose outcome could not be written stayed 'processing' for good: not applied,
// not retried, not dead-lettered, and counted under neither "failed" nor
// "pending" on the target's status page. The same happens whenever the process
// is killed between the claim and the outcome, which needs no database failure
// at all.
//
// For an outbound deprovision that is the whole joiner-mover-leaver promise: a
// departed employee keeps their account in the downstream application, and the
// queue says nothing is wrong.

func stalledQueueFixture(t *testing.T) (*outboundWorker, context.Context, string, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
		cleanup()
		t.Fatalf("pgcrypto: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, outboundSchema); err != nil {
		cleanup()
		t.Fatalf("schema: %v", err)
	}
	svc := &Service{db: db, logger: zap.NewNop(), config: &config.Config{}}
	target, err := svc.CreateTargetApp(ctx, testOrgID, &TargetAppInput{
		Name: "stalled-saas", BaseURL: "http://127.0.0.1:1", AuthType: "bearer", BearerToken: "tok",
		ProvisionUsers: true, DeprovisionAction: "deactivate", Enabled: true,
	})
	if err != nil {
		cleanup()
		t.Fatalf("CreateTargetApp: %v", err)
	}
	w := &outboundWorker{svc: svc, cfg: OutboundWorkerConfig{BatchSize: 10}, logger: zap.NewNop()}
	return w, ctx, target.ID, cleanup
}

func TestAProvisioningItemAbandonedInProcessingIsRequeued(t *testing.T) {
	w, ctx, targetID, cleanup := stalledQueueFixture(t)
	defer cleanup()

	// One item abandoned an hour ago; one a worker is still applying.
	var stale, fresh int64
	if err := w.svc.db.Pool.QueryRow(ctx, `
		INSERT INTO scim_provisioning_queue
			(org_id, target_id, resource_type, local_id, operation, state, attempts, updated_at)
		VALUES ($1, $2, 'user', '11111111-1111-1111-1111-111111111111', 'delete',
		        'processing', 0, NOW() - INTERVAL '1 hour')
		RETURNING id`, testOrgID, targetID).Scan(&stale); err != nil {
		t.Fatalf("seed the stalled item: %v", err)
	}
	if err := w.svc.db.Pool.QueryRow(ctx, `
		INSERT INTO scim_provisioning_queue
			(org_id, target_id, resource_type, local_id, operation, state, attempts, updated_at)
		VALUES ($1, $2, 'user', '22222222-2222-2222-2222-222222222222', 'delete',
		        'processing', 0, NOW())
		RETURNING id`, testOrgID, targetID).Scan(&fresh); err != nil {
		t.Fatalf("seed the in-flight item: %v", err)
	}

	w.requeueStalledItems(ctx)

	var state string
	var attempts int
	if err := w.svc.db.Pool.QueryRow(ctx,
		`SELECT state, attempts FROM scim_provisioning_queue WHERE id = $1`, stale).
		Scan(&state, &attempts); err != nil {
		t.Fatalf("read the stalled item back: %v", err)
	}
	if state != "pending" {
		t.Errorf("a deprovision abandoned in 'processing' an hour ago is still %q. The drain only "+
			"ever selects 'pending', so this leaver's downstream account is never disabled and "+
			"nothing says so.", state)
	}
	if attempts != 1 {
		t.Errorf("requeued with attempts=%d, want 1 — an item that keeps stalling must reach "+
			"maxQueueAttempts and dead-letter rather than cycling for ever", attempts)
	}

	if err := w.svc.db.Pool.QueryRow(ctx,
		`SELECT state FROM scim_provisioning_queue WHERE id = $1`, fresh).Scan(&state); err != nil {
		t.Fatalf("read the in-flight item back: %v", err)
	}
	if state != "processing" {
		t.Errorf("an item claimed moments ago was requeued (state %q); the worker holding it is "+
			"still applying it, and this is how one operation is sent twice", state)
	}
}

// The drain recovers its own abandoned claims, so nothing else has to.
func TestTheProvisioningDrainRecoversItsOwnAbandonedClaims(t *testing.T) {
	w, ctx, targetID, cleanup := stalledQueueFixture(t)
	defer cleanup()

	if _, err := w.svc.db.Pool.Exec(ctx, `
		INSERT INTO scim_provisioning_queue
			(org_id, target_id, resource_type, local_id, operation, state, attempts, updated_at)
		VALUES ($1, $2, 'user', '11111111-1111-1111-1111-111111111111', 'delete',
		        'processing', 0, NOW() - INTERVAL '1 hour')`,
		testOrgID, targetID); err != nil {
		t.Fatalf("seed the stalled item: %v", err)
	}

	// The target refuses the connection, so applying it fails and the item is
	// rescheduled — but it had to be claimed at all, which is the point.
	n, err := w.drainBatch(ctx)
	if err != nil {
		t.Fatalf("drainBatch: %v", err)
	}
	if n != 1 {
		t.Fatalf("the drain claimed %d items; the stalled one should have been requeued and picked up", n)
	}

	var state string
	if err := w.svc.db.Pool.QueryRow(ctx,
		`SELECT state FROM scim_provisioning_queue WHERE target_id = $1::uuid`, targetID).Scan(&state); err != nil {
		t.Fatalf("read the item back: %v", err)
	}
	if state == "processing" {
		t.Error("after a full drain the item is still 'processing' — it was never recovered")
	}
}
