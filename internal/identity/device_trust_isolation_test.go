package identity

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestDeviceTrustRequests_TenantIsolation guards the device-trust cross-tenant
// IDOR: before v72 the table had no org_id and Approve/Reject acted by bare id
// while the count queries had no org filter, so an admin in one org could
// approve/reject another org's requests and read global pending counts. With
// org_id + the per-method org predicate, a caller only ever sees/acts on
// requests in their own org. DB-backed because the methods run real queries.
func TestDeviceTrustRequests_TenantIsolation(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const (
		orgA  = "00000000-0000-0000-0000-00000000000a"
		orgB  = "00000000-0000-0000-0000-00000000000b"
		userA = "11111111-0000-0000-0000-00000000000a"
		userB = "11111111-0000-0000-0000-00000000000b"
		reqA  = "22222222-0000-0000-0000-00000000000a"
		reqB  = "22222222-0000-0000-0000-00000000000b"
		admin = "33333333-0000-0000-0000-000000000001"
	)
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})

	if _, err := db.Pool.Exec(ctxA, `
		CREATE TABLE users (id UUID PRIMARY KEY, email VARCHAR(255), first_name VARCHAR(255), last_name VARCHAR(255), org_id UUID NOT NULL);
		CREATE TABLE device_trust_requests (
			id UUID PRIMARY KEY, user_id UUID, device_id VARCHAR(255), device_fingerprint VARCHAR(255),
			device_name VARCHAR(255), device_type VARCHAR(50), ip_address VARCHAR(45), user_agent TEXT,
			justification TEXT, status VARCHAR(20), reviewed_by UUID, reviewed_at TIMESTAMPTZ,
			review_notes TEXT, auto_expire_at TIMESTAMPTZ, org_id UUID NOT NULL, created_at TIMESTAMPTZ DEFAULT now());
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	exec := func(q string, a ...interface{}) {
		if _, err := db.Pool.Exec(ctxA, q, a...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO users (id, email, first_name, last_name, org_id) VALUES ($1,'a@x','A','U',$2)`, userA, orgA)
	exec(`INSERT INTO users (id, email, first_name, last_name, org_id) VALUES ($1,'b@x','B','U',$2)`, userB, orgB)
	// review_notes must be non-NULL: ListDeviceTrustRequests scans it into a
	// non-pointer string (a NULL would error the row Scan and drop the row).
	req := func(id, user, org string) {
		exec(`INSERT INTO device_trust_requests (id, user_id, device_id, device_fingerprint, device_name, device_type, ip_address, user_agent, justification, status, review_notes, org_id)
		      VALUES ($1,$2,'dev','fp','Laptop','personal','1.2.3.4','ua','need it','pending','',$3)`, id, user, org)
	}
	req(reqA, userA, orgA)
	req(reqB, userB, orgB)

	s := &Service{db: db, logger: zap.NewNop()}

	status := func(id string) string {
		var st string
		if err := db.Pool.QueryRow(ctxA, `SELECT status FROM device_trust_requests WHERE id=$1`, id).Scan(&st); err != nil {
			t.Fatalf("status(%s): %v", id, err)
		}
		return st
	}

	// Count + list under org A must see only org A's request.
	if n, err := s.GetPendingRequestCount(ctxA); err != nil || n != 1 {
		t.Fatalf("GetPendingRequestCount for org A: got %d (err %v), want 1 (org B's request must not be counted)", n, err)
	}
	list, total, err := s.ListDeviceTrustRequests(ctxA, "", "", 50, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 || len(list) != 1 || list[0].ID != reqA {
		t.Fatalf("list for org A: total=%d len=%d — want only reqA (%s), got %+v", total, len(list), reqA, list)
	}

	// Approving org B's request from org A must be refused, and B must stay pending.
	if err := s.ApproveDeviceTrustRequest(ctxA, reqB, admin, ""); err == nil {
		t.Fatal("org A approving org B's device-trust request should fail (cross-tenant IDOR), got nil")
	}
	if st := status(reqB); st != "pending" {
		t.Fatalf("org B's request must remain pending after a cross-org approve attempt, got %q", st)
	}
	// Rejecting cross-org likewise refused.
	if err := s.RejectDeviceTrustRequest(ctxA, reqB, admin, ""); err == nil {
		t.Fatal("org A rejecting org B's request should fail, got nil")
	}

	// Approving its own request works.
	if err := s.ApproveDeviceTrustRequest(ctxA, reqA, admin, ""); err != nil {
		t.Fatalf("org A approving its own request should succeed, got %v", err)
	}
	if st := status(reqA); st != "approved" {
		t.Fatalf("own request should be approved, got %q", st)
	}
}
