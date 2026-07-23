package provisioning

import (
	"context"
	"testing"

	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// inboundUsersSchema is the minimal users/scim_users schema the inbound-SCIM
// write path needs, so we can prove the outbound fan-out hooks fire.
const inboundUsersSchema = `
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL, email VARCHAR(255),
    first_name VARCHAR(255), last_name VARCHAR(255),
    enabled BOOLEAN DEFAULT true, email_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(),
    org_id UUID, manager_id UUID);
CREATE TABLE IF NOT EXISTS scim_users (
    id UUID PRIMARY KEY, external_id VARCHAR(255), username VARCHAR(255),
    data JSONB NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(),
    org_id UUID);
CREATE TABLE IF NOT EXISTS sessions (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID);
CREATE TABLE IF NOT EXISTS api_keys (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID, revoked BOOLEAN DEFAULT false);`

// TestInboundCreateFansOutToTargets proves the end-to-end path: an inbound SCIM
// user create enqueues an outbound provisioning op for each enabled target.
func TestInboundCreateFansOutToTargets(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	if _, err := db.Pool.Exec(ctx, outboundSchema); err != nil {
		t.Fatalf("outbound schema: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, inboundUsersSchema); err != nil {
		t.Fatalf("inbound schema: %v", err)
	}

	svc := &Service{db: db, logger: zap.NewNop()}
	orgID := "00000000-0000-0000-0000-0000000000aa"
	octx := orgctx.With(ctx, orgctx.Org{ID: orgID})

	// One enabled user target.
	if _, err := svc.CreateTargetApp(octx, orgID, &TargetAppInput{
		Name: "saas", BaseURL: "https://x/scim", AuthType: "bearer", BearerToken: "t",
		ProvisionUsers: true, Enabled: true,
	}); err != nil {
		t.Fatalf("CreateTargetApp: %v", err)
	}

	// Inbound SCIM create.
	created, err := svc.CreateSCIMUser(octx, &SCIMUser{
		UserName: "newhire@corp.com", Active: true,
		Name:   SCIMName{GivenName: "New", FamilyName: "Hire"},
		Emails: []SCIMEmail{{Value: "newhire@corp.com", Primary: true}},
	})
	if err != nil {
		t.Fatalf("CreateSCIMUser: %v", err)
	}

	// Exactly one outbound create op should be queued for that user.
	var n int
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM scim_provisioning_queue
        WHERE resource_type='user' AND local_id=$1 AND operation='create'`, created.ID).Scan(&n)
	if n != 1 {
		t.Fatalf("expected 1 queued create op after inbound create, got %d", n)
	}

	// A deprovision (active:false) should enqueue a deactivate op.
	if _, err := svc.UpdateSCIMUser(octx, created.ID, &SCIMUser{
		UserName: "newhire@corp.com", Active: false,
		Name: SCIMName{GivenName: "New", FamilyName: "Hire"},
	}); err != nil {
		t.Fatalf("UpdateSCIMUser deprovision: %v", err)
	}
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM scim_provisioning_queue
        WHERE resource_type='user' AND local_id=$1 AND operation='deactivate'`, created.ID).Scan(&n)
	if n != 1 {
		t.Fatalf("expected 1 queued deactivate op after active:false, got %d", n)
	}

	// Delete should enqueue a delete op (before the row is removed).
	if err := svc.DeleteSCIMUser(octx, created.ID); err != nil {
		t.Fatalf("DeleteSCIMUser: %v", err)
	}
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM scim_provisioning_queue
        WHERE resource_type='user' AND local_id=$1 AND operation='delete'`, created.ID).Scan(&n)
	if n != 1 {
		t.Fatalf("expected 1 queued delete op after inbound delete, got %d", n)
	}
}

// TestInboundCreateNoTargetsNoQueue proves fan-out is a no-op when no targets
// are configured (the common case; must not error or enqueue).
func TestInboundCreateNoTargetsNoQueue(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	db.Pool.Exec(ctx, outboundSchema)
	db.Pool.Exec(ctx, inboundUsersSchema)

	svc := &Service{db: db, logger: zap.NewNop()}
	orgID := "00000000-0000-0000-0000-0000000000bb"
	octx := orgctx.With(ctx, orgctx.Org{ID: orgID})

	created, err := svc.CreateSCIMUser(octx, &SCIMUser{
		UserName: "solo@corp.com", Active: true, Name: SCIMName{GivenName: "Solo"},
	})
	if err != nil {
		t.Fatalf("CreateSCIMUser: %v", err)
	}
	var n int
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM scim_provisioning_queue WHERE local_id=$1`, created.ID).Scan(&n)
	if n != 0 {
		t.Errorf("expected 0 queued ops with no targets, got %d", n)
	}
}
