package access

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestMyZitiServices proves the self endpoint resolves the caller's Dial-policy
// reach and enriches service names with connection details from the mirror.
func TestMyZitiServices(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	schema := []string{
		`CREATE TABLE ziti_identities (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			ziti_id VARCHAR(255) NOT NULL, name VARCHAR(255) NOT NULL,
			user_id UUID, org_id UUID, enrolled BOOLEAN DEFAULT false,
			attributes JSONB DEFAULT '[]')`,
		`CREATE TABLE enrolled_agents (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			agent_id VARCHAR(255), platform VARCHAR(64), status VARCHAR(64),
			compliance_status VARCHAR(64), ziti_identity_id VARCHAR(255),
			enrolled_by_user_id UUID, enrolled_at TIMESTAMPTZ DEFAULT NOW(),
			last_seen_at TIMESTAMPTZ)`,
		`CREATE TABLE known_devices (
			user_id UUID, org_id UUID, trusted BOOLEAN DEFAULT false)`,
		`CREATE TABLE ziti_service_policies (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255), org_id UUID, policy_type VARCHAR(20),
			identity_roles JSONB DEFAULT '[]', service_roles JSONB DEFAULT '[]')`,
		`CREATE TABLE ziti_services (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			ziti_id VARCHAR(255) NOT NULL, name VARCHAR(255) NOT NULL,
			description TEXT, protocol VARCHAR(20) DEFAULT 'tcp',
			host VARCHAR(255), port INTEGER, org_id UUID, enabled BOOLEAN DEFAULT true)`,
	}
	for _, q := range schema {
		if _, err := db.Pool.Exec(ctx, q); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}

	const (
		org  = "00000000-0000-0000-0000-000000000010"
		user = "11111111-1111-1111-1111-111111111111"
	)
	exec := func(q string, args ...any) {
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	// Synced + enrolled identity for the user.
	exec(`INSERT INTO ziti_identities (ziti_id, name, user_id, org_id, enrolled, attributes)
	      VALUES ('zid-1','alice-laptop',$1,$2,true,'["#device-trusted"]')`, user, org)
	// Two enabled services; a Dial policy granting #all to the identity.
	exec(`INSERT INTO ziti_services (ziti_id, name, description, protocol, host, port, org_id, enabled)
	      VALUES ('svc-web','web-app','Internal web','tcp','web.internal',443,$1,true),
	             ('svc-db','postgres-prod','DB','tcp','db.internal',5432,$1,true)`, org)
	exec(`INSERT INTO ziti_service_policies (name, org_id, policy_type, identity_roles, service_roles)
	      VALUES ('all-can-dial',$1,'Dial','["#all"]','["#all"]')`, org)

	s := &Service{db: db, logger: zap.NewNop()}
	octx := orgctx.With(ctx, orgctx.Org{ID: org})

	resp, err := s.myZitiServices(octx, org, user)
	if err != nil {
		t.Fatalf("myZitiServices: %v", err)
	}
	if !resp.Linked || !resp.Enrolled {
		t.Fatalf("want linked+enrolled identity, got linked=%v enrolled=%v", resp.Linked, resp.Enrolled)
	}
	if len(resp.Services) != 2 {
		t.Fatalf("want 2 reachable services, got %d: %+v", len(resp.Services), resp.Services)
	}
	// Sorted by name: postgres-prod, web-app; and enriched with host/port.
	if resp.Services[0].Name != "postgres-prod" || resp.Services[0].Host != "db.internal" || resp.Services[0].Port != 5432 {
		t.Errorf("first service not enriched correctly: %+v", resp.Services[0])
	}
	if resp.Services[1].Name != "web-app" || resp.Services[1].Port != 443 {
		t.Errorf("second service not enriched correctly: %+v", resp.Services[1])
	}

	// A user with no synced identity gets an empty, unlinked response (no error).
	empty, err := s.myZitiServices(octx, org, "22222222-2222-2222-2222-222222222222")
	if err != nil {
		t.Fatalf("myZitiServices(no identity): %v", err)
	}
	if empty.Linked || len(empty.Services) != 0 {
		t.Errorf("unlinked user should have 0 services, got linked=%v n=%d", empty.Linked, len(empty.Services))
	}
}
