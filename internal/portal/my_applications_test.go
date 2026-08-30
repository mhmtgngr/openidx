package portal

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestMyApplicationsMatchesOverviewCount pins the catalogue and the count to one
// predicate. They drifted before (#874): the count saw only direct assignments
// while the list also saw group-derived ones, so My Access said "0 apps" while
// My Apps listed them.
func TestMyApplicationsMatchesOverviewCount(t *testing.T) {
	db, cleanup := setupPortalTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const (
		org   = "00000000-0000-0000-0000-0000000000c0"
		user  = "11111111-0000-0000-0000-0000000000c1"
		group = "22222222-0000-0000-0000-0000000000c1"
		appA  = "33333333-0000-0000-0000-0000000000c1"
		appB  = "33333333-0000-0000-0000-0000000000c2"
	)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})

	schema := []string{
		`CREATE TABLE applications (id UUID PRIMARY KEY, name VARCHAR(255),
		    description TEXT, base_url VARCHAR(500), protocol VARCHAR(50),
		    enabled BOOLEAN, route_id UUID, org_id UUID)`,
		`CREATE TABLE user_application_assignments (user_id UUID, application_id UUID, org_id UUID)`,
		`CREATE TABLE group_application_assignments (group_id UUID, application_id UUID, org_id UUID)`,
		`CREATE TABLE group_memberships (user_id UUID, group_id UUID, org_id UUID)`,
		`CREATE TABLE user_roles (user_id UUID, role_id UUID, org_id UUID)`,
		`CREATE TABLE roles (id UUID PRIMARY KEY, name VARCHAR(255))`,
		`CREATE TABLE groups (id UUID PRIMARY KEY, name VARCHAR(255))`,
		`CREATE TABLE group_join_requests (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    user_id UUID, org_id UUID, status VARCHAR(32))`,
		`CREATE TABLE vault_access_grants (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    org_id UUID, secret_id UUID, principal_type VARCHAR(32), principal_id UUID, expires_at TIMESTAMPTZ)`,
		`CREATE TABLE vault_checkouts (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    org_id UUID, principal_id UUID, status VARCHAR(16))`,
		`CREATE TABLE jit_grants (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    user_id UUID, org_id UUID, expires_at TIMESTAMPTZ, status VARCHAR(16))`,
		`CREATE TABLE guacamole_sessions (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    org_id UUID, user_id UUID, status VARCHAR(16))`,
		`CREATE TABLE guacamole_session_requests (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    org_id UUID, requester_id UUID, status VARCHAR(16), expires_at TIMESTAMPTZ)`,
		`CREATE TABLE ziti_identities (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    org_id UUID, user_id UUID, enrolled BOOLEAN)`,
		`CREATE TABLE enrolled_agents (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), enrolled_by_user_id UUID)`,
		`CREATE TABLE known_devices (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    user_id UUID, org_id UUID, trusted BOOLEAN)`,
	}
	for _, stmt := range schema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}

	seeds := []string{
		`INSERT INTO groups (id, name) VALUES ('` + group + `','Engineering')`,
		`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ('` + user + `','` + group + `','` + org + `')`,
		`INSERT INTO applications (id, name, enabled, org_id) VALUES
		   ('` + appA + `','Direct',true,'` + org + `'),
		   ('` + appB + `','ViaGroup',true,'` + org + `')`,
		`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ('` + user + `','` + appA + `','` + org + `')`,
		`INSERT INTO group_application_assignments (group_id, application_id, org_id) VALUES ('` + group + `','` + appB + `','` + org + `')`,
	}
	for _, stmt := range seeds {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	svc := NewService(db, zap.NewNop())
	apps, err := svc.GetMyApplications(ctx, user)
	if err != nil {
		t.Fatalf("GetMyApplications: %v", err)
	}
	ov, err := svc.GetAccessOverview(ctx, user)
	if err != nil {
		t.Fatalf("GetAccessOverview: %v", err)
	}
	if len(apps) != ov.AppsCount {
		t.Errorf("catalogue lists %d apps but the overview counts %d — they must use one predicate", len(apps), ov.AppsCount)
	}
	if len(apps) != 2 {
		t.Errorf("got %d apps, want 2 (one direct, one group-derived)", len(apps))
	}
}
