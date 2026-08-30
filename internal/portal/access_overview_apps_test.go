package portal

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestGetAccessOverview_AppsCountIncludesGroupAssignments pins the app count to
// the same predicate GetMyApplications uses. Access to an application can come
// from a direct assignment OR from a group the user belongs to
// (group_application_assignments, migration v136), but the overview counted only
// user_application_assignments — so a user whose apps all come through a group
// was told "0 apps" on My Access while My Apps listed them.
func TestGetAccessOverview_AppsCountIncludesGroupAssignments(t *testing.T) {
	db, cleanup := setupPortalTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const (
		orgID    = "00000000-0000-0000-0000-0000000000ae"
		userID   = "11111111-0000-0000-0000-0000000000a1"
		groupID  = "33333333-0000-0000-0000-0000000000a1"
		directID = "55555555-0000-0000-0000-0000000000a1"
		groupApp = "55555555-0000-0000-0000-0000000000a2"
		bothApp  = "55555555-0000-0000-0000-0000000000a3"
		otherApp = "55555555-0000-0000-0000-0000000000a4"
	)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	schema := []string{
		`CREATE TABLE user_roles (user_id UUID, role_id UUID, org_id UUID)`,
		`CREATE TABLE roles (id UUID PRIMARY KEY, name VARCHAR(255))`,
		`CREATE TABLE group_memberships (user_id UUID, group_id UUID, org_id UUID)`,
		`CREATE TABLE groups (id UUID PRIMARY KEY, name VARCHAR(255))`,
		`CREATE TABLE applications (id UUID PRIMARY KEY, name VARCHAR(255), enabled BOOLEAN, org_id UUID)`,
		`CREATE TABLE user_application_assignments (user_id UUID, application_id UUID, org_id UUID)`,
		`CREATE TABLE group_application_assignments (group_id UUID, application_id UUID, org_id UUID)`,
		`CREATE TABLE group_join_requests (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID, status VARCHAR(32))`,
		`CREATE TABLE vault_access_grants (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID, secret_id UUID,
			principal_type VARCHAR(32), principal_id UUID, expires_at TIMESTAMPTZ)`,
		`CREATE TABLE vault_checkouts (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID,
			principal_id UUID, status VARCHAR(16))`,
		`CREATE TABLE jit_grants (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID,
			expires_at TIMESTAMPTZ, status VARCHAR(16))`,
		`CREATE TABLE guacamole_sessions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID, user_id UUID, status VARCHAR(16))`,
		`CREATE TABLE guacamole_session_requests (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID, requester_id UUID,
			status VARCHAR(16), expires_at TIMESTAMPTZ)`,
		`CREATE TABLE ziti_identities (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID, user_id UUID, enrolled BOOLEAN)`,
		`CREATE TABLE enrolled_agents (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), enrolled_by_user_id UUID)`,
		`CREATE TABLE known_devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID, trusted BOOLEAN)`,
	}
	for _, stmt := range schema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}

	seeds := []string{
		`INSERT INTO groups (id, name) VALUES ('` + groupID + `','Engineering')`,
		`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ('` + userID + `','` + groupID + `','` + orgID + `')`,
		`INSERT INTO applications (id, name, enabled, org_id) VALUES
			('` + directID + `','Direct',true,'` + orgID + `'),
			('` + groupApp + `','ViaGroup',true,'` + orgID + `'),
			('` + bothApp + `','Both',true,'` + orgID + `'),
			('` + otherApp + `','Unassigned',true,'` + orgID + `')`,
		`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES
			('` + userID + `','` + directID + `','` + orgID + `'),
			('` + userID + `','` + bothApp + `','` + orgID + `')`,
		// ViaGroup reaches the user only through the group; Both is reachable
		// twice and must still count once.
		`INSERT INTO group_application_assignments (group_id, application_id, org_id) VALUES
			('` + groupID + `','` + groupApp + `','` + orgID + `'),
			('` + groupID + `','` + bothApp + `','` + orgID + `')`,
	}
	for _, stmt := range seeds {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	svc := NewService(db, zap.NewNop())
	ov, err := svc.GetAccessOverview(ctx, userID)
	if err != nil {
		t.Fatalf("GetAccessOverview: %v", err)
	}

	// Direct + ViaGroup + Both (deduped), never the unassigned one.
	if ov.AppsCount != 3 {
		t.Errorf("apps_count = %d, want 3 (direct + group-derived, deduped, excluding unassigned)", ov.AppsCount)
	}
}
