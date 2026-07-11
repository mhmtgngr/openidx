package portal

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestGetAccessOverview_CrossPillar pins the user-side unified view: the
// portal overview must aggregate all three pillars — IAM (roles/groups/apps),
// PAM (vault grants incl. role-mediated ones, checkouts, JIT, sessions), and
// Ziti (identity link/enrollment, devices, device trust) — from the single
// Postgres store. DB-backed because the aggregation is one round of scoped
// SQL against the real column names.
func TestGetAccessOverview_CrossPillar(t *testing.T) {
	db, cleanup := setupPortalTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const (
		orgID    = "00000000-0000-0000-0000-0000000000dd"
		userID   = "11111111-0000-0000-0000-0000000000e1"
		roleID   = "22222222-0000-0000-0000-0000000000e1"
		secretID = "44444444-0000-0000-0000-0000000000e1"
	)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	schema := []string{
		`CREATE TABLE user_roles (user_id UUID, role_id UUID, org_id UUID)`,
		`CREATE TABLE roles (id UUID PRIMARY KEY, name VARCHAR(255))`,
		`CREATE TABLE group_memberships (user_id UUID, group_id UUID, org_id UUID)`,
		`CREATE TABLE groups (id UUID PRIMARY KEY, name VARCHAR(255))`,
		`CREATE TABLE user_application_assignments (user_id UUID, org_id UUID)`,
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
		`INSERT INTO roles (id, name) VALUES ('` + roleID + `','DBA')`,
		`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ('` + userID + `','` + roleID + `','` + orgID + `')`,
		// One direct grant + one via the DBA role on the SAME secret: the
		// overview counts DISTINCT secrets, so this must count as 1.
		`INSERT INTO vault_access_grants (org_id, secret_id, principal_type, principal_id) VALUES ('` + orgID + `','` + secretID + `','user','` + userID + `')`,
		`INSERT INTO vault_access_grants (org_id, secret_id, principal_type, principal_id) VALUES ('` + orgID + `','` + secretID + `','role','` + roleID + `')`,
		`INSERT INTO vault_checkouts (org_id, principal_id, status) VALUES ('` + orgID + `','` + userID + `','active')`,
		`INSERT INTO jit_grants (user_id, org_id, expires_at, status) VALUES ('` + userID + `','` + orgID + `',NOW()+'1h','active')`,
		`INSERT INTO guacamole_sessions (org_id, user_id, status) VALUES ('` + orgID + `','` + userID + `','active')`,
		`INSERT INTO guacamole_session_requests (org_id, requester_id, status) VALUES ('` + orgID + `','` + userID + `','pending')`,
		`INSERT INTO ziti_identities (org_id, user_id, enrolled) VALUES ('` + orgID + `','` + userID + `',true)`,
		`INSERT INTO enrolled_agents (enrolled_by_user_id) VALUES ('` + userID + `')`,
		`INSERT INTO known_devices (user_id, org_id, trusted) VALUES ('` + userID + `','` + orgID + `',true)`,
	}
	for _, s := range seeds {
		if _, err := db.Pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	svc := NewService(db, zap.NewNop())
	ov, err := svc.GetAccessOverview(ctx, userID)
	if err != nil {
		t.Fatalf("GetAccessOverview: %v", err)
	}

	if ov.RolesCount != 1 {
		t.Errorf("roles_count = %d, want 1", ov.RolesCount)
	}
	// PAM slice.
	if ov.Privileged.VaultGrants != 1 {
		t.Errorf("vault_grants = %d, want 1 (distinct secret via user+role)", ov.Privileged.VaultGrants)
	}
	if ov.Privileged.ActiveCheckouts != 1 || ov.Privileged.ActiveJITGrants != 1 ||
		ov.Privileged.ActiveSessions != 1 || ov.Privileged.PendingSessionReq != 1 {
		t.Errorf("privileged slice wrong: %+v", ov.Privileged)
	}
	// Ziti slice.
	if !ov.Network.ZitiLinked || !ov.Network.ZitiEnrolled {
		t.Errorf("network identity flags wrong: %+v", ov.Network)
	}
	if ov.Network.Devices != 1 || !ov.Network.TrustedDevice {
		t.Errorf("network device slice wrong: %+v", ov.Network)
	}
}
