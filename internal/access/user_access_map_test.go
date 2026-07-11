package access

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// ---------------------------------------------------------------------------
// Pure matching logic (no DB)
// ---------------------------------------------------------------------------

func TestPolicyAppliesToIdentity(t *testing.T) {
	cases := []struct {
		name  string
		roles []string
		ziti  string
		attrs []string
		want  bool
	}{
		{"all matches everyone", []string{"#all"}, "z1", nil, true},
		{"pinned identity matches", []string{"@z1"}, "z1", nil, true},
		{"pinned other identity does not", []string{"@z2"}, "z1", nil, false},
		{"attribute matches", []string{"#platform"}, "z1", []string{"platform"}, true},
		{"attribute with hash prefix in attrs", []string{"#platform"}, "z1", []string{"#platform"}, true},
		{"no overlap", []string{"#sre"}, "z1", []string{"platform"}, false},
		{"empty policy matches nothing", nil, "z1", []string{"platform"}, false},
		{"one of many matches", []string{"#sre", "@z1"}, "z1", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := policyAppliesToIdentity(tc.roles, tc.ziti, tc.attrs); got != tc.want {
				t.Fatalf("policyAppliesToIdentity(%v, %q, %v) = %v, want %v",
					tc.roles, tc.ziti, tc.attrs, got, tc.want)
			}
		})
	}
}

func TestResolveServiceRoles(t *testing.T) {
	byID := map[string]string{"s1": "prod-db", "s2": "jumphost"}
	all := []string{"prod-db", "jumphost"}

	t.Run("all expands to every service", func(t *testing.T) {
		got := resolveServiceRoles([]string{"#all"}, byID, all)
		if len(got) != 2 {
			t.Fatalf("want 2 services, got %v", got)
		}
	})
	t.Run("id ref resolves to name", func(t *testing.T) {
		got := resolveServiceRoles([]string{"@s1"}, byID, all)
		if len(got) != 1 || got[0] != "prod-db" {
			t.Fatalf("want [prod-db], got %v", got)
		}
	})
	t.Run("unknown id ref is dropped", func(t *testing.T) {
		got := resolveServiceRoles([]string{"@missing"}, byID, all)
		if len(got) != 0 {
			t.Fatalf("want empty, got %v", got)
		}
	})
	t.Run("tag ref is kept as intent", func(t *testing.T) {
		got := resolveServiceRoles([]string{"#web-apps"}, byID, all)
		if len(got) != 1 || got[0] != "#web-apps" {
			t.Fatalf("want [#web-apps], got %v", got)
		}
	})
	t.Run("duplicates collapse", func(t *testing.T) {
		got := resolveServiceRoles([]string{"#all", "@s1"}, byID, all)
		if len(got) != 2 {
			t.Fatalf("want 2 unique services, got %v", got)
		}
	})
}

// ---------------------------------------------------------------------------
// DB-backed cross-pillar aggregation
// ---------------------------------------------------------------------------

// crossPillarSchema creates the minimal columns of every table the access map,
// kill switch, and lifecycle sweep touch — the same shape production has, no
// FKs so each test seeds only what it needs.
var crossPillarSchema = []string{
	`CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY, org_id UUID NOT NULL, username VARCHAR(255) NOT NULL,
		email VARCHAR(255) NOT NULL, enabled BOOLEAN NOT NULL DEFAULT true,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_login_at TIMESTAMPTZ,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
	`CREATE TABLE IF NOT EXISTS roles (id UUID PRIMARY KEY, name VARCHAR(255) NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS user_roles (user_id UUID, role_id UUID, org_id UUID)`,
	`CREATE TABLE IF NOT EXISTS groups (id UUID PRIMARY KEY, name VARCHAR(255) NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS group_memberships (user_id UUID, group_id UUID, org_id UUID)`,
	`CREATE TABLE IF NOT EXISTS sessions (
		id UUID PRIMARY KEY, user_id UUID, org_id UUID, revoked BOOLEAN,
		revoked_at TIMESTAMPTZ, expires_at TIMESTAMPTZ)`,
	`CREATE TABLE IF NOT EXISTS api_keys (
		id UUID PRIMARY KEY, user_id UUID, org_id UUID, status VARCHAR(32))`,
	`CREATE TABLE IF NOT EXISTS access_requests (
		id UUID PRIMARY KEY, requester_id UUID, org_id UUID,
		resource_type VARCHAR(50), status VARCHAR(50))`,
	`CREATE TABLE IF NOT EXISTS vault_secrets (
		id UUID PRIMARY KEY, org_id UUID, name VARCHAR(255), type VARCHAR(32))`,
	`CREATE TABLE IF NOT EXISTS vault_access_grants (
		id UUID PRIMARY KEY, org_id UUID, secret_id UUID, principal_type VARCHAR(32),
		principal_id UUID, actions TEXT[], expires_at TIMESTAMPTZ)`,
	`CREATE TABLE IF NOT EXISTS vault_checkouts (
		id UUID PRIMARY KEY, org_id UUID, secret_id UUID, principal_id UUID,
		mode VARCHAR(16), leased_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		expires_at TIMESTAMPTZ, returned_at TIMESTAMPTZ, status VARCHAR(16))`,
	`CREATE TABLE IF NOT EXISTS jit_grants (
		id UUID PRIMARY KEY, user_id UUID, org_id UUID, role_name VARCHAR(255),
		expires_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ, revoked_by UUID,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), status VARCHAR(16))`,
	`CREATE TABLE IF NOT EXISTS proxy_routes (
		id UUID PRIMARY KEY, name VARCHAR(255), ziti_enabled BOOLEAN DEFAULT false)`,
	`CREATE TABLE IF NOT EXISTS guacamole_connections (
		id UUID PRIMARY KEY, route_id UUID, protocol VARCHAR(20))`,
	`CREATE TABLE IF NOT EXISTS guacamole_sessions (
		id UUID PRIMARY KEY, org_id UUID, connection_id UUID, user_id UUID,
		guac_session_uuid VARCHAR(255), started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		ended_at TIMESTAMPTZ, status VARCHAR(16))`,
	`CREATE TABLE IF NOT EXISTS guacamole_session_requests (
		id UUID PRIMARY KEY, org_id UUID, requester_id UUID, status VARCHAR(16),
		expires_at TIMESTAMPTZ)`,
	`CREATE TABLE IF NOT EXISTS ziti_identities (
		id UUID PRIMARY KEY, org_id UUID, ziti_id VARCHAR(255), name VARCHAR(255),
		user_id UUID, enrolled BOOLEAN DEFAULT false, attributes JSONB DEFAULT '[]')`,
	`CREATE TABLE IF NOT EXISTS ziti_services (
		id UUID PRIMARY KEY, org_id UUID, ziti_id VARCHAR(255), name VARCHAR(255),
		enabled BOOLEAN DEFAULT true)`,
	`CREATE TABLE IF NOT EXISTS ziti_service_policies (
		id UUID PRIMARY KEY, org_id UUID, name VARCHAR(255), policy_type VARCHAR(10),
		service_roles JSONB DEFAULT '[]', identity_roles JSONB DEFAULT '[]')`,
	`CREATE TABLE IF NOT EXISTS enrolled_agents (
		id UUID PRIMARY KEY, agent_id VARCHAR(64), platform VARCHAR(32),
		status VARCHAR(20), compliance_status VARCHAR(20) DEFAULT 'unknown',
		ziti_identity_id VARCHAR(255), last_seen_at TIMESTAMPTZ,
		enrolled_at TIMESTAMPTZ DEFAULT NOW(), enrolled_by_user_id UUID)`,
	`CREATE TABLE IF NOT EXISTS known_devices (
		id UUID PRIMARY KEY, user_id UUID, org_id UUID, trusted BOOLEAN DEFAULT false)`,
	`CREATE TABLE IF NOT EXISTS unified_audit_events (
		id UUID PRIMARY KEY, source VARCHAR(50), event_type VARCHAR(100),
		route_id UUID, user_id UUID, actor_ip VARCHAR(45), details JSONB DEFAULT '{}',
		created_at TIMESTAMPTZ DEFAULT NOW())`,
}

const (
	testOrg   = "00000000-0000-0000-0000-0000000000aa"
	testUser  = "11111111-0000-0000-0000-000000000001"
	testActor = "11111111-0000-0000-0000-00000000000f"
)

func TestUserAccessMap_CrossPillar(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: testOrg})
	for _, stmt := range crossPillarSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}

	const (
		roleID   = "22222222-0000-0000-0000-000000000001"
		groupID  = "33333333-0000-0000-0000-000000000001"
		secretID = "44444444-0000-0000-0000-000000000001"
		routeID  = "55555555-0000-0000-0000-000000000001"
		connID   = "55555555-0000-0000-0000-000000000002"
	)

	seed := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users (id, org_id, username, email, enabled) VALUES ($1,$2,'alice','alice@x.io',true)`,
			[]any{testUser, testOrg}},
		{`INSERT INTO roles (id, name) VALUES ($1,'DBA')`, []any{roleID}},
		{`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, []any{testUser, roleID, testOrg}},
		{`INSERT INTO groups (id, name) VALUES ($1,'Platform')`, []any{groupID}},
		{`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1,$2,$3)`, []any{testUser, groupID, testOrg}},
		{`INSERT INTO sessions (id, user_id, org_id, revoked, expires_at) VALUES (gen_random_uuid(),$1,$2,false,NOW()+'1h')`,
			[]any{testUser, testOrg}},
		{`INSERT INTO api_keys (id, user_id, org_id, status) VALUES (gen_random_uuid(),$1,$2,'active')`,
			[]any{testUser, testOrg}},
		// Vault: secret granted via the DBA role, plus an active checkout.
		{`INSERT INTO vault_secrets (id, org_id, name, type) VALUES ($1,$2,'prod-db-root','password')`,
			[]any{secretID, testOrg}},
		{`INSERT INTO vault_access_grants (id, org_id, secret_id, principal_type, principal_id, actions)
		  VALUES (gen_random_uuid(),$1,$2,'role',$3,'{use,reveal}')`, []any{testOrg, secretID, roleID}},
		{`INSERT INTO vault_checkouts (id, org_id, secret_id, principal_id, mode, status, expires_at)
		  VALUES (gen_random_uuid(),$1,$2,$3,'reveal','active',NOW()+'1h')`, []any{testOrg, secretID, testUser}},
		{`INSERT INTO jit_grants (id, user_id, org_id, role_name, expires_at, status)
		  VALUES (gen_random_uuid(),$1,$2,'break-glass',NOW()+'2h','active')`, []any{testUser, testOrg}},
		// PAM session riding a Ziti-enabled route.
		{`INSERT INTO proxy_routes (id, name, ziti_enabled) VALUES ($1,'prod-jumphost',true)`, []any{routeID}},
		{`INSERT INTO guacamole_connections (id, route_id, protocol) VALUES ($1,$2,'ssh')`, []any{connID, routeID}},
		{`INSERT INTO guacamole_sessions (id, org_id, connection_id, user_id, guac_session_uuid, status)
		  VALUES (gen_random_uuid(),$1,$2,$3,'guac-uuid-1','active')`, []any{testOrg, connID, testUser}},
		// Ziti identity carrying the group attribute; a Dial policy matching it.
		{`INSERT INTO ziti_identities (id, org_id, ziti_id, name, user_id, enrolled, attributes)
		  VALUES (gen_random_uuid(),$1,'zid-1','alice',$2,true,'["Platform"]')`, []any{testOrg, testUser}},
		{`INSERT INTO ziti_services (id, org_id, ziti_id, name, enabled)
		  VALUES (gen_random_uuid(),$1,'zsvc-1','prod-db',true)`, []any{testOrg}},
		{`INSERT INTO ziti_service_policies (id, org_id, name, policy_type, service_roles, identity_roles)
		  VALUES (gen_random_uuid(),$1,'platform-dial','Dial','["@zsvc-1"]','["#Platform"]')`, []any{testOrg}},
		{`INSERT INTO enrolled_agents (id, agent_id, platform, status, compliance_status, enrolled_by_user_id)
		  VALUES (gen_random_uuid(),'agent-1','linux','active','compliant',$1)`, []any{testUser}},
		{`INSERT INTO known_devices (id, user_id, org_id, trusted) VALUES (gen_random_uuid(),$1,$2,true)`,
			[]any{testUser, testOrg}},
		{`INSERT INTO unified_audit_events (id, source, event_type, user_id)
		  VALUES (gen_random_uuid(),'ziti','circuit.created',$1)`, []any{testUser}},
		{`INSERT INTO unified_audit_events (id, source, event_type, user_id)
		  VALUES (gen_random_uuid(),'guacamole','session.started',$1)`, []any{testUser}},
	}
	for _, s := range seed {
		if _, err := db.Pool.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("seed %q: %v", s.sql[:40], err)
		}
	}

	s := &Service{db: db, logger: zap.NewNop()}
	m, err := s.buildUserAccessMap(ctx, testOrg, testUser)
	if err != nil {
		t.Fatalf("buildUserAccessMap: %v", err)
	}

	// IAM pillar
	if m.User.Username != "alice" || !m.User.Enabled {
		t.Errorf("user header wrong: %+v", m.User)
	}
	if len(m.IAM.Roles) != 1 || m.IAM.Roles[0].Name != "DBA" {
		t.Errorf("roles wrong: %+v", m.IAM.Roles)
	}
	if m.IAM.ActiveSessions != 1 || m.IAM.ActiveAPIKeys != 1 {
		t.Errorf("live IAM counts wrong: %+v", m.IAM)
	}

	// PAM pillar — the role-mediated grant must be attributed via role:DBA.
	if len(m.PAM.VaultGrants) != 1 || m.PAM.VaultGrants[0].Via != "role:DBA" {
		t.Errorf("vault grants wrong: %+v", m.PAM.VaultGrants)
	}
	if len(m.PAM.ActiveCheckouts) != 1 || m.PAM.ActiveCheckouts[0].SecretName != "prod-db-root" {
		t.Errorf("checkouts wrong: %+v", m.PAM.ActiveCheckouts)
	}
	if len(m.PAM.ActiveJITGrants) != 1 || m.PAM.ActiveJITGrants[0].RoleName != "break-glass" {
		t.Errorf("jit grants wrong: %+v", m.PAM.ActiveJITGrants)
	}
	// PAM⇄Ziti correlation: the live privileged session rides a Ziti route.
	if len(m.PAM.ActiveSessions) != 1 || !m.PAM.ActiveSessions[0].OverZiti {
		t.Errorf("privileged session ziti correlation wrong: %+v", m.PAM.ActiveSessions)
	}

	// Ziti pillar — group attribute matched the dial policy; @zsvc-1 resolved.
	if m.Ziti.Identity == nil || !m.Ziti.Identity.Enrolled {
		t.Fatalf("ziti identity wrong: %+v", m.Ziti.Identity)
	}
	if len(m.Ziti.DialPolicies) != 1 || m.Ziti.DialPolicies[0].Name != "platform-dial" {
		t.Errorf("dial policies wrong: %+v", m.Ziti.DialPolicies)
	}
	if len(m.Ziti.ReachableServices) != 1 || m.Ziti.ReachableServices[0] != "prod-db" {
		t.Errorf("reachable services wrong: %+v", m.Ziti.ReachableServices)
	}
	if len(m.Ziti.Devices) != 1 || m.Ziti.Devices[0].AgentID != "agent-1" {
		t.Errorf("devices wrong: %+v", m.Ziti.Devices)
	}
	if !m.Ziti.TrustedDevice {
		t.Error("trusted device flag not set")
	}

	// Cross-pillar activity from both non-IAM sources.
	if len(m.Activity) != 2 {
		t.Errorf("activity wrong: %+v", m.Activity)
	}

	// Unknown user in the same org → not-found, not a 500.
	if _, err := s.buildUserAccessMap(ctx, testOrg, "11111111-0000-0000-0000-0000000000ee"); err != errAccessMapUserNotFound {
		t.Errorf("want errAccessMapUserNotFound, got %v", err)
	}
	// Right user, wrong org → also not-found (org gate).
	if _, err := s.buildUserAccessMap(ctx, "00000000-0000-0000-0000-0000000000bb", testUser); err != errAccessMapUserNotFound {
		t.Errorf("cross-org lookup must 404, got %v", err)
	}
}
