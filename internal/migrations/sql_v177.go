package migrations

// v177 — drop the four tables no code has ever touched.
//
// The other half of what tools/tablewriters found. v176 took the two tables
// something read; these four are read by nothing and written by nothing: DDL,
// indexes, grants, foreign keys, row-level-security policies and, in one case,
// a seed that maintains rows nobody consults.
//
//	health_check_history  v54. (service_name, dependency_name, status,
//	                      latency_ms, details, checked_at) with an index for the
//	                      time-series read someone intended. The health checks
//	                      that exist (internal/access/health_checks.go) report
//	                      live and store nothing.
//	posture_check_types   v29. A global enum of posture check kinds.
//	                      deployments/docker/seed.sql fills it with five rows
//	                      and no Go code has ever read it: the posture check
//	                      definitions live in Go (internal/admin's
//	                      postureCheckDefs), which is why the ISPM rules page
//	                      works at all. The seed goes with the table.
//	scim_groups           v3, the unused half of its SCIM pair. scim_users is
//	                      written and updated by the provisioning service on
//	                      every SCIM user operation; SCIM group provisioning
//	                      writes the product's own groups table, and this has
//	                      never had a writer. Migration v173 re-scoped its
//	                      install-wide UNIQUE on display_name to (org_id,
//	                      display_name) -- a constraint carefully fixed on a
//	                      table nothing uses, which is the cost of dead schema:
//	                      it consumes the attention real tables need.
//	user_mfa_policies     v5. (user_id, policy_id, assigned_at). No writer, no
//	                      reader, no history of either. MFA policy is decided by
//	                      admin_console_settings and the per-factor tables.
//
// Two of them carry org_id and sit behind the v37 FORCE-RLS belt, which is
// exactly why they are dropped rather than left: a belted table with no rows
// looks, to every census this repository runs, like a tenant boundary that is
// being maintained.
//
// Nothing is lost. A table with no writer has no rows, on any install, at any
// version.
const orphanTablesUp = `-- Migration 177: drop four tables nothing reads and nothing writes.

DROP TABLE IF EXISTS health_check_history;

DROP TABLE IF EXISTS posture_check_types;

DROP TABLE IF EXISTS scim_groups;

DROP TABLE IF EXISTS user_mfa_policies;
`

// Down recreates all four in the shape the chain had produced -- not the shape
// of the migration that first created them. scim_groups and user_mfa_policies
// gained org_id, a foreign key, an index and an RLS policy after their original
// DDL, and scim_groups' unique key was re-scoped by v173; restoring the v3 and
// v5 statements would roll back to a schema this repository has not shipped in
// a long time. Read off a database with the full chain applied.
//
// Grants need no statement: v53 set ALTER DEFAULT PRIVILEGES for openidx_app in
// this schema, so a table created by the migration role carries them.
const orphanTablesDown = `
CREATE TABLE IF NOT EXISTS health_check_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name VARCHAR(100) NOT NULL,
    dependency_name VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL,
    latency_ms INT,
    details JSONB,
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_health_history_service ON health_check_history(service_name, checked_at DESC);

CREATE TABLE IF NOT EXISTS posture_check_types (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    category VARCHAR(100) NOT NULL,
    parameters JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scim_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id VARCHAR(255),
    display_name VARCHAR(255) NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    org_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000010'
);

ALTER TABLE scim_groups ADD CONSTRAINT fk_scim_groups_org
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_scim_groups_external_id ON scim_groups(external_id);
CREATE INDEX IF NOT EXISTS idx_scim_groups_org_id ON scim_groups(org_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scim_groups_org_display_name ON scim_groups(org_id, display_name);

DROP POLICY IF EXISTS pol_scim_groups_org_scope ON scim_groups;
CREATE POLICY pol_scim_groups_org_scope ON scim_groups
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE scim_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_groups FORCE  ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS user_mfa_policies (
    user_id UUID NOT NULL,
    policy_id UUID NOT NULL,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    org_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000010',
    PRIMARY KEY (user_id, policy_id)
);

ALTER TABLE user_mfa_policies ADD CONSTRAINT fk_user_mfa_policies_org
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_user_mfa_policies_org_id ON user_mfa_policies(org_id);

DROP POLICY IF EXISTS pol_user_mfa_policies_org_scope ON user_mfa_policies;
CREATE POLICY pol_user_mfa_policies_org_scope ON user_mfa_policies
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE user_mfa_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_mfa_policies FORCE  ROW LEVEL SECURITY;
`
