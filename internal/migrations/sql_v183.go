package migrations

// v183 — drop jit_grants, the second representation of a time-bound elevation.
//
// The product has always had two. The live one is an access_requests row:
// resource_type 'role', 'group' or 'application', status 'fulfilled',
// expires_at set. governance's approval workflow creates it and inserts the
// assignment; its expiry sweep removes the assignment and marks the request
// expired. That path works and is tested.
//
// jit_grants was the other, and internal/governance/jit.go was the only code
// that INSERTed it -- a service no binary could reach (tools/deadservice). So
// the table has been empty on every install ever run, while five live paths
// aimed at it:
//
//	internal/access/kill_switch.go      revoked it on account compromise and
//	                                    published pam_jit_grants_revoked
//	internal/access/lifecycle_sweep.go  revoked the elevations of disabled users
//	internal/identity/service.go        revoked a leaver's on deprovisioning
//	internal/access/user_access_map.go  listed them on User Access 360
//	internal/portal/service.go          counted them on the user's dashboard
//
// The first three did nothing and reported nothing; the kill switch's zero, on
// the response an incident responder reads, said "this user held no
// elevations" while they kept every elevated role the approval workflow had
// granted them. The last two showed an empty list and a zero on pages whose
// whole job is to say what access somebody has.
//
// All five now go through internal/jitgrant against access_requests, so the
// table has no reader and no writer left and the code that would have written
// it is deleted in the same commit.
//
// EMPTY BY CONSTRUCTION, WITH ONE EXCEPTION WORTH NAMING. Nothing in this
// product could create a row. A row could only exist if an operator inserted
// one by hand or a fork wired NewJITService. The DROP is therefore not a data
// migration on any install this repository has shipped -- but it is a DROP, so
// down recreates the table in the v58 shape with v64's org_id, index, policy
// and belt, and a rollback lands on the schema the code at that point expects.
var dropJITGrantsUp = `-- Migration 183: drop jit_grants.
DROP TABLE IF EXISTS jit_grants CASCADE;`

var dropJITGrantsDown = `-- Rollback 183: recreate jit_grants (v58 shape + v64 org_id and belt).
CREATE TABLE IF NOT EXISTS jit_grants (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id       UUID,
    role_name     VARCHAR(255) NOT NULL,
    granted_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    justification TEXT,
    duration      BIGINT,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at    TIMESTAMPTZ,
    revoked_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    status        VARCHAR(16) NOT NULL DEFAULT 'active',
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_jit_grants_user_role ON jit_grants(user_id, role_id, status);
CREATE INDEX IF NOT EXISTS idx_jit_grants_expiry    ON jit_grants(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_jit_grants_org       ON jit_grants(org_id);
DROP POLICY IF EXISTS pol_jit_grants_org_scope ON jit_grants;
CREATE POLICY pol_jit_grants_org_scope ON jit_grants
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE jit_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE jit_grants FORCE  ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON jit_grants TO openidx_app;`
