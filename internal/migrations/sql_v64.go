package migrations

// Migration v64 — org_id + FORCE-RLS belt for jit_grants and
// request_approval_chains (readiness W2.10, defense-in-depth).
//
// v58 created these tables without org_id / the belt on the reasoning that
// jit_grants is org-scoped implicitly via its user/role FKs and
// request_approval_chains is reached only through its RLS-scoped access_requests
// parent. That holds today, but the belt is cheap defense-in-depth and closes the
// gap if a future query forgets the join/filter. The cross-org background sweeps
// that scan these tables already run under orgctx.WithBypassRLS
// (jit.go StartExpiryChecker, jit_expiry.go, request.go checkEscalations), so the
// belt does not break them.
//
// org_id is backfilled from the natural parent (jit_grants -> users.org_id via
// user_id; request_approval_chains -> access_requests.org_id via request_id),
// then set NOT NULL, then belted (USING + WITH CHECK). Plain statements only
// (splitSQL cannot handle DO $$ blocks). Mirrored into init-db.sql so
// TestInitDB(Column)Parity stays green.
var jitApprovalOrgRLSUp = `-- Migration 064: org_id + FORCE-RLS belt for jit_grants + request_approval_chains.
ALTER TABLE jit_grants              ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE request_approval_chains ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Backfill from the natural parent; any orphan -> oldest org so SET NOT NULL can't fail.
UPDATE jit_grants g SET org_id = u.org_id FROM users u WHERE g.user_id = u.id AND g.org_id IS NULL;
UPDATE jit_grants SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE request_approval_chains c SET org_id = r.org_id FROM access_requests r WHERE c.request_id = r.id AND c.org_id IS NULL;
UPDATE request_approval_chains SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE jit_grants              ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE request_approval_chains ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_jit_grants_org              ON jit_grants(org_id);
CREATE INDEX IF NOT EXISTS idx_request_approval_chains_org ON request_approval_chains(org_id);

-- v37 FORCE-RLS belt (USING + explicit WITH CHECK so INSERT/UPDATE are enforced too).
DROP POLICY IF EXISTS pol_jit_grants_org_scope ON jit_grants;
CREATE POLICY pol_jit_grants_org_scope ON jit_grants
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE jit_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE jit_grants FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_request_approval_chains_org_scope ON request_approval_chains;
CREATE POLICY pol_request_approval_chains_org_scope ON request_approval_chains
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE request_approval_chains ENABLE ROW LEVEL SECURITY;
ALTER TABLE request_approval_chains FORCE  ROW LEVEL SECURITY;

-- Plain GRANT (belt-and-suspenders; v53's ALTER DEFAULT PRIVILEGES already covers new tables).
GRANT SELECT, INSERT, UPDATE, DELETE ON jit_grants, request_approval_chains TO openidx_app;
`

var jitApprovalOrgRLSDown = `-- Migration 064 down.
DROP POLICY IF EXISTS pol_request_approval_chains_org_scope ON request_approval_chains;
DROP POLICY IF EXISTS pol_jit_grants_org_scope ON jit_grants;
ALTER TABLE request_approval_chains DISABLE ROW LEVEL SECURITY;
ALTER TABLE jit_grants              DISABLE ROW LEVEL SECURITY;
ALTER TABLE request_approval_chains DROP COLUMN IF EXISTS org_id;
ALTER TABLE jit_grants              DROP COLUMN IF EXISTS org_id;
`
