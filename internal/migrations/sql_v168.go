package migrations

// Migration v168 — the MCP tool allowlist: one tenant could widen another's.
//
// v103 created `mcp_servers` and `mcp_tool_policies` for the MCP gateway: an
// AI agent presents its OpenIDX token, a per-tool allowlist decides whether it
// may invoke that tool, and the call is forwarded to the MCP server over a dark
// Ziti service. Both tables got a nullable `org_id` with no foreign key, and
// neither got FORCE ROW LEVEL SECURITY.
//
// ONE TENANT COULD WIDEN ANOTHER TENANT'S ALLOWLIST. AddMCPToolPolicy takes the
// server id from the URL and inserts:
//
//	INSERT INTO mcp_tool_policies (org_id, server_id, principal, tool)
//	VALUES ($1,$2,$3,$4) ON CONFLICT (server_id, principal, tool) DO NOTHING
//
// with no check whatever that the server belongs to the caller. So
// POST /mcp/servers/<another organization's server id>/policies wrote an allow
// rule onto THEIR server. And the two functions that read the allowlist --
// toolAllowed and toolRequiresApproval -- match on `server_id` and `principal`
// and name no organization at all, so the rule is honoured.
//
// The principal is where this stops being theoretical. It is either
// 'client:<client_id>' or 'role:<role_name>', and ROLE NAMES ARE NOT GLOBALLY
// UNIQUE: every organization has an 'admin'. So a single POST naming another
// tenant's server id with principal 'role:admin' and tool '*' granted THEIR
// administrators blanket access to every tool on a server whose allowlist they
// had deliberately narrowed -- a control widened from outside, enforced by
// their own gateway, and visible on their console only as a policy row they did
// not create.
//
// The same POST also sets require_approval's absence: v118 added that column so
// a sensitive tool waits for a human, and toolRequiresApproval reads it through
// the same untenanted match, so an inserted row with require_approval unset can
// satisfy the allow check while contributing nothing to the approval check.
//
// Both reads now carry the tenant, and the write refuses a server that is not
// the caller's rather than writing the row and filtering later -- the call v152
// made for delegations and v163 for the entitlement owner.
//
// THE SAME WILDCARD AS v164 AND v165. Get-by-id, get-by-name, list and delete
// carry an OR-empty-string escape hatch on the tenant term, and the helper feeding them returns the
// empty string when the request carries no organization. Not reachable through
// the mounted routes, which run TenantResolver in front of every one of them,
// and gone anyway: it contradicts the belt, under which an unscoped read
// returns nothing rather than everything.
//
// A NULL TENANT. Both writes passed the organization through a nullIfEmpty
// helper, so an empty org stored a row with no tenant -- invisible to every
// scoped read once the belt lands. For a server that means a registered MCP
// gateway that still forwards and no longer appears; for a policy row it means
// a grant nobody can see and nothing can revoke. v103's own
// `UNIQUE (org_id, name)` does not constrain those either, because NULL is
// distinct from NULL in a unique index, so two tenantless servers could share a
// name. The column is made NOT NULL with a real foreign key.
//
// BACKFILL. A policy follows its server through v103's enforced foreign key,
// which is exact. A server carries no attribution column, so one stored with a
// NULL organization goes to the oldest organization.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var mcpTenantBeltUp = `-- Migration 168: belt the MCP gateway tables and make their tenant real.

UPDATE mcp_tool_policies p SET org_id = s.org_id FROM mcp_servers s
  WHERE s.id = p.server_id AND p.org_id IS NULL AND s.org_id IS NOT NULL;

UPDATE mcp_servers       SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE mcp_tool_policies SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE mcp_servers       ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE mcp_tool_policies ALTER COLUMN org_id SET NOT NULL;

ALTER TABLE mcp_servers       DROP CONSTRAINT IF EXISTS fk_mcp_servers_org;
ALTER TABLE mcp_servers       ADD  CONSTRAINT fk_mcp_servers_org       FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE mcp_tool_policies DROP CONSTRAINT IF EXISTS fk_mcp_tool_policies_org;
ALTER TABLE mcp_tool_policies ADD  CONSTRAINT fk_mcp_tool_policies_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_mcp_tool_policies_org_server ON mcp_tool_policies(org_id, server_id);

DROP POLICY IF EXISTS pol_mcp_servers_org_scope ON mcp_servers;
CREATE POLICY pol_mcp_servers_org_scope ON mcp_servers
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE mcp_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_servers FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_mcp_tool_policies_org_scope ON mcp_tool_policies;
CREATE POLICY pol_mcp_tool_policies_org_scope ON mcp_tool_policies
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE mcp_tool_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_tool_policies FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_servers       TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_tool_policies TO openidx_app;
`

// Down lifts the belt, drops the index and the foreign keys, and returns org_id
// to nullable. The columns themselves stay -- v103 created them -- so this
// rollback cannot fail on data.
var mcpTenantBeltDown = `-- Rollback 168.

ALTER TABLE mcp_tool_policies NO FORCE ROW LEVEL SECURITY;
ALTER TABLE mcp_tool_policies DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_mcp_tool_policies_org_scope ON mcp_tool_policies;

ALTER TABLE mcp_servers NO FORCE ROW LEVEL SECURITY;
ALTER TABLE mcp_servers DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_mcp_servers_org_scope ON mcp_servers;

DROP INDEX IF EXISTS idx_mcp_tool_policies_org_server;

ALTER TABLE mcp_tool_policies DROP CONSTRAINT IF EXISTS fk_mcp_tool_policies_org;
ALTER TABLE mcp_servers       DROP CONSTRAINT IF EXISTS fk_mcp_servers_org;

ALTER TABLE mcp_tool_policies ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE mcp_servers       ALTER COLUMN org_id DROP NOT NULL;
`
