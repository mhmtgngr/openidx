package migrations

// Migration v103 — MCP / AI-agent gateway (Wave D1).
//
// The 2026 battleground: OpenIDX can do NETWORK-enforced agent containment that
// pure-IdP rivals cannot. An AI agent authenticates with an OpenIDX-issued token
// (registered via DCR #545, optionally delegated via token exchange #545), and
// every MCP tool call it makes goes through a gateway that:
//  1. authenticates the agent (its OAuth token),
//  2. checks a per-tool allowlist (this agent/role may call this tool),
//  3. forwards to the MCP server — published as a dark Ziti service, so the
//     server has zero inbound exposure,
//  4. audits the call.
//
// Two tables (org-scoped for RLS):
//
//	mcp_servers        — a registered MCP server (dark Ziti service or URL).
//	mcp_tool_policies  — the per-tool allowlist: which principal (agent client_id
//	                     or a role) may invoke which tool on which server. An
//	                     empty tool ('*') is a server-wide grant.
//
// Additive + idempotent. No behavior change until an MCP server is registered.
var mcpGatewayUp = `-- Migration 103: MCP / AI-agent gateway.

CREATE TABLE IF NOT EXISTS mcp_servers (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID,
    -- URL-safe name used in the gateway path (/api/v1/mcp/<name>/...).
    name          VARCHAR(128) NOT NULL,
    description   TEXT,
    -- How the gateway reaches the MCP server. When ziti_service is set, the
    -- gateway dials it over the overlay (dark service, no inbound exposure);
    -- otherwise it uses upstream_url directly.
    ziti_service  VARCHAR(255),
    upstream_url  TEXT,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);
CREATE INDEX IF NOT EXISTS idx_mcp_servers_org ON mcp_servers(org_id);

CREATE TABLE IF NOT EXISTS mcp_tool_policies (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID,
    server_id     UUID NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    -- The allowed principal: 'client:<client_id>' for a specific agent, or
    -- 'role:<role_name>' for any principal holding that role.
    principal     VARCHAR(255) NOT NULL,
    -- The tool this grants; '*' means every tool on the server.
    tool          VARCHAR(255) NOT NULL DEFAULT '*',
    created_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (server_id, principal, tool)
);
CREATE INDEX IF NOT EXISTS idx_mcp_tool_policies_server ON mcp_tool_policies(server_id);
`

var mcpGatewayDown = `-- Rollback 103.
DROP TABLE IF EXISTS mcp_tool_policies;
DROP TABLE IF EXISTS mcp_servers;
`
