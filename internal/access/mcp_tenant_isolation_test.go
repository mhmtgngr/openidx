package access

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// Tenant isolation for the MCP gateway, migration v168.
//
// ONE TENANT COULD WIDEN ANOTHER TENANT'S ALLOWLIST. AddMCPToolPolicy took the
// server id straight from the URL and inserted an allow rule with no check
// whatever that the server belonged to the caller -- and toolAllowed, which
// reads the rule, matched on server_id and principal and named no organization
// either. Since a principal may be 'role:<name>' and role names are not
// globally unique (every organization has an 'admin'), one POST naming another
// tenant's server id could grant THEIR administrators every tool on a server
// whose allowlist they had deliberately narrowed.
func TestMCP_TenantIsolation(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	if _, err := db.Pool.Exec(ctx, mcpSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	const orgB = "00000000-0000-0000-0000-0000000000d2"
	s := &Service{db: db, logger: zap.NewNop()}

	// org A's server, with a deliberately narrow allowlist: one agent, one tool.
	srvA, err := s.CreateMCPServer(ctx, mcpTestOrgID, &MCPServerInput{
		Name: "org-a-tools", UpstreamURL: "https://a.mcp.internal", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create org A server: %v", err)
	}
	if err := s.AddMCPToolPolicy(ctx, mcpTestOrgID, srvA.ID,
		&MCPToolPolicyInput{Principal: "client:agent-a", Tool: "search"}); err != nil {
		t.Fatalf("seed org A policy: %v", err)
	}
	if _, err := s.CreateMCPServer(ctx, orgB, &MCPServerInput{
		Name: "org-b-tools", UpstreamURL: "https://b.mcp.internal", Enabled: true,
	}); err != nil {
		t.Fatalf("create org B server: %v", err)
	}

	t.Run("another tenant cannot widen this allowlist", func(t *testing.T) {
		// The sharp version: 'role:admin' is a role name org A also has.
		err := s.AddMCPToolPolicy(ctx, orgB, srvA.ID,
			&MCPToolPolicyInput{Principal: "role:admin", Tool: "*"})
		if err == nil {
			t.Error("org B wrote an allow rule onto org A's MCP server. The write took " +
				"the server id from the URL and checked nothing, and toolAllowed " +
				"names no organization -- so org A's own administrators would have " +
				"been granted every tool on a server whose allowlist org A had " +
				"deliberately narrowed")
		}

		// org A's gateway still enforces exactly what org A granted.
		if !s.toolAllowed(ctx, mcpTestOrgID, srvA.ID, "agent-a", nil, "search") {
			t.Error("org A lost its own grant")
		}
		if s.toolAllowed(ctx, mcpTestOrgID, srvA.ID, "anyone", []string{"admin"}, "delete") {
			t.Error("org A's allowlist was widened: role:admin now reaches every tool")
		}
	})

	t.Run("a server is created with a real tenant, never NULL", func(t *testing.T) {
		if _, err := s.CreateMCPServer(ctx, "", &MCPServerInput{
			Name: "tenantless", UpstreamURL: "https://x", Enabled: true,
		}); err == nil {
			t.Error("a server was registered with no organization. It would keep " +
				"forwarding and stop appearing on any console once the belt landed")
		}
		var nulls int
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM mcp_servers WHERE org_id IS NULL`).Scan(&nulls); err != nil {
			t.Fatalf("count: %v", err)
		}
		if nulls != 0 {
			t.Errorf("%d MCP servers have no organization", nulls)
		}
	})

	t.Run("the server list and lookups are this tenant's", func(t *testing.T) {
		got, err := s.ListMCPServers(ctx, mcpTestOrgID)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(got) != 1 || got[0].Name != "org-a-tools" {
			t.Errorf("org A sees %d MCP servers, want exactly its own", len(got))
		}
		wide, err := s.ListMCPServers(ctx, "")
		if err != nil {
			t.Fatalf("list with no org: %v", err)
		}
		if len(wide) != 0 {
			t.Errorf("an empty organization returned %d MCP servers; the predicate was "+
				"`(org_id::text=$1 OR $1='')`, so an absent tenant meant every tenant",
				len(wide))
		}
		if _, err := s.getMCPServerByID(ctx, orgB, srvA.ID); err == nil {
			t.Error("org B read org A's MCP server registration")
		}
		if _, err := s.getMCPServerByName(ctx, orgB, "org-a-tools"); err == nil {
			t.Error("org B resolved org A's MCP server by name — the gateway's own lookup")
		}
		if err := s.DeleteMCPServer(ctx, orgB, srvA.ID); err == nil {
			t.Error("org B deleted org A's MCP server, and its allowlist with it")
		}
	})

	// The allowlist read must not honour another tenant's rule even if one
	// exists — the belt is the second half of this, the predicate the first.
	t.Run("a foreign allow rule is not honoured", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO mcp_tool_policies (org_id, server_id, principal, tool)
			VALUES ($1::uuid, $2::uuid, 'role:admin', '*')`, orgB, srvA.ID); err != nil {
			t.Fatalf("plant foreign rule: %v", err)
		}
		if s.toolAllowed(ctx, mcpTestOrgID, srvA.ID, "anyone", []string{"admin"}, "delete") {
			t.Error("a rule belonging to org B widened org A's allowlist. toolAllowed " +
				"matched on server_id and principal and named no organization")
		}
	})
}
