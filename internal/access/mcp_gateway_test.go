package access

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

const mcpSchema = `
CREATE TABLE IF NOT EXISTS mcp_servers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID, name VARCHAR(128) NOT NULL,
    description TEXT, ziti_service VARCHAR(255), upstream_url TEXT, enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name));
CREATE TABLE IF NOT EXISTS mcp_tool_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID,
    server_id UUID NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    principal VARCHAR(255) NOT NULL, tool VARCHAR(255) NOT NULL DEFAULT '*',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (server_id, principal, tool));`

func TestMCPServerCRUD(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	if _, err := db.Pool.Exec(ctx, mcpSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	s := &Service{db: db, logger: zap.NewNop()}

	// Requires an endpoint.
	if _, err := s.CreateMCPServer(ctx, "", &MCPServerInput{Name: "nowhere"}); err == nil {
		t.Error("expected error without ziti_service or upstream_url")
	}
	srv, err := s.CreateMCPServer(ctx, "", &MCPServerInput{
		Name: "tools-a", UpstreamURL: "https://mcp.internal", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateMCPServer: %v", err)
	}
	if srv.ID == "" {
		t.Fatal("expected server id")
	}
	// Lookup by name (enabled only).
	got, err := s.getMCPServerByName(ctx, "", "tools-a")
	if err != nil || got.ID != srv.ID {
		t.Fatalf("getMCPServerByName: %v", err)
	}
	list, _ := s.ListMCPServers(ctx, "")
	if len(list) != 1 {
		t.Fatalf("expected 1 server, got %d", len(list))
	}
	if err := s.DeleteMCPServer(ctx, "", srv.ID); err != nil {
		t.Fatalf("DeleteMCPServer: %v", err)
	}
}

func TestMCPToolAllowlist(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	db.Pool.Exec(ctx, mcpSchema)
	s := &Service{db: db, logger: zap.NewNop()}

	srv, _ := s.CreateMCPServer(ctx, "", &MCPServerInput{Name: "a", UpstreamURL: "https://x", Enabled: true})

	// client:agent-1 may call tool "search"; role:analyst may call anything (*).
	s.AddMCPToolPolicy(ctx, "", srv.ID, &MCPToolPolicyInput{Principal: "client:agent-1", Tool: "search"})
	s.AddMCPToolPolicy(ctx, "", srv.ID, &MCPToolPolicyInput{Principal: "role:analyst", Tool: "*"})

	// agent-1 can call search, not delete.
	if !s.toolAllowed(ctx, srv.ID, "agent-1", nil, "search") {
		t.Error("agent-1 should be allowed to call search")
	}
	if s.toolAllowed(ctx, srv.ID, "agent-1", nil, "delete") {
		t.Error("agent-1 should NOT be allowed to call delete")
	}
	// A principal with role:analyst can call any tool via the wildcard.
	if !s.toolAllowed(ctx, srv.ID, "agent-2", []string{"analyst"}, "delete") {
		t.Error("role:analyst wildcard should allow delete")
	}
	// An unknown agent with no roles is denied.
	if s.toolAllowed(ctx, srv.ID, "stranger", nil, "search") {
		t.Error("unknown agent should be denied")
	}
}

func TestClaimStrings(t *testing.T) {
	got := claimStrings([]interface{}{"a", "b", 3, "c"})
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Errorf("claimStrings dropped/kept wrong values: %v", got)
	}
	if claimStrings(nil) != nil {
		t.Error("nil claim should yield nil")
	}
	if claimStrings("notarray") != nil {
		t.Error("non-array claim should yield nil")
	}
}
