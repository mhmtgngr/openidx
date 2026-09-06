package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// TestMCPApprovalIsTenantScopedWithoutTheBelt covers the human-in-the-loop gate
// for AI-agent tool calls, under an explicit RLS bypass.
//
// The bypass is the point. mcp_tool_approvals has carried FORCE ROW LEVEL
// SECURITY since v118, so with the belt on a missing org predicate is invisible
// — the database supplies the scope and a test passes whether or not the SQL
// says anything. Under a bypass only the query's own terms remain.
//
// The sharpest of these is consumeApprovedToolCall. gateToolCall asks two
// questions on consecutive lines: "does this tool require approval, in this
// tenant?" — which passed the organization — and "has this call been approved?"
// — which did not. The second is the one that lets an agent's tool call
// through.
func TestMCPApprovalIsTenantScopedWithoutTheBelt(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.WithBypassRLS(context.Background())
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	seedOrg := func(slug string) string {
		var id string
		if err := db.Pool.QueryRow(ctx,
			"INSERT INTO organizations (name, slug) VALUES ($1,$1) RETURNING id::text", slug).Scan(&id); err != nil {
			t.Fatalf("seed org %s: %v", slug, err)
		}
		return id
	}
	orgA, orgB := seedOrg("mcp-appr-a"), seedOrg("mcp-appr-b")

	seedServer := func(org, name string) string {
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO mcp_servers (org_id, name, upstream_url)
			VALUES ($1::uuid, $2, 'http://localhost:1') RETURNING id::text`, org, name).Scan(&id); err != nil {
			t.Fatalf("seed server %s: %v", name, err)
		}
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO mcp_tool_policies (org_id, server_id, principal, tool, require_approval)
			VALUES ($1::uuid, $2::uuid, 'client:agent1', 'deploy', true)`, org, id); err != nil {
			t.Fatalf("seed policy for %s: %v", name, err)
		}
		return id
	}
	serverB := seedServer(orgB, "deploy-b")

	s := &Service{db: db, logger: zap.NewNop()}
	body := []byte(`{"env":"prod"}`)

	// Org B opens a pending approval for its own server, and approves it.
	idB, statusB, err := s.createOrGetPendingToolApproval(ctx, orgB, serverB, "deploy", "agent1", "sub", body)
	if err != nil {
		t.Fatalf("org B open approval: %v", err)
	}
	if statusB != "pending" {
		t.Fatalf("org B approval status = %q, want pending", statusB)
	}
	if _, err := db.Pool.Exec(ctx,
		"UPDATE mcp_tool_approvals SET status='approved' WHERE id=$1", idB); err != nil {
		t.Fatalf("approve org B's request: %v", err)
	}

	t.Run("another tenant cannot consume this approval", func(t *testing.T) {
		ok, err := s.consumeApprovedToolCall(ctx, orgA, serverB, "deploy", "agent1", body)
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		if ok {
			t.Error("org A consumed org B's tool-call approval — the gate that clears " +
				"an agent's call to run answered for a tenant that did not grant it")
		}
	})

	t.Run("the owning tenant still consumes it", func(t *testing.T) {
		ok, err := s.consumeApprovedToolCall(ctx, orgB, serverB, "deploy", "agent1", body)
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		if !ok {
			t.Error("org B could not consume its own approval — the org predicate must " +
				"scope the gate, not empty it")
		}
	})

	t.Run("a tenantless caller is refused rather than writing an invisible row", func(t *testing.T) {
		if _, _, err := s.createOrGetPendingToolApproval(ctx, "", serverB, "deploy", "agent1", "sub", []byte(`{"x":1}`)); err == nil {
			t.Error("an approval was opened with no organization; such a row is invisible " +
				"to the pending list, so the administrator is never asked and the agent waits for ever")
		}
		var n int
		_ = db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM mcp_tool_approvals WHERE org_id IS NULL").Scan(&n)
		if n != 0 {
			t.Errorf("%d approval rows carry a NULL tenant", n)
		}
	})

	t.Run("another tenant cannot decide this approval", func(t *testing.T) {
		// A fresh pending approval owned by org B.
		id, _, err := s.createOrGetPendingToolApproval(ctx, orgB, serverB, "deploy", "agent1", "sub", []byte(`{"env":"stage"}`))
		if err != nil {
			t.Fatalf("open approval: %v", err)
		}

		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/mcp/approvals/"+id+"/approve", nil).
			WithContext(orgctx.With(orgctx.WithBypassRLS(context.Background()), orgctx.Org{ID: orgA}))
		c.Params = gin.Params{{Key: "id", Value: id}, {Key: "decision", Value: "approve"}}
		c.Set("user_id", "00000000-0000-0000-0000-0000000000a1")
		s.handleDecideToolApproval(c)

		if w.Code != http.StatusConflict {
			var got map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &got)
			t.Errorf("org A approved org B's pending tool call (%d): %v", w.Code, got)
		}
		var status string
		_ = db.Pool.QueryRow(ctx, "SELECT status FROM mcp_tool_approvals WHERE id=$1", id).Scan(&status)
		if status != "pending" {
			t.Errorf("org B's approval is now %q — another tenant decided an AI agent's tool call", status)
		}
	})
}
