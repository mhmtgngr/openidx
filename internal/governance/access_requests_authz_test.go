package governance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestHandleListAccessRequests_NonAdminScopedToSelf guards the broken-access-
// control fix: GET /governance/requests must never return another user's
// requests to a non-admin caller, even when requester_id is omitted or points
// at someone else. An admin sees the whole org.
func TestHandleListAccessRequests_NonAdminScopedToSelf(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE access_requests (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id UUID NOT NULL,
			requester_id UUID NOT NULL,
			resource_type VARCHAR(64), resource_id VARCHAR(255), resource_name VARCHAR(255),
			justification TEXT, status VARCHAR(32) NOT NULL DEFAULT 'pending',
			priority VARCHAR(32) DEFAULT 'normal', expires_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());
		CREATE TABLE users (id UUID PRIMARY KEY, org_id UUID, username VARCHAR(255),
			first_name VARCHAR(255), last_name VARCHAR(255));
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const (
		org   = "00000000-0000-0000-0000-000000000010"
		alice = "11111111-1111-1111-1111-111111111111"
		bob   = "22222222-2222-2222-2222-222222222222"
	)
	exec := func(q string, args ...any) {
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("exec: %v", err)
		}
	}
	exec(`INSERT INTO users (id, org_id, username) VALUES ($1,$2,'alice'),($3,$2,'bob')`, alice, org, bob)
	exec(`INSERT INTO access_requests (org_id, requester_id, resource_type, resource_id, resource_name, justification, status, priority)
	      VALUES ($1,$2,'role','role-a','r-alice','need it','pending','normal'),
	             ($1,$3,'role','role-b','r-bob','need it','pending','normal')`, org, alice, bob)

	s := &Service{db: db, logger: zap.NewNop()}
	gin.SetMode(gin.TestMode)

	// Runs the handler as `caller` with `roles`, returns the requester_ids listed.
	listAs := func(caller string, roles []string, query string) []string {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/governance/requests"+query, nil)
		req = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		c.Request = req
		c.Set("user_id", caller)
		c.Set("roles", roles)

		s.handleListAccessRequests(c)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
		}
		var resp struct {
			Requests []struct {
				RequesterID string `json:"requester_id"`
			} `json:"requests"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		ids := make([]string, 0, len(resp.Requests))
		for _, r := range resp.Requests {
			ids = append(ids, r.RequesterID)
		}
		return ids
	}

	// Non-admin Bob, no requester_id → only his own request, never Alice's.
	got := listAs(bob, []string{"user"}, "")
	if len(got) != 1 || got[0] != bob {
		t.Fatalf("non-admin with no filter: want only bob's request, got %v", got)
	}

	// Non-admin Bob trying to read Alice's requests → still pinned to himself.
	got = listAs(bob, []string{"user"}, "?requester_id="+alice)
	if len(got) != 1 || got[0] != bob {
		t.Fatalf("non-admin spoofing requester_id: want only bob's request, got %v", got)
	}

	// Admin sees the whole org (both requesters).
	got = listAs(alice, []string{"admin"}, "")
	if len(got) != 2 {
		t.Fatalf("admin: want all 2 requests, got %v", got)
	}
}
