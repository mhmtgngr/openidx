package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Tenant isolation for remote support sessions, migration v150.
//
// A remote support session is an administrator watching or driving an end
// user's screen. HandleListSessions was:
//
//	SELECT s.id, s.agent_id, ... FROM remote_support_sessions s
//	 ORDER BY s.started_at DESC LIMIT 200
//
// No WHERE clause at all — every tenant's remote support history on any
// tenant's console, and no belt behind the omission because the table was on
// needsBelt with fourteen unscoped queries.
//
// The second case is the one that made this batch delicate. org_id was
// NULLABLE, and belting a nullable tenant column HIDES rows rather than
// scoping them: a NULL-org session is invisible to every scoped query at once,
// so the administrator who started it cannot list it, end it, or revoke its
// recording — while the session keeps running, because the broker holds the
// peer in memory and never re-reads the row. The handler refuses at the door
// now, and the test pins the refusal rather than the NULL write.
//
// The third pins the other direction: the DEVICE paths must keep working
// without a tenant, because the agent authenticates as a device. Belting the
// agent's own session poll without a bypass leaves a device that can never be
// helped.
func TestRemoteSupport_TenantIsolation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	var orgB string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('rs-b','rs-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	seedSession := func(org, agent string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO remote_support_sessions (agent_id, status, mode, org_id)
			VALUES ($1, 'active', 'interactive', $2) RETURNING id::text`, agent, org).Scan(&id); err != nil {
			t.Fatalf("seed session for %s: %v", agent, err)
		}
		return id
	}
	agentA := "rs-agent-a-" + suffix
	agentB := "rs-agent-b-" + suffix
	sessionA := seedSession(orgA, agentA)
	sessionB := seedSession(orgB, agentB)

	h := &RemoteSupportHandler{db: db, logger: zap.NewNop()}

	call := func(org string, fn gin.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := context.Background()
		if org != "" {
			rctx = orgctx.With(rctx, orgctx.Org{ID: org})
		}
		c.Request = req.WithContext(rctx)
		if org != "" {
			c.Set("org_id", org)
		}
		c.Set("user_id", "00000000-0000-0000-0000-000000000001")
		fn(c)
		return w
	}

	// THE DISCLOSURE.
	t.Run("the session list is per org", func(t *testing.T) {
		w := call(orgB, h.HandleListSessions, http.MethodGet, "/remote-support/sessions", "")
		if w.Code != http.StatusOK {
			t.Fatalf("org B list: %d %s", w.Code, w.Body.String())
		}
		var got []struct {
			ID      string `json:"id"`
			AgentID string `json:"agent_id"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("bad json: %s", w.Body.String())
		}
		for _, r := range got {
			if r.ID == sessionA {
				t.Fatalf("org B's console lists org A's remote support session (agent %s). This "+
					"query had no WHERE clause: whose screen was taken over, by which "+
					"administrator, and whether a recording exists", r.AgentID)
			}
		}
		if len(got) != 1 || got[0].ID != sessionB {
			t.Fatalf("org B should see exactly its own session, got %d rows", len(got))
		}

		// And org A still sees its own — the predicate must scope, not empty.
		w = call(orgA, h.HandleListSessions, http.MethodGet, "/remote-support/sessions", "")
		got = got[:0]
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("bad json: %s", w.Body.String())
		}
		if len(got) != 1 || got[0].ID != sessionA {
			t.Fatalf("org A should see exactly its own session, got %d rows", len(got))
		}
	})

	// THE HAZARD.
	t.Run("a session with no organization is refused, not written NULL", func(t *testing.T) {
		before := countRemoteSessions(t, db, ctx)
		w := call("", h.HandleStartSession, http.MethodPost, "/remote-support/sessions",
			`{"agent_id":"rs-orphan-`+suffix+`","mode":"view"}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("a session started with no organization returned %d %s; it must be refused. "+
				"Written as NULL it is invisible to every scoped query — the admin who started it "+
				"cannot list, end or revoke it, while the broker keeps the peer connected",
				w.Code, w.Body.String())
		}
		if after := countRemoteSessions(t, db, ctx); after != before {
			t.Fatalf("the refused session was still written (%d -> %d rows)", before, after)
		}
	})

	// THE OTHER DIRECTION.
	//
	// WHAT THIS ONE CANNOT PROVE: it does not go red against the pre-v150
	// handlers, because before the belt there was nothing to fail closed
	// against, and this pool is a superuser so RLS never applies here anyway.
	// It is a forward guard — it fails if a later edit "tidies up" these
	// queries by adding an org predicate, which is exactly the change that
	// would leave a device unable to be helped. The belt's own half is proved
	// under the NOSUPERUSER role in test/integration/cross_org_test.go.
	t.Run("the device paths still work without a tenant", func(t *testing.T) {
		// The agent polls for its own session with no organization anywhere:
		// it authenticates as a device, not as a member of a tenant.
		info, ok := findActiveSessionForAgent(context.Background(), db, agentA)
		if !ok {
			t.Fatal("the agent's own session poll returned nothing on a context with no " +
				"organization. Under the belt this read must run bypassed; without that, a device " +
				"can never be helped — the admin starts a session and the agent never sees it")
		}
		if info.SessionID != sessionA {
			t.Fatalf("the agent got session %q, want its own %q", info.SessionID, sessionA)
		}

		// Ending a session is reachable from either peer, including the device.
		if err := h.endSession(context.Background(), sessionA, "test"); err != nil {
			t.Fatalf("endSession on a context with no organization: %v", err)
		}
		var status string
		if err := db.Pool.QueryRow(ctx,
			`SELECT status FROM remote_support_sessions WHERE id = $1`, sessionA).Scan(&status); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if status != "ended" {
			t.Fatalf("the session is %q after endSession; a session nobody can end is one the "+
				"broker keeps relaying", status)
		}
	})
}

func countRemoteSessions(t *testing.T, db *database.PostgresDB, ctx context.Context) int {
	t.Helper()
	var n int
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM remote_support_sessions`).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return n
}
