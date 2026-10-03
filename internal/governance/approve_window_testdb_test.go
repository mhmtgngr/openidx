package governance

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

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// A time-bound request approved through the approver's own route is granted
// for its window. The handler read the request back without its expires_at,
// and a PAM entry connection (like a vault credential or a network service)
// refuses an unbounded grant, so the approval was recorded and nothing was
// granted. On the migrated schema: a PAM connection request is filed, its
// approver approves it through handleApproveRequest, and the grant ends when
// the request does.
func TestAnApprovedRequestIsGrantedForItsWindow(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gin.SetMode(gin.TestMode)
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(bg, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	user := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
			org, name+"-"+suffix)
	}
	requester, approver := user("aw-requester"), user("aw-approver")
	entry := scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port)
		VALUES ($1, $2, 'ssh', 'target.example.test', 22) RETURNING id::text`, org, "aw-db-"+suffix)
	if _, err := db.Pool.Exec(ctx, `INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
		VALUES ($1, $2, 'user', $3, '{view}')`, org, entry, requester); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO approval_policies (org_id, name, resource_type, resource_id, approval_steps, enabled)
		VALUES ($1, $2, 'pam_entry', $3, $4::jsonb, true)`, org, "aw-"+suffix, entry,
		fmt.Sprintf(`[{"type":"specific_user","approver_id":%q}]`, approver)); err != nil {
		t.Fatal(err)
	}

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	call := func(userID, path, body string) (int, map[string]interface{}) {
		t.Helper()
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			c.Set("user_id", userID)
			c.Set("roles", []string{"user"})
			c.Next()
		})
		r.POST("/requests", s.handleCreateAccessRequest)
		r.POST("/requests/:id/approve", s.handleApproveRequest)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	if code, body := call(requester, "/requests", fmt.Sprintf(
		`{"resource_type":"pam_entry","resource_id":%q,"justification":"patch window","duration":"4h"}`, entry)); code != http.StatusCreated {
		t.Fatalf("file the request: %d %v", code, body)
	}
	request := scalar(`SELECT id::text FROM access_requests WHERE requester_id = $1`, requester)
	if code, body := call(approver, "/requests/"+request+"/approve", `{"comments":"ok"}`); code != http.StatusOK || body["status"] != "fulfilled" {
		t.Fatalf("the approver approves: %d %v, want 200 fulfilled", code, body)
	}
	if got := scalar(`SELECT (g.expires_at = r.expires_at)::text FROM pam_entry_grants g JOIN access_requests r ON r.id = g.request_id
		WHERE g.request_id = $1`, request); got != "true" {
		t.Errorf("the grant does not end with the request's window")
	}
}
