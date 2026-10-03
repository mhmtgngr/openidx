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
	"github.com/openidx/openidx/internal/jitgrant"
	"github.com/openidx/openidx/internal/migrations"
	"github.com/openidx/openidx/internal/pamgrant"
)

// Section 6.9 of the third-party access framework: a PAM entry connection is a
// governance request. The test drives handleCreateAccessRequest, fulfillRequest,
// the expiry sweep and the kill switch's elevation sever on the migrated
// schema, and checks both halves at each step:
//
//   - who may ask: an entry the requester sees (a standing 'view' grant) is
//     taken, with the entry's own name on the request; an entry they cannot
//     see answers 404 like a missing one, an entry they can already connect
//     to (through a role) answers 409, and a request with no duration 400;
//   - fulfilment writes one 'connect' grant carrying the request's id and
//     window, beside the standing grant, and a retry writes nothing twice;
//   - the expiry sweep ends that grant and only that grant: the standing
//     'view' grant survives and the entry stays visible;
//   - the kill switch's sever (jitgrant.EndAllForUser) ends a live request's
//     grant instead of failing on an unknown type, and a review's revoke
//     (jitgrant.Revoke) ends every grant the user holds on the entry.
func TestAPamEntryRequestGrantsConnectForItsWindow(t *testing.T) {
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
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
	}
	requester := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "pamreq-"+suffix)
	entry := func(name string) string {
		return scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port)
			VALUES ($1::uuid, $2, 'ssh', 'target.example.test', 22) RETURNING id::text`, org, name+"-"+suffix)
	}
	seen, hidden, held := entry("prod-db"), entry("hidden"), entry("build-agent")
	exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
		VALUES ($1::uuid, $2::uuid, 'user', $3, '{view}')`, org, seen, requester)
	exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
		VALUES ($1::uuid, $2::uuid, 'role', 'pam-operators', '{view,connect}')`, org, held)

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("user_id", requester)
		c.Set("roles", []string{"user", "pam-operators"})
		c.Next()
	})
	r.POST("/requests", s.handleCreateAccessRequest)
	request := func(entryID, name, duration string) (int, map[string]interface{}) {
		t.Helper()
		body := fmt.Sprintf(`{"resource_type":"pam_entry","resource_id":%q,"resource_name":%q,"justification":"patch window","duration":%q}`,
			entryID, name, duration)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/requests", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	filed := func(entryID string) string {
		return scalar(`SELECT count(*)::text FROM access_requests WHERE requester_id = $1 AND resource_id = $2::uuid`, requester, entryID)
	}
	holds := func(entryID, action string) bool {
		t.Helper()
		ok, err := pamgrant.Holds(ctx, db.Pool, org, entryID, requester, []string{"user"}, action)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	t.Run("who may ask", func(t *testing.T) {
		for _, tc := range []struct {
			what, entry, duration string
			status                int
			code                  string
		}{
			{"an entry the requester cannot see", hidden, "4h", http.StatusNotFound, "pam_entry_not_found"},
			{"an entry that is not one", "not-a-uuid", "4h", http.StatusNotFound, "pam_entry_not_found"},
			{"an entry the requester can already connect to", held, "4h", http.StatusConflict, "pam_entry_already_granted"},
			{"a request with no duration", seen, "", http.StatusBadRequest, "pam_entry_duration_required"},
		} {
			code, body := request(tc.entry, "whatever", tc.duration)
			if code != tc.status || body["code"] != tc.code {
				t.Errorf("%s: %d %v, want %d %s", tc.what, code, body, tc.status, tc.code)
			}
		}
		if n := filed(hidden); n != "0" {
			t.Errorf("a refused request left %s row(s) behind", n)
		}
	})

	code, body := request(seen, "not the entry's name", "4h")
	if code != http.StatusCreated {
		t.Fatalf("a request for an entry the requester sees: %d %v", code, body)
	}
	reqID, _ := body["id"].(string)
	if got := scalar(`SELECT resource_name FROM access_requests WHERE id = $1`, reqID); got != "prod-db-"+suffix {
		t.Errorf("the request names %q, want the entry's own name", got)
	}

	fulfil := func(id string) {
		t.Helper()
		var ar AccessRequest
		if err := db.Pool.QueryRow(ctx, `SELECT id::text, requester_id::text, resource_type, resource_id::text, expires_at
			FROM access_requests WHERE id = $1`, id).Scan(&ar.ID, &ar.RequesterID, &ar.ResourceType, &ar.ResourceID, &ar.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		exec(`UPDATE access_requests SET status = 'approved' WHERE id = $1`, id)
		if err := s.fulfillRequest(ctx, &ar); err != nil {
			t.Fatalf("fulfil: %v", err)
		}
	}

	t.Run("fulfilment writes the request's own connect grant", func(t *testing.T) {
		if holds(seen, "connect") {
			t.Fatal("the requester could connect before the request was fulfilled")
		}
		fulfil(reqID)
		fulfil(reqID) // a retry writes nothing twice
		var n int
		var actions []string
		var grantEnd, requestEnd time.Time
		if err := db.Pool.QueryRow(ctx, `
			SELECT count(*), max(g.actions::text)::text[], max(g.expires_at), max(r.expires_at)
			  FROM pam_entry_grants g JOIN access_requests r ON r.id = g.request_id
			 WHERE g.request_id = $1`, reqID).Scan(&n, &actions, &grantEnd, &requestEnd); err != nil {
			t.Fatal(err)
		}
		if n != 1 || len(actions) != 1 || actions[0] != "connect" || !grantEnd.Equal(requestEnd) {
			t.Errorf("the request's grants: %d, actions %v, ending %v; want one connect grant ending with the request at %v",
				n, actions, grantEnd, requestEnd)
		}
		if !holds(seen, "connect") {
			t.Error("the fulfilled request does not let the requester connect")
		}
		if n := scalar(`SELECT count(*)::text FROM pam_entry_grants WHERE entry_id = $1 AND principal_id = $2 AND request_id IS NULL`, seen, requester); n != "1" {
			t.Errorf("the standing view grant: %s row(s), want it kept beside the request's", n)
		}
	})

	t.Run("the expiry sweep ends the request's grant and only that one", func(t *testing.T) {
		exec(`UPDATE access_requests SET expires_at = NOW() - interval '1 minute' WHERE id = $1`, reqID)
		s.revokeExpiredJITAccess(orgctx.WithBypassRLS(bg))
		if st := scalar(`SELECT status FROM access_requests WHERE id = $1`, reqID); st != "expired" {
			t.Errorf("the request is %s after the sweep, want expired", st)
		}
		if holds(seen, "connect") {
			t.Error("the requester can still connect after the request expired")
		}
		if !holds(seen, "") {
			t.Error("the expiry took the standing view grant with it")
		}
	})

	t.Run("the kill switch's sever and a review's revoke", func(t *testing.T) {
		code, body := request(seen, "", "8h")
		if code != http.StatusCreated {
			t.Fatalf("a second request: %d %v", code, body)
		}
		second, _ := body["id"].(string)
		fulfil(second)
		if !holds(seen, "connect") {
			t.Fatal("the second request did not grant connect")
		}
		ended, err := jitgrant.EndAllForUser(ctx, db.Pool, requester, org)
		if err != nil || ended != 1 {
			t.Fatalf("EndAllForUser: ended %d, %v; want 1 and no error", ended, err)
		}
		if holds(seen, "connect") || !holds(seen, "") {
			t.Error("after the sever the requester still connects, or lost the standing view grant")
		}
		if err := jitgrant.Revoke(ctx, db.Pool, "pam_entry", requester, seen, org); err != nil {
			t.Fatal(err)
		}
		if holds(seen, "") {
			t.Error("a review's revoke left the requester a grant on the entry")
		}
		if jitgrant.TokenCarries("pam_entry") {
			t.Error("a PAM entry grant is read live; ending one must not cut the user's tokens")
		}
	})
}
