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
)

// A role an access request gives ends with the request's window, and the
// request's end takes nothing else (migration v223). On the migrated schema,
// through the real request and approval handlers:
//
//   - fulfilment writes the request's window on the user_roles row, keeps a
//     standing assignment standing, and of two windows keeps the later;
//   - a token issued after the window reads the role as gone, before the
//     expiry tick has run (the token builder's predicate);
//   - the tick removes the role the request gave, and leaves an
//     administrator's standing assignment of the same role and the one a
//     later request carried past the first one's end;
//   - the kill switch's elevation sweep ends a live request's role and leaves
//     a standing one.
func TestARoleFromARequestEndsWithItsWindow(t *testing.T) {
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
	user := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
			org, name+"-"+suffix)
	}
	role := func(name string) string {
		return scalar(`INSERT INTO roles (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, name+"-"+suffix)
	}
	administrator := scalar(`SELECT id::text FROM users WHERE username = 'admin'`)

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	call := func(userID, path, body string, roles ...string) (int, map[string]interface{}) {
		t.Helper()
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			c.Set("user_id", userID)
			c.Set("roles", append([]string{}, roles...))
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
	// grant files a request for the role and has the administrator approve
	// it, and returns the request.
	grant := func(requester, roleID, duration string) string {
		t.Helper()
		if code, body := call(requester, "/requests", fmt.Sprintf(
			`{"resource_type":"role","resource_id":%q,"resource_name":"role","justification":"release","duration":%q}`,
			roleID, duration)); code != http.StatusCreated {
			t.Fatalf("file a %s request: %d %v", duration, code, body)
		}
		id := scalar(`SELECT id::text FROM access_requests WHERE requester_id = $1 AND resource_id = $2::uuid
			ORDER BY created_at DESC LIMIT 1`, requester, roleID)
		if code, body := call(administrator, "/requests/"+id+"/approve", `{"comments":"ok"}`, "admin"); code != http.StatusOK || body["status"] != "fulfilled" {
			t.Fatalf("approve request %s: %d %v", id, code, body)
		}
		return id
	}
	// assignment reads the user's assignment of the role: "none", "standing",
	// or whether its end is the request's.
	assignment := func(userID, roleID, requestID string) string {
		return scalar(`SELECT COALESCE((SELECT CASE WHEN ur.expires_at IS NULL THEN 'standing'
			                WHEN ur.expires_at = r.expires_at THEN 'the request''s window'
			                ELSE 'another window' END
			   FROM user_roles ur, access_requests r
			  WHERE ur.user_id = $1 AND ur.role_id = $2::uuid AND r.id = $3::uuid), 'none')`,
			userID, roleID, requestID)
	}
	// inToken is the predicate the token builder reads a role with
	// (internal/oauth authorizationClaims).
	inToken := func(userID, roleID string) bool {
		return scalar(`SELECT EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = $1 AND ur.role_id = $2::uuid AND ur.org_id = $3
			AND (ur.expires_at IS NULL OR ur.expires_at > NOW()))::text`, userID, roleID, org) == "true"
	}
	statusOf := func(requestID string) string {
		return scalar(`SELECT status FROM access_requests WHERE id = $1`, requestID)
	}
	// elapse lets time pass for one user: every window of theirs moves back
	// by d, on the requests and on the role assignments alike.
	elapse := func(userID, d string) {
		exec(`UPDATE access_requests SET expires_at = expires_at - $2::interval WHERE requester_id = $1 AND expires_at IS NOT NULL`, userID, d)
		exec(`UPDATE user_roles SET expires_at = expires_at - $2::interval WHERE user_id = $1 AND expires_at IS NOT NULL`, userID, d)
	}

	requester := user("rw-requester")
	windowRole, standingRole, twiceRole := role("rw-window"), role("rw-standing"), role("rw-twice")
	// An administrator assigned one role before anyone asked for it.
	exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1, $2, $3)`, requester, standingRole, org)

	windowReq := grant(requester, windowRole, "2h")
	standingReq := grant(requester, standingRole, "2h")
	firstReq := grant(requester, twiceRole, "2h")
	secondReq := grant(requester, twiceRole, "4h")

	if got := assignment(requester, windowRole, windowReq); got != "the request's window" {
		t.Errorf("fulfilment wrote the role as %s; want the request's window", got)
	}
	if got := assignment(requester, standingRole, standingReq); got != "standing" {
		t.Errorf("a request made an administrator's standing role %s; want it standing", got)
	}
	if got := assignment(requester, twiceRole, secondReq); got != "the request's window" {
		t.Errorf("a role two requests gave is %s; want the later window", got)
	}

	t.Run("at the window's end the token no longer carries the role, before the tick", func(t *testing.T) {
		if !inToken(requester, windowRole) {
			t.Fatal("the role is not in a token while its window lasts")
		}
		elapse(requester, "2 hours 1 minute")
		if inToken(requester, windowRole) {
			t.Error("the window ended and a token issued now still carries the role")
		}
		if !inToken(requester, standingRole) || !inToken(requester, twiceRole) {
			t.Error("the standing role or the one a later window carries left the token")
		}
	})

	t.Run("the tick removes only what the request gave", func(t *testing.T) {
		s.RunJITExpiryOnce(bg)
		if got := assignment(requester, windowRole, windowReq); got != "none" {
			t.Errorf("after the tick the requested role is %s; want none", got)
		}
		if got := assignment(requester, standingRole, standingReq); got != "standing" {
			t.Errorf("the request's end took the administrator's standing role: %s", got)
		}
		if got := assignment(requester, twiceRole, secondReq); got != "the request's window" {
			t.Errorf("the first request's end took the role a later request carried: %s", got)
		}
		for _, id := range []string{windowReq, standingReq, firstReq} {
			if got := statusOf(id); got != "expired" {
				t.Errorf("request %s is %s after its window; want expired", id, got)
			}
		}
		if got := statusOf(secondReq); got != "fulfilled" {
			t.Errorf("the later request is %s while its window lasts; want fulfilled", got)
		}
	})

	t.Run("the kill switch's elevation sweep ends a live request's role and keeps a standing one", func(t *testing.T) {
		victim := user("rw-victim")
		liveRole, keptRole := role("rw-live"), role("rw-kept")
		exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1, $2, $3)`, victim, keptRole, org)
		liveReq := grant(victim, liveRole, "2h")
		keptReq := grant(victim, keptRole, "2h")
		if _, err := jitgrant.EndAllForUser(ctx, db.Pool, victim, org); err != nil {
			t.Fatalf("EndAllForUser: %v", err)
		}
		if got := assignment(victim, liveRole, liveReq); got != "none" {
			t.Errorf("the kill switch left the requested role: %s", got)
		}
		if got := assignment(victim, keptRole, keptReq); got != "standing" {
			t.Errorf("the kill switch's elevation sweep took a standing role: %s", got)
		}
	})
}
