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

	"github.com/openidx/openidx/internal/appaccess"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/jitgrant"
	"github.com/openidx/openidx/internal/migrations"
)

// An application assignment ends with the window of the request that granted
// it (migration v222). On the migrated schema, through the real request and
// approval handlers:
//
//   - fulfilment writes the request's window on the assignment, keeps a
//     standing assignment standing, and of two windows keeps the later;
//   - the shared predicate (internal/appaccess) refuses the moment the window
//     is over, before the expiry tick has run;
//   - the tick then removes the assignment the request gave, and leaves the
//     standing one and the one a later request carried past it;
//   - the kill switch's elevation sweep ends a live request's assignment and
//     leaves a standing one.
func TestAnApplicationAssignmentEndsWithItsWindow(t *testing.T) {
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
	app := func(name string) string {
		return scalar(`INSERT INTO applications (org_id, client_id, name, type) VALUES ($1, $2, $2, 'web') RETURNING id::text`,
			org, name+"-"+suffix)
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
	// grant files a request for the application and has the administrator
	// approve it, and returns the request.
	grant := func(requester, appID, duration string) string {
		t.Helper()
		if code, body := call(requester, "/requests", fmt.Sprintf(
			`{"resource_type":"application","resource_id":%q,"resource_name":"app","justification":"release","duration":%q}`,
			appID, duration)); code != http.StatusCreated {
			t.Fatalf("file a %s request: %d %v", duration, code, body)
		}
		id := scalar(`SELECT id::text FROM access_requests WHERE requester_id = $1 AND resource_id = $2::uuid
			ORDER BY created_at DESC LIMIT 1`, requester, appID)
		if code, body := call(administrator, "/requests/"+id+"/approve", `{"comments":"ok"}`, "admin"); code != http.StatusOK || body["status"] != "fulfilled" {
			t.Fatalf("approve request %s: %d %v", id, code, body)
		}
		return id
	}
	allowed := func(userID, appID string) bool {
		t.Helper()
		ok, err := appaccess.Allowed(ctx, db, userID, org, appID)
		if err != nil {
			t.Fatalf("appaccess.Allowed: %v", err)
		}
		return ok
	}
	// assignment reads the user's assignment to the application: "none",
	// "standing", or whether its end is the request's.
	assignment := func(userID, appID, requestID string) string {
		return scalar(`SELECT COALESCE((SELECT CASE WHEN uaa.expires_at IS NULL THEN 'standing'
			                WHEN uaa.expires_at = r.expires_at THEN 'the request''s window'
			                ELSE 'another window' END
			   FROM user_application_assignments uaa, access_requests r
			  WHERE uaa.user_id = $1 AND uaa.application_id = $2::uuid AND r.id = $3::uuid), 'none')`,
			userID, appID, requestID)
	}
	statusOf := func(requestID string) string {
		return scalar(`SELECT status FROM access_requests WHERE id = $1`, requestID)
	}
	// elapse lets time pass for one user: every window of theirs moves back
	// by d, on the requests and on the assignments alike.
	elapse := func(userID, d string) {
		exec(`UPDATE access_requests SET expires_at = expires_at - $2::interval WHERE requester_id = $1 AND expires_at IS NOT NULL`, userID, d)
		exec(`UPDATE user_application_assignments SET expires_at = expires_at - $2::interval WHERE user_id = $1 AND expires_at IS NOT NULL`, userID, d)
	}

	requester := user("aw-requester")
	windowApp, standingApp, twiceApp := app("aw-window"), app("aw-standing"), app("aw-twice")
	// An administrator assigned one application before anyone asked for it.
	exec(`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1, $2, $3)`, requester, standingApp, org)

	windowRequest := grant(requester, windowApp, "2h")
	standingRequest := grant(requester, standingApp, "2h")
	firstRequest := grant(requester, twiceApp, "2h")
	laterRequest := grant(requester, twiceApp, "4h")

	t.Run("fulfilment writes the window, keeps a standing assignment and keeps the later window", func(t *testing.T) {
		if got := assignment(requester, windowApp, windowRequest); got != "the request's window" {
			t.Errorf("the requested application's assignment ends with %s", got)
		}
		if got := assignment(requester, standingApp, standingRequest); got != "standing" {
			t.Errorf("a request on a standing assignment left it %s", got)
		}
		if got := assignment(requester, twiceApp, laterRequest); got != "the request's window" {
			t.Errorf("two requests left the assignment ending with %s, want the later request's window", got)
		}
		for _, a := range []string{windowApp, standingApp, twiceApp} {
			if !allowed(requester, a) {
				t.Errorf("the requester cannot reach %s in the window", a)
			}
		}
	})

	t.Run("the window's end refuses before the tick, and the tick removes only what the request gave", func(t *testing.T) {
		elapse(requester, "2 hours 1 minute")
		if allowed(requester, windowApp) {
			t.Error("the window is over and the predicate still admits the requester")
		}
		if !allowed(requester, standingApp) {
			t.Error("the standing assignment stopped counting when a request's window ended")
		}
		if !allowed(requester, twiceApp) {
			t.Error("the first request's end cut the later request's window short")
		}

		s.RunJITExpiryOnce(ctx)
		if got := assignment(requester, windowApp, windowRequest); got != "none" {
			t.Errorf("after the tick the ended assignment is %s, want none", got)
		}
		if got := assignment(requester, standingApp, standingRequest); got != "standing" {
			t.Errorf("after the tick the standing assignment is %s", got)
		}
		if got := assignment(requester, twiceApp, laterRequest); got != "the request's window" {
			t.Errorf("after the tick the assignment the later request carries is %s", got)
		}
		for id, want := range map[string]string{windowRequest: "expired", standingRequest: "expired", firstRequest: "expired", laterRequest: "fulfilled"} {
			if got := statusOf(id); got != want {
				t.Errorf("request %s is %s, want %s", id, got, want)
			}
		}

		elapse(requester, "2 hours")
		if allowed(requester, twiceApp) {
			t.Error("the later window is over and the predicate still admits the requester")
		}
		s.RunJITExpiryOnce(ctx)
		if got := assignment(requester, twiceApp, laterRequest); got != "none" {
			t.Errorf("after the later window's tick the assignment is %s, want none", got)
		}
		if !allowed(requester, standingApp) {
			t.Error("the standing assignment did not outlast every request")
		}
	})

	t.Run("the kill switch ends a live request's assignment and leaves a standing one", func(t *testing.T) {
		severed := user("aw-severed")
		keptApp, requestedApp := app("aw-kept"), app("aw-requested")
		exec(`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1, $2, $3)`, severed, keptApp, org)
		grant(severed, keptApp, "2h")
		live := grant(severed, requestedApp, "2h")

		ended, err := jitgrant.EndAllForUser(orgctx.WithBypassRLS(bg), db.Pool, severed, org)
		if err != nil {
			t.Fatalf("EndAllForUser: %v", err)
		}
		if ended != 2 {
			t.Errorf("the kill switch ended %d elevations, want 2", ended)
		}
		if allowed(severed, requestedApp) {
			t.Error("the requested application is still reachable after the kill switch")
		}
		if got := assignment(severed, requestedApp, live); got != "none" {
			t.Errorf("the live request's assignment is %s after the kill switch, want none", got)
		}
		if !allowed(severed, keptApp) {
			t.Error("the kill switch's elevation sweep took the standing assignment")
		}
	})
}
