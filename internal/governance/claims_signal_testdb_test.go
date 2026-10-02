package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/ssfsignal"
	"github.com/openidx/openidx/internal/migrations"
)

// The tenant's SSF receivers are told when a role or a group an access request
// gives begins and when it ends (section 6.10 of the third-party access
// framework). On the migrated schema, through the real request and approval
// handlers and the expiry tick:
//
//   - approving a role request and a group request enqueues one
//     token-claims-change each, about the requester, in the request's
//     organization;
//   - an application request enqueues nothing: an application is not in the
//     token;
//   - when the windows end, the tick enqueues one more for the role and one
//     for the group, after the access is gone, and nothing for the
//     application; a second tick enqueues nothing.
func TestARoleOrGroupRequestTellsTheReceiversWhenItBeginsAndEnds(t *testing.T) {
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
	administrator := scalar(`SELECT id::text FROM users WHERE username = 'admin'`)
	requester := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "cs-requester-"+suffix)
	role := scalar(`INSERT INTO roles (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "cs-role-"+suffix)
	group := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "cs-group-"+suffix)
	app := scalar(`INSERT INTO applications (org_id, client_id, name, type) VALUES ($1, $2, $2, 'web') RETURNING id::text`,
		org, "cs-app-"+suffix)

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
	grant := func(resourceType, resourceID string) {
		t.Helper()
		if code, body := call(requester, "/requests", fmt.Sprintf(
			`{"resource_type":%q,"resource_id":%q,"resource_name":"cs","justification":"release","duration":"2h"}`,
			resourceType, resourceID)); code != http.StatusCreated {
			t.Fatalf("file a %s request: %d %v", resourceType, code, body)
		}
		id := scalar(`SELECT id::text FROM access_requests WHERE requester_id = $1 AND resource_id = $2::uuid
			ORDER BY created_at DESC LIMIT 1`, requester, resourceID)
		if code, body := call(administrator, "/requests/"+id+"/approve", `{"comments":"ok"}`, "admin"); code != http.StatusOK || body["status"] != "fulfilled" {
			t.Fatalf("approve the %s request: %d %v", resourceType, code, body)
		}
	}
	// signals reads what was enqueued about the requester, oldest first, as
	// "<event>:<reason>", and fails on a row of the wrong kind or tenant.
	signals := func() []string {
		t.Helper()
		rows, err := db.Pool.Query(orgctx.WithBypassRLS(bg),
			`SELECT org_id::text, event_type, COALESCE(claims->>'reason', '') FROM ssf_pending_events WHERE subject_id = $1 ORDER BY id`, requester)
		if err != nil {
			t.Fatalf("read the SSF signals: %v", err)
		}
		defer rows.Close()
		out := []string{}
		for rows.Next() {
			var rowOrg, event, reason string
			if err := rows.Scan(&rowOrg, &event, &reason); err != nil {
				t.Fatalf("read an SSF signal: %v", err)
			}
			if rowOrg != org || event != ssfsignal.TokenClaimsChange {
				t.Errorf("a signal about the requester is %s in org %s; want token-claims-change in %s", event, rowOrg, org)
			}
			out = append(out, reason)
		}
		return out
	}

	grant("role", role)
	if got := signals(); !slices.Equal(got, []string{"access_granted"}) {
		t.Fatalf("after the role was granted: %v, want [access_granted]", got)
	}
	grant("group", group)
	grant("application", app)
	if got := signals(); !slices.Equal(got, []string{"access_granted", "access_granted"}) {
		t.Fatalf("after the group and the application were granted: %v, want two, the role's and the group's", got)
	}

	// Two hours and a minute pass.
	if _, err := db.Pool.Exec(ctx, `UPDATE access_requests SET expires_at = expires_at - interval '2 hours 1 minute' WHERE requester_id = $1`, requester); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE user_application_assignments SET expires_at = expires_at - interval '2 hours 1 minute' WHERE user_id = $1`, requester); err != nil {
		t.Fatal(err)
	}
	s.RunJITExpiryOnce(bg)
	want := []string{"access_granted", "access_granted", "access_ended", "access_ended"}
	if got := signals(); !slices.Equal(got, want) {
		t.Fatalf("after the windows ended: %v, want %v", got, want)
	}
	// Told after the access is gone, so the claims the drainer reads are the
	// new ones.
	if n := scalar(`SELECT (SELECT count(*) FROM user_roles WHERE user_id = $1) + (SELECT count(*) FROM group_memberships WHERE user_id = $1)`,
		requester); n != "0" {
		t.Errorf("the requester still holds %s of the role and the group after the tick", n)
	}
	s.RunJITExpiryOnce(bg)
	if got := signals(); !slices.Equal(got, want) {
		t.Errorf("a second tick enqueued more: %v", got)
	}
}
