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
	"github.com/openidx/openidx/internal/migrations"
)

// An access review is read by its reviewer, an auditor and an administrator.
// Its items name who holds what across the organization, and the list, the
// review and its items answered anyone signed in, with OPA off; with OPA on,
// the reviewer's routes are now open to every signed-in caller so that a
// reviewer who is not an auditor reaches their own review, and the handler is
// what keeps everyone else out. On the migrated schema, through the handlers:
//
//   - the list shows a reviewer their own reviews only, and an auditor and an
//     administrator every review;
//   - a review and its items answer their reviewer, an auditor and an
//     administrator, and anyone else not found;
//   - a decision still needs the reviewer or an administrator: an auditor
//     reads a review it may not decide.
func TestAnAccessReviewIsReadByItsReviewerAnAuditorAndAnAdministrator(t *testing.T) {
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
	reviewer, other, stranger, auditor, admin := user("rv-reviewer"), user("rv-other"), user("rv-stranger"), user("rv-auditor"), user("rv-admin")
	review := func(name, reviewerID string) string {
		id := scalar(`INSERT INTO access_reviews (org_id, name, type, status, reviewer_id, start_date, end_date)
			VALUES ($1, $2, 'user_access', 'in_progress', $3, NOW(), NOW() + interval '7 days') RETURNING id::text`,
			org, name+"-"+suffix, reviewerID)
		scalar(`INSERT INTO review_items (org_id, review_id, user_id, resource_type, resource_id)
			VALUES ($1, $2, $3, 'role', 'admin') RETURNING id::text`, org, id, stranger)
		return id
	}
	mine, theirs := review("rv-mine", reviewer), review("rv-theirs", other)

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	call := func(caller, method, path, body string, roles ...string) (int, []byte) {
		t.Helper()
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			c.Set("user_id", caller)
			c.Set("roles", append([]string{}, roles...))
			c.Next()
		})
		r.GET("/reviews", s.handleListReviews)
		r.GET("/reviews/:id", s.handleGetReview)
		r.GET("/reviews/:id/items", s.handleListReviewItems)
		r.POST("/reviews/:id/items/batch-decision", s.handleBatchDecision)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		if body != "" {
			req = httptest.NewRequest(method, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
		}
		r.ServeHTTP(w, req)
		return w.Code, w.Body.Bytes()
	}
	listed := func(caller string, roles ...string) []string {
		t.Helper()
		code, body := call(caller, http.MethodGet, "/reviews?limit=1000", "", roles...)
		if code != http.StatusOK {
			t.Fatalf("list as %v: %d %s", roles, code, body)
		}
		var reviews []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &reviews); err != nil {
			t.Fatalf("list body: %v %s", err, body)
		}
		out := []string{}
		for _, r := range reviews {
			if r.ID == mine || r.ID == theirs {
				out = append(out, r.ID)
			}
		}
		slices.Sort(out)
		return out
	}
	both := []string{mine, theirs}
	slices.Sort(both)

	if got := listed(reviewer, "user"); !slices.Equal(got, []string{mine}) {
		t.Errorf("the reviewer's list holds %v, want only their own review", got)
	}
	if got := listed(stranger, "user"); len(got) != 0 {
		t.Errorf("a user who reviews nothing lists %v, want none", got)
	}
	for _, role := range []string{"auditor", "admin"} {
		if got := listed(auditor, role); !slices.Equal(got, both) {
			t.Errorf("an %s lists %v, want both reviews", role, got)
		}
	}

	for _, c := range []struct {
		who, caller, review string
		roles               []string
		want                int
	}{
		{"its reviewer", reviewer, mine, []string{"user"}, http.StatusOK},
		{"another reviewer", reviewer, theirs, []string{"user"}, http.StatusNotFound},
		{"a user who reviews nothing", stranger, mine, []string{"user"}, http.StatusNotFound},
		{"an auditor", auditor, theirs, []string{"auditor"}, http.StatusOK},
		{"an administrator", admin, theirs, []string{"admin"}, http.StatusOK},
	} {
		for _, path := range []string{"/reviews/" + c.review, "/reviews/" + c.review + "/items"} {
			if code, body := call(c.caller, http.MethodGet, path, "", c.roles...); code != c.want {
				t.Errorf("%s reading %s: %d %s, want %d", c.who, path, code, body, c.want)
			}
		}
	}

	// An auditor reads every review and decides none it is not assigned.
	if code, body := call(auditor, http.MethodPost, "/reviews/"+theirs+"/items/batch-decision",
		`{"item_ids":[],"decision":"approved"}`, "auditor"); code != http.StatusForbidden {
		t.Errorf("an auditor deciding a review it is not the reviewer of: %d %s, want 403", code, body)
	}
}
