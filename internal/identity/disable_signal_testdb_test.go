package identity

import (
	"context"
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
	"github.com/openidx/openidx/internal/common/ssfsignal"
)

// An administrator's edit that disables an account tells the SSF receivers,
// as offboarding, deletion and a lifecycle policy do. The edit runs whenever
// the account ends up disabled, so the signal goes on the edit that turns it
// off and on no other. On the migrated schema, through PUT /users/:id:
//
//   - the edit that disables the account enqueues one account-disabled;
//   - an edit of the account while it is disabled enqueues nothing;
//   - enabling it enqueues nothing, and disabling it again one more;
//   - an edit that leaves an account enabled enqueues nothing.
func TestDisablingAnAccountTellsTheReceiversOnce(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user := func(name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `INSERT INTO users (org_id, username, email, enabled) VALUES ($1, $2::text, $2::text || '@example.test', true) RETURNING id::text`,
			org, name+"-"+suffix).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		return id
	}
	admin, subject, bystander := user("ds-admin"), user("ds-subject"), user("ds-bystander")
	signals := func(id string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM ssf_pending_events WHERE subject_id = $1 AND event_type = $2`,
			id, ssfsignal.AccountDisabled).Scan(&n); err != nil {
			t.Fatalf("count the signals: %v", err)
		}
		return n
	}

	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("user_id", admin)
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	r.PUT("/users/:id", svc.handleUpdateUser)
	edit := func(id string, enabled bool, lastName string) {
		t.Helper()
		body := fmt.Sprintf(`{"userName":%q,"name":{"familyName":%q},"emails":[{"value":%q,"primary":true}],"enabled":%v,"active":%v}`,
			"user-"+id, lastName, id+"@example.test", enabled, enabled)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/users/"+id, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("edit %s (enabled=%v): %d %s", id, enabled, w.Code, w.Body.String())
		}
	}

	edit(subject, false, "Leaver")
	if n := signals(subject); n != 1 {
		t.Fatalf("the edit that disabled the account enqueued %d account-disabled, want 1", n)
	}
	edit(subject, false, "Renamed")
	if n := signals(subject); n != 1 {
		t.Errorf("an edit of the disabled account enqueued another: %d", n)
	}
	edit(subject, true, "Back")
	if n := signals(subject); n != 1 {
		t.Errorf("enabling the account enqueued one: %d", n)
	}
	edit(subject, false, "Gone")
	if n := signals(subject); n != 2 {
		t.Errorf("disabling it again enqueued %d in all, want 2", n)
	}
	edit(bystander, true, "Stays")
	if n := signals(bystander); n != 0 {
		t.Errorf("an edit that kept the account enabled enqueued %d", n)
	}
}
