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
)

// Replacing a user's role set keeps the window of each role the new set
// keeps. The replacement wrote every role back standing, so editing a user's
// roles in the console made a time-bound role permanent: one an access request
// gave (migration v223) or an administrator gave until a date. On the migrated
// schema, through PUT /users/:id/roles:
//
//   - a standing role stays standing;
//   - a role with a window keeps it;
//   - a role whose window has ended, and that the role-expiry sweep has not
//     yet removed, keeps its end and is not brought back;
//   - a role the set adds is standing;
//   - a role the set leaves out is gone.
func TestReplacingARoleSetKeepsEachRolesWindow(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	admin := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "rs-admin-"+suffix)
	subject := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "rs-subject-"+suffix)
	role := func(name, expires string) string {
		t.Helper()
		id := scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1, $2, '') RETURNING id::text`, org, name+"-"+suffix)
		if expires != "-" {
			var window interface{}
			if expires != "" {
				window = scalar(`SELECT (NOW() + $1::interval)::text`, expires)
			}
			if _, err := db.Pool.Exec(ctx, `INSERT INTO user_roles (user_id, role_id, org_id, expires_at) VALUES ($1, $2, $3, $4::timestamptz)`,
				subject, id, org, window); err != nil {
				t.Fatalf("assign %s: %v", name, err)
			}
		}
		return id
	}
	standing := role("rs-standing", "")
	timed := role("rs-timed", "2 hours")
	lapsed := role("rs-lapsed", "-1 minute")
	dropped := role("rs-dropped", "")
	added := role("rs-added", "-")
	window := func(roleID string) string {
		return scalar(`SELECT COALESCE((SELECT COALESCE(expires_at::text, 'standing') FROM user_roles WHERE user_id = $1 AND role_id = $2), 'none')`,
			subject, roleID)
	}
	before := map[string]string{timed: window(timed), lapsed: window(lapsed)}

	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("user_id", admin)
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	r.PUT("/users/:id/roles", svc.handleUpdateUserRoles)
	w := httptest.NewRecorder()
	// The ids in capitals, as a client may send them: a kept role is matched
	// whatever their case.
	body := fmt.Sprintf(`{"role_ids":[%q,%q,%q,%q]}`, standing, strings.ToUpper(timed), lapsed, added)
	req := httptest.NewRequest(http.MethodPut, "/users/"+subject+"/roles", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("replace the role set: %d %s", w.Code, w.Body.String())
	}

	for _, c := range []struct{ name, id, want string }{
		{"a standing role", standing, "standing"},
		{"a role with a window", timed, before[timed]},
		{"a role whose window has ended", lapsed, before[lapsed]},
		{"a role the set adds", added, "standing"},
		{"a role the set leaves out", dropped, "none"},
	} {
		if got := window(c.id); got != c.want {
			t.Errorf("%s is %s after the replacement; want %s", c.name, got, c.want)
		}
	}
}
