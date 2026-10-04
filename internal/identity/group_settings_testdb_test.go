package identity

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
)

// TestAGroupEditKeepsTheSettingsItDoesNotName drives the group routes on the
// migrated schema. A group's membership settings, self-join, approval and the
// member cap, are attributes on the API. The update wrote all three whatever
// it was sent, so an edit that named only the name, the console's edit form
// among them, turned self-join off and dropped the cap; and a read never
// returned them, so the console's settings dialog always showed them off.
//
// Now a read returns what is stored, an update keeps what it leaves out and
// changes what it names, an empty maxMembers clears the cap, and a cap that
// is not a positive whole number is refused.
func TestAGroupEditKeepsTheSettingsItDoesNotName(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)

	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	var group string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO groups (org_id, name, description, allow_self_join, require_approval, max_members)
		VALUES ($1, $2, 'Pager rota', true, true, 12) RETURNING id::text`,
		org, fmt.Sprintf("on-call-%d", time.Now().UnixNano())).Scan(&group); err != nil {
		t.Fatalf("seed the group: %v", err)
	}
	stored := func() string {
		t.Helper()
		var selfJoin, approval bool
		var cap *int
		if err := db.Pool.QueryRow(ctx,
			`SELECT allow_self_join, require_approval, max_members FROM groups WHERE id = $1`, group).
			Scan(&selfJoin, &approval, &cap); err != nil {
			t.Fatalf("read the group: %v", err)
		}
		c := "none"
		if cap != nil {
			c = fmt.Sprint(*cap)
		}
		return fmt.Sprintf("selfJoin=%v approval=%v cap=%s", selfJoin, approval, c)
	}

	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	r.GET("/groups/:id", svc.handleGetGroup)
	r.PUT("/groups/:id", svc.handleUpdateGroup)
	call := func(method, body string) (int, map[string]interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/groups/"+group, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	// A read returns the stored settings.
	code, body := call(http.MethodGet, "")
	attrs, _ := body["attributes"].(map[string]interface{})
	if code != http.StatusOK || attrs["allowSelfJoin"] != "true" || attrs["requireApproval"] != "true" || attrs["maxMembers"] != "12" {
		t.Fatalf("read the group: %d %v; want its settings in attributes", code, body)
	}

	// An edit that names only the name and description keeps them.
	if code, body := call(http.MethodPut, `{"displayName":"on-call-renamed","attributes":{"description":"Pager rota"}}`); code != http.StatusOK {
		t.Fatalf("rename: %d %v", code, body)
	}
	if got := stored(); got != "selfJoin=true approval=true cap=12" {
		t.Errorf("after a rename the group has %s; want its settings kept", got)
	}

	// An edit that names them changes them; an empty cap clears it.
	if code, body := call(http.MethodPut,
		`{"displayName":"on-call-renamed","attributes":{"allowSelfJoin":"false","requireApproval":"false","maxMembers":""}}`); code != http.StatusOK {
		t.Fatalf("change the settings: %d %v", code, body)
	}
	if got := stored(); got != "selfJoin=false approval=false cap=none" {
		t.Errorf("after the settings change the group has %s", got)
	}
	if code, body := call(http.MethodPut, `{"displayName":"on-call-renamed","attributes":{"maxMembers":"40"}}`); code != http.StatusOK {
		t.Fatalf("set the cap: %d %v", code, body)
	}
	if got := stored(); got != "selfJoin=false approval=false cap=40" {
		t.Errorf("after setting the cap the group has %s", got)
	}

	// A cap that is not a positive whole number is refused, and nothing changes.
	for _, bad := range []string{"0", "-3", "ten"} {
		code, body := call(http.MethodPut, `{"displayName":"on-call-renamed","attributes":{"allowSelfJoin":"true","maxMembers":"`+bad+`"}}`)
		if code != http.StatusBadRequest || body["code"] != "invalid_max_members" {
			t.Errorf("maxMembers %q: %d %v; want 400 invalid_max_members", bad, code, body)
		}
	}
	if got := stored(); got != "selfJoin=false approval=false cap=40" {
		t.Errorf("after the refused edits the group has %s", got)
	}
}
