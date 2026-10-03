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

// TestAGroupReadCountsItsMembers: the list and the single read counted each
// group's members and dropped the count on the way out, so the console's
// Groups page showed 0 members for every group. A read that counted them now
// returns memberCount; an empty group leaves it out.
func TestAGroupReadCountsItsMembers(t *testing.T) {
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
			t.Fatalf("seed (%s): %v", q, err)
		}
		return v
	}
	full := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "counted-"+suffix)
	empty := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "counted-"+suffix+"-empty")
	for _, name := range []string{"first", "second"} {
		u := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
			org, name+"-"+suffix)
		scalar(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1, $2, $3) RETURNING user_id::text`, u, full, org)
	}

	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	r.GET("/groups", svc.handleListGroups)
	r.GET("/groups/:id", svc.handleGetGroup)
	get := func(path string, out interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
	}

	var list []map[string]interface{}
	get("/groups?search=counted-"+suffix, &list)
	counts := map[string]interface{}{}
	for _, g := range list {
		counts[g["id"].(string)] = g["memberCount"]
	}
	if counts[full] != float64(2) {
		t.Errorf("the list gives the group with two members memberCount %v; want 2", counts[full])
	}
	if _, listed := counts[empty]; !listed {
		t.Fatalf("the list did not return the empty group: %v", list)
	}
	if counts[empty] != nil {
		t.Errorf("the list gives the empty group memberCount %v; want it left out", counts[empty])
	}

	var one map[string]interface{}
	get("/groups/"+full, &one)
	if one["memberCount"] != float64(2) {
		t.Errorf("the group read gives memberCount %v; want 2", one["memberCount"])
	}
}

// TestAGroupIsCreatedWithItsSettings: creating a group wrote its name,
// description, parent and external flag, and dropped self-join, approval and
// the member cap, so a group created with a cap had none. A duplicate name,
// on create or on a rename, and an update of a group that does not exist,
// answered 500. Now the settings are written as an update writes them, a bad
// cap is refused, a duplicate answers 409 and a missing group 404.
func TestAGroupIsCreatedWithItsSettings(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)

	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	r.POST("/groups", svc.handleCreateGroup)
	r.PUT("/groups/:id", svc.handleUpdateGroup)
	call := func(method, path, body string) (int, map[string]interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	code, body := call(http.MethodPost, "/groups",
		`{"displayName":"capped-`+suffix+`","attributes":{"allowSelfJoin":"true","requireApproval":"true","maxMembers":"8"}}`)
	id, _ := body["id"].(string)
	if code != http.StatusCreated || id == "" {
		t.Fatalf("create: %d %v", code, body)
	}
	var selfJoin, approval bool
	var cap *int
	if err := db.Pool.QueryRow(ctx, `SELECT allow_self_join, require_approval, max_members FROM groups WHERE id = $1`, id).
		Scan(&selfJoin, &approval, &cap); err != nil {
		t.Fatalf("read the group: %v", err)
	}
	if !selfJoin || !approval || cap == nil || *cap != 8 {
		t.Errorf("the created group has selfJoin=%v approval=%v cap=%v; want true, true, 8", selfJoin, approval, cap)
	}

	code, body = call(http.MethodPost, "/groups", `{"displayName":"plain-`+suffix+`"}`)
	plain, _ := body["id"].(string)
	if code != http.StatusCreated || plain == "" {
		t.Fatalf("create without settings: %d %v", code, body)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT allow_self_join, require_approval, max_members FROM groups WHERE id = $1`, plain).
		Scan(&selfJoin, &approval, &cap); err != nil {
		t.Fatalf("read the group: %v", err)
	}
	if selfJoin || approval || cap != nil {
		t.Errorf("a group created without settings has selfJoin=%v approval=%v cap=%v; want the defaults", selfJoin, approval, cap)
	}

	for _, tc := range []struct {
		what, method, path, body string
		status                   int
		code                     interface{}
	}{
		{"a create with a cap of 0", http.MethodPost, "/groups",
			`{"displayName":"zero-` + suffix + `","attributes":{"maxMembers":"0"}}`, http.StatusBadRequest, "invalid_max_members"},
		{"a create of a name in use", http.MethodPost, "/groups",
			`{"displayName":"capped-` + suffix + `"}`, http.StatusConflict, "group_exists"},
		{"a rename onto a name in use", http.MethodPut, "/groups/" + plain,
			`{"displayName":"capped-` + suffix + `"}`, http.StatusConflict, "group_exists"},
		{"an update of a group that does not exist", http.MethodPut, "/groups/00000000-0000-0000-0000-00000000dead",
			`{"displayName":"ghost-` + suffix + `"}`, http.StatusNotFound, nil},
	} {
		if code, body := call(tc.method, tc.path, tc.body); code != tc.status || body["code"] != tc.code {
			t.Errorf("%s: %d %v; want %d %v", tc.what, code, body, tc.status, tc.code)
		}
	}
	var n int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE name = $1`, "zero-"+suffix).Scan(&n); err != nil || n != 0 {
		t.Errorf("the refused create left %d groups (%v)", n, err)
	}
}
