package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// A grant a fulfilled access request wrote and a grant an administrator wrote
// are two rows with two lifetimes (migration v216), read together at connect.
// Through the real handlers on the migrated schema: the request's connect
// grant opens the entry; the administrator's grant on the same user is
// upserted beside it, not over it, and the grant list names which row came
// from which request; ending the request's grant (jitgrant.RevokeRequest, the
// expiry sweep's call) closes connect and leaves the standing grant; a
// standing connect grant opens it again.
func TestAnAdministratorsGrantAndARequestsGrantStandApart(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	octx := orgctx.With(ctx, orgctx.Org{ID: org})
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(octx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	seedUser := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2::text, $2::text || '@example.test', true) RETURNING id::text`,
			org, name+"-"+suffix)
	}
	admin, user := seedUser("prg-admin"), seedUser("prg-user")

	svc := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	as := func(userID string, roles ...string) *gin.Engine {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			c.Set("user_id", userID)
			c.Set("roles", append([]string{}, roles...))
			c.Next()
		})
		r.POST("/pam/entries", svc.handlePamCreateEntry)
		r.GET("/pam/entries/:id/grants", svc.handlePamListEntryGrants)
		r.POST("/pam/entries/:id/grants", svc.handlePamAddEntryGrant)
		r.POST("/pam/entries/:id/connect", svc.handlePamConnect)
		return r
	}
	call := func(r *gin.Engine, method, path, body string) (int, map[string]interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	adminAPI, userAPI := as(admin, "admin"), as(user, "user")

	// A website entry: connect answers without a broker, so the grant is the
	// whole decision.
	code, body := call(adminAPI, http.MethodPost, "/pam/entries",
		`{"name":"request grant `+suffix+`","entry_type":"website","url":"https://intranet.example.test"}`)
	entry, _ := body["id"].(string)
	if code != http.StatusCreated || entry == "" {
		t.Fatalf("create entry: %d %v", code, body)
	}
	connect := func() int {
		code, _ := call(userAPI, http.MethodPost, "/pam/entries/"+entry+"/connect", `{}`)
		return code
	}
	if code := connect(); code != http.StatusForbidden {
		t.Fatalf("connect with no grant: %d, want 403", code)
	}

	// What governance's fulfilment writes for an approved pam_entry request.
	req := scalar(`INSERT INTO access_requests (requester_id, resource_type, resource_id, resource_name, status, expires_at, org_id)
		VALUES ($1::uuid, 'pam_entry', $2::uuid, 'request grant', 'fulfilled', NOW() + interval '1 hour', $3::uuid) RETURNING id::text`,
		user, entry, org)
	if _, err := db.Pool.Exec(octx, `INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions, expires_at, request_id)
		VALUES ($1::uuid, $2::uuid, 'user', $3, '{connect}', NOW() + interval '1 hour', $4::uuid)`, org, entry, user, req); err != nil {
		t.Fatal(err)
	}
	if code := connect(); code != http.StatusOK {
		t.Fatalf("connect on the request's grant: %d, want 200", code)
	}

	for i := 0; i < 2; i++ {
		if code, body := call(adminAPI, http.MethodPost, "/pam/entries/"+entry+"/grants",
			`{"principal_type":"user","principal_id":"`+user+`","actions":["view"]}`); code != http.StatusCreated {
			t.Fatalf("the administrator's view grant (%d): %d %v", i+1, code, body)
		}
	}
	code, body = call(adminAPI, http.MethodGet, "/pam/entries/"+entry+"/grants", "")
	grants, _ := body["grants"].([]interface{})
	var standing, fromRequest int
	for _, g := range grants {
		m, _ := g.(map[string]interface{})
		if m["request_id"] == req {
			fromRequest++
		} else if m["request_id"] == nil {
			standing++
		}
	}
	if code != http.StatusOK || standing != 1 || fromRequest != 1 {
		t.Errorf("the grant list: %d, %d standing and %d from the request; want 1 and 1: %v", code, standing, fromRequest, grants)
	}

	if err := jitgrant.RevokeRequest(octx, db.Pool, req, "pam_entry", user, entry, org); err != nil {
		t.Fatal(err)
	}
	if code := connect(); code != http.StatusForbidden {
		t.Errorf("connect after the request's grant ended: %d, want 403", code)
	}
	if got := scalar(`SELECT array_to_string(actions, ',') FROM pam_entry_grants WHERE entry_id = $1::uuid AND request_id IS NULL AND (expires_at IS NULL OR expires_at > NOW())`, entry); got != "view" {
		t.Errorf("the standing grant after the request ended: %q, want view", got)
	}

	if code, body := call(adminAPI, http.MethodPost, "/pam/entries/"+entry+"/grants",
		`{"principal_type":"user","principal_id":"`+user+`","actions":["view","connect"]}`); code != http.StatusCreated {
		t.Fatalf("the administrator's connect grant: %d %v", code, body)
	}
	if code := connect(); code != http.StatusOK {
		t.Errorf("connect on the standing grant: %d, want 200", code)
	}
}
