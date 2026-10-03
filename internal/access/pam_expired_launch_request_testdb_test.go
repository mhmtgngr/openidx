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
	"github.com/openidx/openidx/internal/migrations"
)

// A launch request lives an hour, and checkAndConsumePamApproval never
// honours one approved after that. So the administrator's queue leaves out a
// request whose hour has passed, as the sponsor's always did, and approving
// one is refused with a reason instead of recorded as an approval nobody can
// use. Denying it is still allowed. On the migrated schema, through the
// handlers.
func TestAnExpiredLaunchRequestIsNotApprovable(t *testing.T) {
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
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	seedUser := func(name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	admin, operator := seedUser("elr-admin"), seedUser("elr-operator")
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
		r.POST("/pam/entries/:id/grants", svc.handlePamAddEntryGrant)
		r.POST("/pam/entries/:id/request", svc.handlePamRequestAccess)
		r.GET("/pam/entry-requests", svc.handlePamListRequests)
		r.POST("/pam/entry-requests/:id/approve", svc.handlePamApproveRequest)
		r.POST("/pam/entry-requests/:id/deny", svc.handlePamDenyRequest)
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
	adminAPI, operatorAPI := as(admin, "admin"), as(operator)

	code, body := call(adminAPI, http.MethodPost, "/pam/entries", `{"name":"elr `+suffix+`","entry_type":"website",`+
		`"url":"https://elr.example.test","require_approval":true}`)
	entry, _ := body["id"].(string)
	if code != http.StatusCreated || entry == "" {
		t.Fatalf("create entry: %d %v", code, body)
	}
	if code, body := call(adminAPI, http.MethodPost, "/pam/entries/"+entry+"/grants",
		`{"principal_type":"user","principal_id":"`+operator+`","actions":["connect"]}`); code != http.StatusCreated {
		t.Fatalf("grant: %d %v", code, body)
	}
	request := func() string {
		t.Helper()
		code, body := call(operatorAPI, http.MethodPost, "/pam/entries/"+entry+"/request", `{"reason":"maintenance"}`)
		id, _ := body["request_id"].(string)
		if code != http.StatusCreated || id == "" {
			t.Fatalf("request: %d %v", code, body)
		}
		return id
	}
	fresh, stale, staleDenied := request(), request(), request()
	if _, err := db.Pool.Exec(orgctx.WithBypassRLS(ctx),
		`UPDATE pam_entry_access_requests SET expires_at = NOW() - interval '1 minute' WHERE id = ANY($1::uuid[])`,
		[]string{stale, staleDenied}); err != nil {
		t.Fatalf("let two requests' hour pass: %v", err)
	}

	code, body = call(adminAPI, http.MethodGet, "/pam/entry-requests", "")
	listed := map[string]bool{}
	if reqs, ok := body["requests"].([]interface{}); ok {
		for _, r := range reqs {
			if m, ok := r.(map[string]interface{}); ok {
				listed[m["id"].(string)] = true
			}
		}
	}
	if code != http.StatusOK || !listed[fresh] || listed[stale] || listed[staleDenied] {
		t.Errorf("the queue: %d, listed %v; want the live request and neither expired one", code, listed)
	}

	if code, body := call(adminAPI, http.MethodPost, "/pam/entry-requests/"+stale+"/approve", `{}`); code != http.StatusConflict || body["code"] != "launch_request_expired" {
		t.Errorf("approving an expired request: %d %v; want 409 launch_request_expired", code, body)
	}
	if code, body := call(adminAPI, http.MethodPost, "/pam/entry-requests/"+staleDenied+"/deny", `{}`); code != http.StatusOK {
		t.Errorf("denying an expired request: %d %v; want 200", code, body)
	}
	if code, body := call(adminAPI, http.MethodPost, "/pam/entry-requests/"+fresh+"/approve", `{}`); code != http.StatusOK {
		t.Errorf("approving a live request: %d %v; want 200", code, body)
	}
	var status string
	if err := db.Pool.QueryRow(orgctx.WithBypassRLS(ctx), `SELECT status FROM pam_entry_access_requests WHERE id = $1`, stale).Scan(&status); err != nil || status != "pending" {
		t.Errorf("the expired request is %q (%v) after the refused approval; want it still pending", status, err)
	}
}
