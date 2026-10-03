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
	"github.com/openidx/openidx/internal/migrations"
)

// A network_service request names one of the organization's Ziti services and a
// window, on the migrated schema and through the real handlers. A service that
// does not exist, one of another organization and a disabled one answer the
// same 404, and a request with no window is refused, since the dial it opens
// would never close. A valid request carries the service's own name, and its
// fulfilment queues the request's attribute with the request and its window.
func TestANetworkServiceRequestNamesAServiceOfTheOrganization(t *testing.T) {
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
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(orgctx.WithBypassRLS(bg), q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	requester := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "ns-requester-"+suffix)
	administrator := scalar(`SELECT id::text FROM users WHERE username = 'admin'`)
	other := scalar(`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "ns-other-"+suffix)
	service := func(orgID, name string, enabled bool) string {
		return scalar(`INSERT INTO ziti_services (org_id, ziti_id, name, host, port, enabled)
			VALUES ($1, $2, $3, 'db.example.test', 5432, $4) RETURNING id::text`, orgID, "zsvc-"+name+"-"+suffix, name+"-"+suffix, enabled)
	}
	ours, theirs, off := service(org, "ns-ledger", true), service(other, "ns-theirs", true), service(org, "ns-off", false)

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
	file := func(serviceID, duration string) (int, map[string]interface{}) {
		t.Helper()
		return call(requester, "/requests", fmt.Sprintf(
			`{"resource_type":"network_service","resource_id":%q,"resource_name":"typed by the requester","justification":"reconcile","duration":%q}`,
			serviceID, duration))
	}

	for name, id := range map[string]string{
		"a service that does not exist": "6f1c2a54-3a3e-4f43-9a52-0c8f3ac2b7d1",
		"not a service id":              "ledger",
		"another organization's":        theirs,
		"a disabled service":            off,
	} {
		if code, body := file(id, "2h"); code != http.StatusNotFound || body["code"] != "network_service_not_found" {
			t.Errorf("%s: %d %v, want 404 network_service_not_found", name, code, body)
		}
	}
	if code, body := file(ours, ""); code != http.StatusBadRequest || body["code"] != "network_service_duration_required" {
		t.Errorf("a request with no window: %d %v, want 400 network_service_duration_required", code, body)
	}
	if n := scalar(`SELECT count(*)::text FROM access_requests WHERE requester_id = $1`, requester); n != "0" {
		t.Fatalf("the refused requests left %s rows", n)
	}

	if code, body := file(ours, "2h"); code != http.StatusCreated {
		t.Fatalf("a request for the organization's service: %d %v", code, body)
	}
	id := scalar(`SELECT id::text FROM access_requests WHERE requester_id = $1`, requester)
	if got := scalar(`SELECT resource_name FROM access_requests WHERE id = $1`, id); got != "ns-ledger-"+suffix {
		t.Errorf("the request reads %q, want the service's own name", got)
	}
	if code, body := call(administrator, "/requests/"+id+"/approve", `{"comments":"ok"}`, "admin"); code != http.StatusOK || body["status"] != "fulfilled" {
		t.Fatalf("approve: %d %v", code, body)
	}
	if got := scalar(`SELECT q.attribute || ' ' || (q.expires_at = r.expires_at)::text
		FROM network_grant_queue q JOIN access_requests r ON r.id = q.request_id WHERE q.request_id = $1`, id); got != "jit-"+id+" true" {
		t.Errorf("the fulfilment queued %q, want the request's attribute with its window", got)
	}
}
