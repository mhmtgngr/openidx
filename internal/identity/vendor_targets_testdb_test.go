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

// Invariant I11 of the third-party access framework at the vendor API, on the
// migrated schema: an administrator puts a vendor organization on a closed
// list and opens targets to it. A PAM entry and an application must exist in
// the organization, a network service is taken by id, an unknown type and a
// second opening are refused, and closing a target removes it. An update that
// does not name the closed list keeps it, so a form that predates the field
// cannot switch it off by saving. A closed vendor's list cannot change.
func TestAVendorsClosedListNamesWhatIsOpen(t *testing.T) {
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
		org, "vt-admin-"+suffix)
	entry := scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port)
		VALUES ($1, $2, 'ssh', 'target.example.test', 22) RETURNING id::text`, org, "vt-db-"+suffix)
	app := scalar(`INSERT INTO applications (org_id, name, client_id, type) VALUES ($1, $2, $2, 'web') RETURNING id::text`, org, "vt-app-"+suffix)
	service := scalar(`INSERT INTO ziti_services (org_id, ziti_id, name, host, port) VALUES ($1, $2, $3, 'db.example.test', 5432) RETURNING id::text`,
		org, "zsvc-vt-"+suffix, "vt-svc-"+suffix)

	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("user_id", admin)
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	r.POST("/vendor-orgs", svc.handleCreateVendorOrg)
	r.GET("/vendor-orgs/:id", svc.handleGetVendorOrg)
	r.PUT("/vendor-orgs/:id", svc.handleUpdateVendorOrg)
	r.POST("/vendor-orgs/:id/close", svc.handleCloseVendorOrg)
	r.GET("/vendor-orgs/:id/targets", svc.handleListVendorTargets)
	r.POST("/vendor-orgs/:id/targets", svc.handleAddVendorTarget)
	r.DELETE("/vendor-orgs/:id/targets/:targetId", svc.handleRemoveVendorTarget)
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

	code, body := call(http.MethodPost, "/vendor-orgs", `{"name":"Acme `+suffix+`","closed_list":true}`)
	vendor, _ := body["id"].(string)
	if code != http.StatusCreated || body["closed_list"] != true {
		t.Fatalf("create a vendor on a closed list: %d %v", code, body)
	}
	if code, body := call(http.MethodPut, "/vendor-orgs/"+vendor, `{"name":"Acme `+suffix+`","notes":"renamed nothing"}`); code != http.StatusOK || body["closed_list"] != true {
		t.Errorf("an update that does not name the closed list: %d closed_list=%v, want it kept", code, body["closed_list"])
	}

	open := func(targetType, targetID string) (int, map[string]interface{}) {
		t.Helper()
		return call(http.MethodPost, "/vendor-orgs/"+vendor+"/targets", fmt.Sprintf(`{"target_type":%q,"target_id":%q}`, targetType, targetID))
	}
	code, body = open("pam_entry", entry)
	entryTarget, _ := body["id"].(string)
	if code != http.StatusCreated {
		t.Fatalf("open the PAM entry: %d %v", code, body)
	}
	if code, body := open("application", app); code != http.StatusCreated {
		t.Errorf("open the application: %d %v", code, body)
	}
	if code, body := open("network_service", service); code != http.StatusCreated {
		t.Errorf("open a network service: %d %v", code, body)
	}
	for _, c := range []struct {
		what, targetType, targetID string
		status                     int
	}{
		{"a type the list does not cover", "role", entry, http.StatusBadRequest},
		{"an id that is not one", "pam_entry", "db-01", http.StatusBadRequest},
		{"a PAM entry that does not exist", "pam_entry", "00000000-0000-0000-0000-0000000000cd", http.StatusNotFound},
		{"a network service that is not one of the organization's", "network_service", "00000000-0000-0000-0000-0000000000ab", http.StatusNotFound},
		{"the same entry twice", "pam_entry", entry, http.StatusConflict},
	} {
		if code, body := open(c.targetType, c.targetID); code != c.status {
			t.Errorf("%s: %d %v, want %d", c.what, code, body, c.status)
		}
	}
	_, body = call(http.MethodGet, "/vendor-orgs/"+vendor+"/targets", "")
	targets, _ := body["targets"].([]interface{})
	names := []string{}
	for _, x := range targets {
		m, _ := x.(map[string]interface{})
		names = append(names, fmt.Sprintf("%v:%v", m["target_type"], m["target_name"]))
	}
	if got, want := strings.Join(names, " "), "pam_entry:vt-db-"+suffix+" application:vt-app-"+suffix+" network_service:vt-svc-"+suffix; got != want {
		t.Errorf("the vendor's targets read %q, want %q", got, want)
	}

	if code, _ := call(http.MethodDelete, "/vendor-orgs/"+vendor+"/targets/"+entryTarget, ""); code != http.StatusNoContent {
		t.Errorf("close the PAM entry: %d, want 204", code)
	}
	if n := scalar(`SELECT count(*)::text FROM vendor_org_targets WHERE vendor_org_id = $1`, vendor); n != "2" {
		t.Errorf("the vendor holds %s targets after one was closed, want 2", n)
	}

	if code, body := call(http.MethodPost, "/vendor-orgs/"+vendor+"/close", `{"reason":"contract ended"}`); code != http.StatusOK {
		t.Fatalf("close the vendor: %d %v", code, body)
	}
	if code, body := open("pam_entry", entry); code != http.StatusConflict || body["code"] != "vendor_org_closed" {
		t.Errorf("open a target to a closed vendor: %d %v, want 409 vendor_org_closed", code, body)
	}
}
