package access

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// pam.entry_connected says when an administrator got in only by being one.
//
// Administrators pass the connect grant and the approval gate on every launch
// path. The event recorded who connected and to what, and nothing about how:
// an administrator opening an entry nobody granted them, or skipping its
// approval, read the same as an operator using their grant. An auditor asking
// "who used their admin role to reach this host" had no field to filter on.
//
// The entries are websites, the one type connect answers without a broker, so
// the gates are the whole decision. The requireFreshMFA step in front of the
// route is a separate control and is not mounted here.
func TestEntryConnectedRecordsTheAdminBypass(t *testing.T) {
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

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	seedUser := func(name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	admin := seedUser("bypass-admin")
	grantedAdmin := seedUser("bypass-granted-admin")
	approver := seedUser("bypass-approver")
	operator := seedUser("bypass-operator")

	// The audit service: keeps each pam.entry_connected event's details.
	var mu sync.Mutex
	var connected []map[string]interface{}
	auditSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var ev struct {
			Action  string                 `json:"action"`
			Details map[string]interface{} `json:"details"`
		}
		_ = json.Unmarshal(raw, &ev)
		if ev.Action == "pam.entry_connected" {
			mu.Lock()
			connected = append(connected, ev.Details)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(auditSrv.Close)

	logger := zap.NewNop()
	svc := &Service{db: db, config: &config.Config{}, logger: logger,
		auditService: NewUnifiedAuditService(db, logger), auditURL: auditSrv.URL}
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
		r.POST("/pam/entry-requests/:id/approve", svc.handlePamApproveRequest)
		r.POST("/pam/entries/:id/connect", svc.handlePamConnect)
		return r
	}
	call := func(r *gin.Engine, path, body string) (int, map[string]interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	adminAPI := as(admin, "admin")
	createEntry := func(name string, approval bool) string {
		t.Helper()
		code, body := call(adminAPI, "/pam/entries", `{"name":"`+name+` `+suffix+`","entry_type":"website",`+
			`"url":"https://`+name+`.example.test","require_approval":`+strconv.FormatBool(approval)+`}`)
		id, _ := body["id"].(string)
		if code != http.StatusCreated || id == "" {
			t.Fatalf("create entry %s: %d %v", name, code, body)
		}
		return id
	}
	grantConnect := func(entry, user string) {
		t.Helper()
		if code, body := call(adminAPI, "/pam/entries/"+entry+"/grants",
			`{"principal_type":"user","principal_id":"`+user+`","actions":["connect"]}`); code != http.StatusCreated {
			t.Fatalf("grant: %d %v", code, body)
		}
	}
	plain := createEntry("payroll", false)
	gated := createEntry("treasury", true)
	grantConnect(plain, grantedAdmin)
	grantConnect(plain, operator)
	grantConnect(gated, grantedAdmin)
	grantConnect(gated, operator)

	// connectAndRead launches and returns the event the launch posted.
	connectAndRead := func(t *testing.T, entry, user string, roles ...string) map[string]interface{} {
		t.Helper()
		mu.Lock()
		before := len(connected)
		mu.Unlock()
		if code, body := call(as(user, roles...), "/pam/entries/"+entry+"/connect", ""); code != http.StatusOK {
			t.Fatalf("connect: %d %v", code, body)
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			for _, d := range connected[before:] {
				if d["user_id"] == user && d["entry_id"] == entry {
					mu.Unlock()
					return d
				}
			}
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("no pam.entry_connected event reached the audit service")
		return nil
	}
	gates := func(d map[string]interface{}) []string {
		raw, ok := d["admin_bypassed"].([]interface{})
		if !ok {
			t.Fatalf("admin_bypassed is missing or not a list: %#v", d["admin_bypassed"])
		}
		out := []string{}
		for _, g := range raw {
			out = append(out, g.(string))
		}
		return out
	}

	for _, tc := range []struct {
		name  string
		entry string
		user  string
		roles []string
		want  []string
	}{
		{"an operator using their grant bypasses nothing", plain, operator, nil, []string{}},
		{"an administrator with a grant bypasses nothing", plain, grantedAdmin, []string{"admin"}, []string{}},
		{"an administrator without a grant bypasses the grant", plain, admin, []string{"admin"}, []string{"grant"}},
		{"an administrator with a grant skips the approval", gated, grantedAdmin, []string{"admin"}, []string{"approval"}},
		{"an administrator without either bypasses both", gated, admin, []string{"admin"}, []string{"grant", "approval"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := connectAndRead(t, tc.entry, tc.user, tc.roles...)
			got := gates(d)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("admin_bypassed = %v, want %v", got, tc.want)
			}
			if d["admin_bypass"] != (len(tc.want) > 0) {
				t.Errorf("admin_bypass = %v, want %v", d["admin_bypass"], len(tc.want) > 0)
			}
		})
	}

	t.Run("an operator spending an approval bypasses nothing", func(t *testing.T) {
		code, body := call(as(operator), "/pam/entries/"+gated+"/request", `{"reason":"month end"}`)
		requestID, _ := body["request_id"].(string)
		if code != http.StatusCreated || requestID == "" {
			t.Fatalf("file request: %d %v", code, body)
		}
		if code, body := call(as(approver, "admin"), "/pam/entry-requests/"+requestID+"/approve", `{}`); code != http.StatusOK {
			t.Fatalf("approve: %d %v", code, body)
		}
		d := connectAndRead(t, gated, operator)
		if got := gates(d); len(got) != 0 || d["admin_bypass"] != false {
			t.Errorf("admin_bypass = %v, admin_bypassed = %v, want false and []", d["admin_bypass"], got)
		}
	})
}
