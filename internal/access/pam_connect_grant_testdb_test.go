package access

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

// The Vault / PAM grant row of docs/evidence/display-equals-enforcement.md at
// connect: "connect as a granted user, then as an ungranted one", with the
// display beside it. The entry and its grants are made through the admin
// routes. For each user the test asks the entry list what it shows, and the
// connect handler what it does.
//
// The entry is a website, the one entry type connect answers without a
// Guacamole broker, so the grant check is the whole decision. The
// requireFreshMFA step in front of the connect route is a separate control and
// is not mounted here.
func TestPamConnectFollowsTheGrant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
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
	admin := seedUser("pam-admin")
	granted := seedUser("pam-granted")
	member := seedUser("pam-member")
	viewer := seedUser("pam-viewer")
	lapsed := seedUser("pam-lapsed")
	stranger := seedUser("pam-stranger")
	var group string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO groups (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`,
		org, "payroll-ops-"+suffix).Scan(&group); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		member, group, org); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	logger := zap.NewNop()
	svc := &Service{db: db, config: &config.Config{}, logger: logger, auditService: NewUnifiedAuditService(db, logger)}
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
		r.GET("/pam/entries", svc.handlePamListEntries)
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

	// The admin makes the entry and grants it.
	adminAPI := as(admin, "admin")
	code, body := call(adminAPI, http.MethodPost, "/pam/entries",
		`{"name":"Payroll portal `+suffix+`","entry_type":"website","url":"https://payroll.example.test"}`)
	entry, _ := body["id"].(string)
	if code != http.StatusCreated || entry == "" {
		t.Fatalf("create entry: %d %v", code, body)
	}
	for _, g := range []string{
		`{"principal_type":"user","principal_id":"` + granted + `","actions":["connect"]}`,
		`{"principal_type":"group","principal_id":"` + group + `","actions":["connect"]}`,
		`{"principal_type":"user","principal_id":"` + viewer + `","actions":["view"]}`,
		`{"principal_type":"user","principal_id":"` + lapsed + `","actions":["connect"],"expires_at":"` +
			time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) + `"}`,
	} {
		if code, body := call(adminAPI, http.MethodPost, "/pam/entries/"+entry+"/grants", g); code != http.StatusCreated {
			t.Fatalf("grant %s: %d %v", g, code, body)
		}
	}

	listed := func(userID string) bool {
		t.Helper()
		code, body := call(as(userID), http.MethodGet, "/pam/entries", "")
		if code != http.StatusOK {
			t.Fatalf("list entries as %s: %d %v", userID, code, body)
		}
		entries, _ := body["entries"].([]interface{})
		for _, e := range entries {
			if m, ok := e.(map[string]interface{}); ok && m["id"] == entry {
				return true
			}
		}
		return false
	}
	connect := func(userID string) (int, map[string]interface{}) {
		t.Helper()
		return call(as(userID), http.MethodPost, "/pam/entries/"+entry+"/connect", "")
	}

	for _, tc := range []struct {
		name       string
		user       string
		wantListed bool
		wantCode   int
	}{
		{"a user granted connect sees the entry and connects", granted, true, http.StatusOK},
		{"a member of a granted group sees the entry and connects", member, true, http.StatusOK},
		{"a user with no grant neither sees it nor connects", stranger, false, http.StatusForbidden},
		{"a lapsed grant is neither shown nor honoured", lapsed, false, http.StatusForbidden},
		// The list shows entries held under any action, and connect needs the
		// connect action. The console's connect button is not gated on it.
		{"a view-only grant shows the entry and refuses the connect", viewer, true, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := listed(tc.user); got != tc.wantListed {
				t.Errorf("listed = %v, want %v", got, tc.wantListed)
			}
			code, body := connect(tc.user)
			if code != tc.wantCode {
				t.Fatalf("connect = %d %v, want %d", code, body, tc.wantCode)
			}
			if code == http.StatusOK && (body["launch_type"] != "url" || body["url"] != "https://payroll.example.test") {
				t.Errorf("a granted connect must hand back the entry's URL: %v", body)
			}
		})
	}
}
