package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestExternalUsersHoldOnlyWhatTheyMay drives the identity routes an
// administrator uses against an external (vendor) user, on the migrated
// schema, and checks both halves of the invariants Phase 1 puts in front of
// such a user:
//
//   - I2, the role ceiling: the user role is given, every other role refused
//     with 403 external_role_cap, on the single-role route and on the
//     replace-all route (which must then leave the roles as they were).
//   - I3, no default assignment: a group an administrator opened to external
//     users accepts the user, any other refuses it; a group cannot be closed
//     to external users while one is a member, and an edit that does not name
//     the flag leaves it alone.
//   - I1, the lifecycle: the account reads back as external with its vendor
//     and sponsor; a suspended one cannot be re-enabled through the user
//     edit; deleting its sponsor suspends it rather than leaving it
//     unsponsored; closing its vendor disables it.
//
// Internal users are the control in each case: the same requests succeed for
// them.
func TestExternalUsersHoldOnlyWhatTheyMay(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)

	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("read (%s): %v", q, err)
		}
		return v
	}
	user := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
			org, name+"-"+suffix)
	}
	admin := user("ext-admin")
	sponsor := user("ext-sponsor")
	colleague := user("ext-colleague")

	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("user_id", admin)
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	r.GET("/vendor-orgs", svc.handleListVendorOrgs)
	r.POST("/vendor-orgs", svc.handleCreateVendorOrg)
	r.PUT("/vendor-orgs/:id", svc.handleUpdateVendorOrg)
	r.POST("/vendor-orgs/:id/close", svc.handleCloseVendorOrg)
	r.GET("/users/:id", svc.handleGetUser)
	r.PUT("/users/:id", svc.handleUpdateUser)
	r.DELETE("/users/:id", svc.handleDeleteUser)
	r.POST("/users/:id/roles", svc.handleAssignUserRole)
	r.PUT("/users/:id/roles", svc.handleUpdateUserRoles)
	r.PUT("/groups/:id", svc.handleUpdateGroup)
	r.POST("/groups/:id/members", svc.handleAddGroupMember)
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
	// signals reads the SSF signals enqueued about a user, oldest first, by
	// the last segment of their event type.
	signals := func(userID string) []string {
		t.Helper()
		rows, err := db.Pool.Query(ctx, `SELECT event_type FROM ssf_pending_events WHERE subject_id = $1 ORDER BY id`, userID)
		if err != nil {
			t.Fatalf("read the SSF signals: %v", err)
		}
		defer rows.Close()
		out := []string{}
		for rows.Next() {
			var ev string
			if err := rows.Scan(&ev); err != nil {
				t.Fatalf("read an SSF signal: %v", err)
			}
			out = append(out, ev[strings.LastIndex(ev, "/")+1:])
		}
		return out
	}
	refused := func(t *testing.T, what string, code int, body map[string]interface{}, wantStatus int, wantCode string) {
		t.Helper()
		if code != wantStatus || body["code"] != wantCode {
			t.Errorf("%s: %d %v, want %d %s", what, code, body, wantStatus, wantCode)
		}
	}

	// The vendor organization.
	code, body := call(http.MethodPost, "/vendor-orgs", `{"name":"Acme Support `+suffix+`",
		"allowed_email_domains":["@Supplier.Example.test"," supplier.example.test "],
		"contract_end":"2099-12-31","default_sponsor_user_id":"`+sponsor+`"}`)
	vendor, _ := body["id"].(string)
	if code != http.StatusCreated || vendor == "" {
		t.Fatalf("create vendor: %d %v", code, body)
	}
	if d, _ := body["allowed_email_domains"].([]interface{}); len(d) != 1 || d[0] != "supplier.example.test" {
		t.Errorf("allowed domains were not normalised: %v", body["allowed_email_domains"])
	}
	if body["default_expiry_days"] != float64(90) {
		t.Errorf("default_expiry_days = %v, want 90", body["default_expiry_days"])
	}
	if code, body := call(http.MethodPost, "/vendor-orgs", `{"name":"Acme Support `+suffix+`"}`); code != http.StatusConflict {
		t.Errorf("a duplicate vendor name: %d %v, want 409", code, body)
	}
	if code, body := call(http.MethodPost, "/vendor-orgs", `{"name":"Too Long `+suffix+`","default_expiry_days":400}`); code != http.StatusBadRequest {
		t.Errorf("a 400-day default expiry: %d %v, want 400", code, body)
	}

	external := func(name string) string {
		return scalar(`
			INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
			VALUES ($1, $2::text, $2::text || '@supplier.example.test', 'external', $3, $4, NOW() + interval '30 days')
			RETURNING id::text`, org, name+"-"+suffix, vendor, sponsor)
	}
	vendorUser := external("ext-vendor")
	if code, body := call(http.MethodPost, "/vendor-orgs", `{"name":"Sponsored By A Vendor `+suffix+`","default_sponsor_user_id":"`+vendorUser+`"}`); true {
		refused(t, "an external default sponsor", code, body, http.StatusForbidden, "external_sponsor_invalid")
	}

	roleID := func(name string) string {
		return scalar(`SELECT id::text FROM roles WHERE name = $1 AND org_id = $2`, name, org)
	}
	userRole, adminRole, auditorRole := roleID("user"), roleID("admin"), roleID("auditor")

	t.Run("I2: an external user holds the user role and nothing above it", func(t *testing.T) {
		if code, body := call(http.MethodPost, "/users/"+vendorUser+"/roles", `{"role_id":"`+userRole+`"}`); code != http.StatusOK {
			t.Fatalf("the user role: %d %v", code, body)
		}
		code, body := call(http.MethodPost, "/users/"+vendorUser+"/roles", `{"role_id":"`+adminRole+`"}`)
		refused(t, "the admin role", code, body, http.StatusForbidden, "external_role_cap")
		code, body = call(http.MethodPut, "/users/"+vendorUser+"/roles", `{"role_ids":["`+userRole+`","`+auditorRole+`"]}`)
		refused(t, "a role list with auditor", code, body, http.StatusForbidden, "external_role_cap")
		if n := scalar(`SELECT count(*)::text FROM user_roles WHERE user_id = $1 AND org_id = $2`, vendorUser, org); n != "1" {
			t.Errorf("after the refused replace the external user holds %s role(s), want the 1 it had", n)
		}
		if code, body := call(http.MethodPost, "/users/"+colleague+"/roles", `{"role_id":"`+adminRole+`"}`); code != http.StatusOK {
			t.Errorf("the admin role for an internal user: %d %v", code, body)
		}
	})

	group := func(name string) string {
		return scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, name+"-"+suffix)
	}
	openGroup, closedGroup := group("vendor-access"), group("finance")

	t.Run("I3: an external user joins only a group opened to external users", func(t *testing.T) {
		code, body := call(http.MethodPost, "/groups/"+openGroup+"/members", `{"user_id":"`+vendorUser+`"}`)
		refused(t, "a group not yet opened", code, body, http.StatusForbidden, "external_group_not_allowed")
		if code, body := call(http.MethodPut, "/groups/"+openGroup,
			`{"displayName":"vendor-access-`+suffix+`","attributes":{"externalAllowed":"true"}}`); code != http.StatusOK {
			t.Fatalf("open the group: %d %v", code, body)
		}
		if code, body := call(http.MethodPost, "/groups/"+openGroup+"/members", `{"user_id":"`+vendorUser+`"}`); code != http.StatusOK {
			t.Fatalf("join the opened group: %d %v", code, body)
		}
		code, body = call(http.MethodPost, "/groups/"+closedGroup+"/members", `{"user_id":"`+vendorUser+`"}`)
		refused(t, "a closed group", code, body, http.StatusForbidden, "external_group_not_allowed")
		if code, body := call(http.MethodPost, "/groups/"+closedGroup+"/members", `{"user_id":"`+colleague+`"}`); code != http.StatusOK {
			t.Errorf("a closed group for an internal user: %d %v", code, body)
		}

		code, body = call(http.MethodPut, "/groups/"+openGroup,
			`{"displayName":"vendor-access-`+suffix+`","attributes":{"externalAllowed":"false"}}`)
		refused(t, "closing a group with an external member", code, body, http.StatusConflict, "external_group_has_members")
		if code, body := call(http.MethodPut, "/groups/"+openGroup,
			`{"displayName":"vendor-access-renamed-`+suffix+`"}`); code != http.StatusOK {
			t.Fatalf("an edit that does not name the flag: %d %v", code, body)
		}
		if v := scalar(`SELECT external_allowed::text FROM groups WHERE id = $1`, openGroup); v != "true" {
			t.Errorf("an edit that did not name externalAllowed changed it to %s", v)
		}
	})

	t.Run("I1: the account reads back external, and stays within its lifecycle", func(t *testing.T) {
		code, body := call(http.MethodGet, "/users/"+vendorUser, "")
		if code != http.StatusOK || body["userType"] != "external" || body["accountStatus"] != "active" ||
			body["sponsorUserId"] != sponsor || body["vendorOrgId"] != vendor || body["accountExpiresAt"] == nil {
			t.Fatalf("read the external user: %d %v", code, body)
		}

		suspended := external("ext-suspended")
		exec(`UPDATE users SET account_status = 'suspended', enabled = false WHERE id = $1`, suspended)
		code, body = call(http.MethodPut, "/users/"+suspended, `{"userName":"ext-suspended-`+suffix+`","enabled":true,"active":true}`)
		refused(t, "re-enabling a suspended external user", code, body, http.StatusForbidden, "external_account_not_live")

		if code, body := call(http.MethodDelete, "/users/"+sponsor, ""); code != http.StatusNoContent {
			t.Fatalf("delete the sponsor: %d %v", code, body)
		}
		var status string
		var enabled bool
		var sponsorID, severed *string
		if err := db.Pool.QueryRow(ctx, `
			SELECT account_status, enabled, sponsor_user_id::text, access_severed_at::text FROM users WHERE id = $1`, vendorUser).
			Scan(&status, &enabled, &sponsorID, &severed); err != nil {
			t.Fatalf("read the external user after the sponsor left: %v", err)
		}
		if status != "suspended" || enabled || sponsorID != nil || severed == nil {
			t.Errorf("after its sponsor's delete the external user is %s, enabled %v, sponsor %v, severed %v; want suspended, disabled, none, severed",
				status, enabled, sponsorID, severed)
		}
		if got := signals(vendorUser); !slices.Equal(got, []string{"session-revoked"}) {
			t.Errorf("SSF signals after the sponsor left: %v, want [session-revoked]", got)
		}
	})

	t.Run("closing the vendor disables its external users and cannot be undone", func(t *testing.T) {
		newSponsor := user("ext-sponsor-2")
		live := scalar(`
			INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
			VALUES ($1, $2::text, $2::text || '@supplier.example.test', 'external', $3, $4, NOW() + interval '30 days')
			RETURNING id::text`, org, "ext-live-"+suffix, vendor, newSponsor)
		if code, body := call(http.MethodPost, "/vendor-orgs/"+vendor+"/close", `{}`); code != http.StatusBadRequest {
			t.Errorf("a close without a reason: %d %v, want 400", code, body)
		}
		code, body := call(http.MethodPost, "/vendor-orgs/"+vendor+"/close", `{"reason":"contract ended"}`)
		if code != http.StatusOK || body["users_disabled"] != float64(3) {
			t.Fatalf("close: %d %v, want 200 with 3 users disabled (live, suspended, the sponsorless one)", code, body)
		}
		var status string
		var enabled bool
		if err := db.Pool.QueryRow(ctx, `SELECT account_status, enabled FROM users WHERE id = $1`, live).Scan(&status, &enabled); err != nil {
			t.Fatalf("read: %v", err)
		}
		if status != "disabled" || enabled {
			t.Errorf("a live external user of the closed vendor is %s, enabled %v", status, enabled)
		}
		if got := signals(live); !slices.Equal(got, []string{"account-disabled"}) {
			t.Errorf("SSF signals of a live external user of the closed vendor: %v, want [account-disabled]", got)
		}
		if got := signals(vendorUser); !slices.Equal(got, []string{"session-revoked", "account-disabled"}) {
			t.Errorf("SSF signals of the suspended external user of the closed vendor: %v, want [session-revoked account-disabled]", got)
		}
		code, body = call(http.MethodPut, "/vendor-orgs/"+vendor, `{"name":"Reopened `+suffix+`"}`)
		refused(t, "editing a closed vendor", code, body, http.StatusConflict, "vendor_org_closed")
		code, body = call(http.MethodPost, "/vendor-orgs/"+vendor+"/close", `{"reason":"again"}`)
		refused(t, "closing it twice", code, body, http.StatusConflict, "vendor_org_closed")
		if n := scalar(`SELECT count(*)::text FROM users WHERE id = $1 AND enabled`, colleague); n != "1" {
			t.Error("closing the vendor touched an internal user")
		}
	})
}
