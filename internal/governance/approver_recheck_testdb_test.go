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

// The approvers of an access request are named when it is filed, from the
// roles, groups, manager and sponsor of that day, and each becomes a row naming
// one user. Nothing on the row said why, so an approver who lost what put them
// there decided the request all the same. On the migrated schema, through the
// handlers, each row records its basis (v226) and the approver is held to it:
//
//   - a role step's approver whose role has ended, a group step's approver
//     whose membership has ended, the manager the requester no longer reports
//     to, the sponsor who handed the external account over: each is refused
//     (403 approver_no_longer_eligible) on approve and on deny, and their
//     queue no longer shows the request;
//   - an approver who still stands decides as before, and a step naming a
//     user is not re-checked;
//   - a row written before v226 (no basis) is decided as before.
func TestAnApproverWhoLostTheirBasisNoLongerDecides(t *testing.T) {
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
	ctx := orgctx.With(bg, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
	}
	user := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
			org, name+"-"+suffix)
	}
	newRole := func(name string) string {
		return scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1, $2, '') RETURNING id::text`, org, name+"-"+suffix)
	}
	roleHolder1, roleHolder2 := user("ar-role-1"), user("ar-role-2")
	member1, member2 := user("ar-member-1"), user("ar-member-2")
	manager, newManager, named := user("ar-manager"), user("ar-new-manager"), user("ar-named")
	sponsor, newSponsor := user("ar-sponsor"), user("ar-new-sponsor")
	requester := user("ar-requester")
	exec(`UPDATE users SET manager_id = $1 WHERE id = $2`, manager, requester)
	vendor := scalar(`INSERT INTO vendor_organizations (org_id, name, contract_end) VALUES ($1, $2, '2099-12-31') RETURNING id::text`, org, "ar-vendor-"+suffix)
	external := scalar(`
		INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
		VALUES ($1, $2::text, $2::text || '@supplier.example.test', 'external', $3, $4, NOW() + interval '30 days')
		RETURNING id::text`, org, "ar-vendor-user-"+suffix, vendor, sponsor)
	exec(`INSERT INTO mfa_totp (user_id, secret, enabled, org_id) VALUES ($1, 'JBSWY3DPEHPK3PXP', true, $2)`, external, org)

	approverRole := newRole("ar-approvers")
	for _, u := range []string{roleHolder1, roleHolder2} {
		exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1, $2, $3)`, u, approverRole, org)
	}
	approverGroup := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "ar-approver-group-"+suffix)
	for _, u := range []string{member1, member2} {
		exec(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1, $2, $3)`, u, approverGroup, org)
	}
	// One requested role per policy, so each request gets its own chain.
	policy := func(name, steps string) string {
		target := newRole(name)
		exec(`INSERT INTO approval_policies (org_id, name, resource_type, resource_id, approval_steps, enabled)
			VALUES ($1, $2, 'role', $3, $4::jsonb, true)`, org, name+"-"+suffix, target, steps)
		return target
	}
	byRole := policy("ar-by-role", fmt.Sprintf(`[{"type":"role","role_id":%q,"min_approvals":1}]`, approverRole))
	byRoleLegacy := policy("ar-by-role-legacy", fmt.Sprintf(`[{"type":"role","role_id":%q,"min_approvals":1}]`, approverRole))
	byGroup := policy("ar-by-group", fmt.Sprintf(`[{"type":"group","group_id":%q,"min_approvals":1}]`, approverGroup))
	byManager := policy("ar-by-manager", `[{"type":"manager","min_approvals":1}]`)
	byName := policy("ar-by-name", fmt.Sprintf(`[{"type":"specific_user","approver_id":%q,"min_approvals":1}]`, named))

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	call := func(userID, method, path, body string) (int, []byte) {
		t.Helper()
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			c.Set("user_id", userID)
			c.Set("roles", []string{"user"})
			c.Next()
		})
		r.POST("/requests", s.handleCreateAccessRequest)
		r.POST("/requests/:id/approve", s.handleApproveRequest)
		r.POST("/requests/:id/deny", s.handleDenyRequest)
		r.GET("/my-approvals", s.handleListPendingApprovals)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w.Code, w.Body.Bytes()
	}
	file := func(userID, target string) string {
		t.Helper()
		code, body := call(userID, http.MethodPost, "/requests", fmt.Sprintf(
			`{"resource_type":"role","resource_id":%q,"resource_name":"target","justification":"release","duration":"4h"}`, target))
		if code != http.StatusCreated {
			t.Fatalf("filing the request for %s: %d %s", target, code, body)
		}
		var out struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(body, &out)
		return out.ID
	}
	decide := func(userID, requestID, verb string) (int, string) {
		t.Helper()
		code, body := call(userID, http.MethodPost, "/requests/"+requestID+"/"+verb, `{"comments":"ok"}`)
		var out struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(body, &out)
		return code, out.Code
	}
	queued := func(userID, requestID string) bool {
		t.Helper()
		code, body := call(userID, http.MethodGet, "/my-approvals", "")
		if code != http.StatusOK {
			t.Fatalf("the queue of %s: %d %s", userID, code, body)
		}
		return strings.Contains(string(body), requestID)
	}
	basis := func(requestID, approverID string) string {
		return scalar(`SELECT COALESCE(approver_basis, '') || ':' || COALESCE(approver_basis_id::text, '')
			FROM access_request_approvals WHERE request_id = $1 AND approver_id = $2`, requestID, approverID)
	}
	refused := func(what, userID, requestID string) {
		t.Helper()
		if queued(userID, requestID) {
			t.Errorf("%s: the request is still in their queue", what)
		}
		for _, verb := range []string{"approve", "deny"} {
			if code, c := decide(userID, requestID, verb); code != http.StatusForbidden || c != "approver_no_longer_eligible" {
				t.Errorf("%s: %s answered %d %q, want 403 approver_no_longer_eligible", what, verb, code, c)
			}
		}
	}

	t.Run("a role step's approver whose role has ended", func(t *testing.T) {
		req := file(requester, byRole)
		if got, want := basis(req, roleHolder1), "role:"+approverRole; got != want {
			t.Errorf("the row's basis is %q, want %q", got, want)
		}
		if !queued(roleHolder1, req) {
			t.Fatalf("a live role holder's queue does not show the request")
		}
		exec(`UPDATE user_roles SET expires_at = NOW() - interval '1 minute' WHERE user_id = $1 AND role_id = $2`, roleHolder1, approverRole)
		refused("an ended role", roleHolder1, req)
		if code, _ := decide(roleHolder2, req, "approve"); code != http.StatusOK {
			t.Errorf("the other holder, who still holds the role: %d, want 200", code)
		}
	})

	t.Run("a group step's approver whose membership has ended", func(t *testing.T) {
		req := file(requester, byGroup)
		if got, want := basis(req, member1), "group:"+approverGroup; got != want {
			t.Errorf("the row's basis is %q, want %q", got, want)
		}
		exec(`UPDATE group_memberships SET expires_at = NOW() - interval '1 minute' WHERE user_id = $1 AND group_id = $2`, member1, approverGroup)
		refused("an ended membership", member1, req)
		if code, _ := decide(member2, req, "approve"); code != http.StatusOK {
			t.Errorf("the other member: %d, want 200", code)
		}
	})

	t.Run("the manager the requester no longer reports to", func(t *testing.T) {
		req := file(requester, byManager)
		if got := basis(req, manager); got != "manager:" {
			t.Errorf("the row's basis is %q, want manager", got)
		}
		exec(`UPDATE users SET manager_id = $1 WHERE id = $2`, newManager, requester)
		refused("a former manager", manager, req)
		exec(`UPDATE users SET manager_id = $1 WHERE id = $2`, manager, requester)
		if code, _ := decide(manager, req, "approve"); code != http.StatusOK {
			t.Errorf("the manager once the requester reports to them again: %d, want 200", code)
		}
	})

	t.Run("the sponsor who handed the account over", func(t *testing.T) {
		req := file(external, byName)
		if got := basis(req, sponsor); got != "sponsor:" {
			t.Errorf("the sponsor's row basis is %q, want sponsor", got)
		}
		if got := basis(req, named); got != "user:" {
			t.Errorf("the named approver's row basis is %q, want user", got)
		}
		exec(`UPDATE users SET sponsor_user_id = $1 WHERE id = $2`, newSponsor, external)
		refused("a former sponsor", sponsor, req)
	})

	t.Run("a named approver is not re-checked, and decides", func(t *testing.T) {
		req := file(requester, byName)
		if code, _ := decide(named, req, "approve"); code != http.StatusOK {
			t.Errorf("the named approver: %d, want 200", code)
		}
	})

	// Two steps can share a step order, so one approver can hold two rows there
	// on two bases. While either stands, the queue shows the request, and the
	// decision agrees with it rather than reading whichever row comes first.
	t.Run("an approver with two rows at one step decides while either stands", func(t *testing.T) {
		twoRows := user("ar-two-rows")
		heldRole := newRole("ar-two-rows-role")
		exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1, $2, $3)`, twoRows, heldRole, org)
		target := policy("ar-two-rows", fmt.Sprintf(`[{"type":"role","role_id":%q,"min_approvals":1}]`, heldRole))
		req := file(requester, target)
		exec(`INSERT INTO access_request_approvals (id, request_id, approver_id, step_order, step_min_approvals, decision, created_at, org_id, approver_basis)
			SELECT gen_random_uuid(), request_id, approver_id, step_order, step_min_approvals, 'pending', NOW(), org_id, 'user'
			  FROM access_request_approvals WHERE request_id = $1 AND approver_id = $2`, req, twoRows)
		exec(`UPDATE user_roles SET expires_at = NOW() - interval '1 minute' WHERE user_id = $1 AND role_id = $2`, twoRows, heldRole)
		if !queued(twoRows, req) {
			t.Fatalf("the queue no longer shows the request, though the approver's second row stands")
		}
		if code, c := decide(twoRows, req, "approve"); code != http.StatusOK {
			t.Errorf("the decision refused what the queue offers: %d %q, want 200", code, c)
		}
	})

	t.Run("a row written before v226 is decided as before", func(t *testing.T) {
		exec(`UPDATE user_roles SET expires_at = NULL WHERE user_id = $1 AND role_id = $2`, roleHolder1, approverRole)
		req := file(requester, byRoleLegacy)
		exec(`UPDATE user_roles SET expires_at = NOW() - interval '1 minute' WHERE user_id = $1 AND role_id = $2`, roleHolder1, approverRole)
		exec(`UPDATE access_request_approvals SET approver_basis = NULL, approver_basis_id = NULL WHERE request_id = $1`, req)
		if code, c := decide(roleHolder1, req, "approve"); code != http.StatusOK {
			t.Errorf("a row with no basis: %d %q, want 200", code, c)
		}
	})
}
