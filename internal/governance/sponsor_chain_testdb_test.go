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

// Section 5.6 and 6.7 of the third-party access framework at the approval
// chain, on the migrated schema and through the real handlers:
//
//   - an external (vendor) user's request is approved by their sponsor first,
//     then by the policy's steps, in which the sponsor is no candidate even
//     when they hold the approver role; no auto-approve condition skips the
//     sponsor, though it still approves an internal user's request;
//   - without a policy, the default administrator step follows the sponsor,
//     and a chain whose only approver after the sponsor would be the sponsor
//     again is refused;
//   - one person approves at most one step of a request (four eyes): an
//     approver of step 1 who is also a candidate in step 2 is refused there,
//     and the step is approved by someone else.
func TestAnExternalUsersRequestIsApprovedByTheirSponsorFirst(t *testing.T) {
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
	sponsor, secops1, secops2, operator := user("sc-sponsor"), user("sc-secops1"), user("sc-secops2"), user("sc-operator")
	vendor := scalar(`INSERT INTO vendor_organizations (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "Acme "+suffix)
	external := scalar(`
		INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
		VALUES ($1, $2::text, $2::text || '@supplier.example.test', 'external', $3, $4, NOW() + interval '30 days')
		RETURNING id::text`, org, "sc-vendor-"+suffix, vendor, sponsor)
	exec(`INSERT INTO mfa_totp (user_id, secret, enabled, org_id) VALUES ($1, 'JBSWY3DPEHPK3PXP', true, $2)`, external, org)

	role := func(name string, members ...string) string {
		id := scalar(`INSERT INTO roles (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, name+"-"+suffix)
		for _, m := range members {
			exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1, $2, $3)`, m, id, org)
		}
		return id
	}
	// The sponsor holds the approver role too: the chain must still put
	// someone else on the policy's step.
	approvers := role("sc-pam-approvers", secops1, sponsor)
	everyone := scalar(`INSERT INTO groups (org_id, name, external_allowed) VALUES ($1, $2, true) RETURNING id::text`, org, "sc-staff-"+suffix)
	for _, m := range []string{external, operator} {
		exec(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1, $2, $3)`, m, everyone, org)
	}
	entry := func(name string) string {
		id := scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port)
			VALUES ($1, $2, 'ssh', 'target.example.test', 22) RETURNING id::text`, org, name+"-"+suffix)
		for _, u := range []string{external, operator} {
			exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
				VALUES ($1, $2, 'user', $3, '{view}')`, org, id, u)
		}
		return id
	}
	// The policy: one approver-role step, and an auto-approve condition both
	// requesters meet.
	exec(`INSERT INTO approval_policies (org_id, name, resource_type, approval_steps, auto_approve_conditions, enabled)
		VALUES ($1, $2, 'pam_entry', $3::jsonb, $4::jsonb, true)`, org, "sc-pam-"+suffix,
		fmt.Sprintf(`[{"type":"role","role_id":%q,"min_approvals":1}]`, approvers),
		fmt.Sprintf(`{"allowed_groups":[%q]}`, everyone))

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	as := func(userID string) *gin.Engine {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			c.Set("user_id", userID)
			c.Set("roles", []string{"user"})
			c.Next()
		})
		r.POST("/requests", s.handleCreateAccessRequest)
		r.POST("/requests/:id/approve", s.handleApproveRequest)
		return r
	}
	call := func(userID, path, body string) (int, map[string]interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		as(userID).ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	file := func(userID, resourceType, resourceID string) (int, map[string]interface{}) {
		t.Helper()
		return call(userID, "/requests", fmt.Sprintf(
			`{"resource_type":%q,"resource_id":%q,"resource_name":"target","justification":"patch window","duration":"4h"}`,
			resourceType, resourceID))
	}
	requestOf := func(userID, resourceID string) string {
		return scalar(`SELECT id::text FROM access_requests WHERE requester_id = $1 AND resource_id = $2::uuid
			ORDER BY created_at DESC LIMIT 1`, userID, resourceID)
	}
	// chain renders a request's approval rows as "step:approver" in order.
	chain := func(requestID string) string {
		return scalar(`SELECT COALESCE(string_agg(step_order::text || ':' || u.username, ' ' ORDER BY step_order, u.username), '')
			FROM access_request_approvals a JOIN users u ON u.id = a.approver_id
			WHERE a.request_id = $1`, requestID)
	}
	statusOf := func(requestID string) string {
		return scalar(`SELECT status FROM access_requests WHERE id = $1`, requestID)
	}
	approve := func(userID, requestID string) (int, map[string]interface{}) {
		t.Helper()
		return call(userID, "/requests/"+requestID+"/approve", `{"comments":"ok"}`)
	}
	name := func(n string) string { return n + "-" + suffix }

	t.Run("an external user's request goes to their sponsor first, then to someone else", func(t *testing.T) {
		target := entry("sc-prod")
		if code, body := file(external, "pam_entry", target); code != http.StatusCreated {
			t.Fatalf("the external user's request: %d %v", code, body)
		}
		req := requestOf(external, target)
		if got, want := chain(req), "1:"+name("sc-sponsor")+" 2:"+name("sc-secops1"); got != want {
			t.Errorf("the chain is %q, want %q: the sponsor first, and not again on the policy's step", got, want)
		}
		if statusOf(req) != "pending" {
			t.Errorf("an auto-approve condition the external user meets left the request %s, want pending", statusOf(req))
		}
		if code, _ := approve(secops1, req); code != http.StatusConflict {
			t.Errorf("the policy's approver before the sponsor: %d, want 409", code)
		}
		if code, body := approve(sponsor, req); code != http.StatusOK || body["status"] != "pending" {
			t.Errorf("the sponsor's approval: %d %v, want 200 and still pending", code, body)
		}
		if code, body := approve(secops1, req); code != http.StatusOK || body["status"] != "fulfilled" {
			t.Errorf("the second approval: %d %v, want 200 fulfilled", code, body)
		}

		internalTarget := entry("sc-stage")
		if code, body := file(operator, "pam_entry", internalTarget); code != http.StatusCreated {
			t.Fatalf("the internal user's request: %d %v", code, body)
		}
		if got := statusOf(requestOf(operator, internalTarget)); got != "fulfilled" {
			t.Errorf("an internal user who meets the auto-approve condition: %s, want fulfilled", got)
		}
	})

	t.Run("without a policy the default administrator follows the sponsor", func(t *testing.T) {
		group := scalar(`INSERT INTO groups (org_id, name, external_allowed) VALUES ($1, $2, true) RETURNING id::text`, org, "sc-nopolicy-"+suffix)
		if code, body := file(external, "group", group); code != http.StatusCreated {
			t.Fatalf("a request no policy covers: %d %v", code, body)
		}
		if got, want := chain(requestOf(external, group)), "1:"+name("sc-sponsor")+" 2:admin"; got != want {
			t.Errorf("the chain is %q, want %q", got, want)
		}

		// When the default administrator is the sponsor, nobody else is left.
		alt := scalar(`INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
			VALUES ($1, $2::text, $2::text || '@supplier.example.test', 'external', $3, '00000000-0000-0000-0000-000000000001', NOW() + interval '30 days')
			RETURNING id::text`, org, "sc-vendor2-"+suffix, vendor)
		exec(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1, $2, $3)`, alt, everyone, org)
		other := scalar(`INSERT INTO groups (org_id, name, external_allowed) VALUES ($1, $2, true) RETURNING id::text`, org, "sc-nopolicy2-"+suffix)
		code, body := file(alt, "group", other)
		if code != http.StatusConflict || body["code"] != "approval_chain_unbuildable" {
			t.Errorf("a chain whose only approver after the sponsor is the sponsor: %d %v, want 409 approval_chain_unbuildable", code, body)
		}
		if n := scalar(`SELECT count(*)::text FROM access_requests WHERE requester_id = $1`, alt); n != "0" {
			t.Errorf("the refused request left %s rows", n)
		}
	})

	t.Run("one person approves at most one step of a request", func(t *testing.T) {
		first := role("sc-first", secops1)
		second := role("sc-second", secops1, secops2)
		group := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "sc-two-step-"+suffix)
		exec(`INSERT INTO approval_policies (org_id, name, resource_type, resource_id, approval_steps, enabled)
			VALUES ($1, $2, 'group', $3, $4::jsonb, true)`, org, "sc-two-step-"+suffix, group,
			fmt.Sprintf(`[{"type":"role","role_id":%q},{"type":"role","role_id":%q}]`, first, second))
		if code, body := file(operator, "group", group); code != http.StatusCreated {
			t.Fatalf("the two-step request: %d %v", code, body)
		}
		req := requestOf(operator, group)
		if code, body := approve(secops1, req); code != http.StatusOK || body["status"] != "pending" {
			t.Fatalf("step one: %d %v", code, body)
		}
		if code, body := approve(secops1, req); code != http.StatusForbidden || body["code"] != "four_eyes" {
			t.Errorf("the step-one approver on step two: %d %v, want 403 four_eyes", code, body)
		}
		if statusOf(req) != "pending" {
			t.Errorf("the refused approval moved the request to %s", statusOf(req))
		}
		if code, body := approve(secops2, req); code != http.StatusOK || body["status"] != "fulfilled" {
			t.Errorf("a second person on step two: %d %v, want 200 fulfilled", code, body)
		}
	})
}
