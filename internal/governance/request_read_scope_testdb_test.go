package governance

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// GET /requests/:id answers the people a request is addressed to: its
// requester, an approver of it, the sponsor of the external user who filed
// it, and an administrator. Anyone else in the organization reads it as not
// found. It was the one access-request route with no check of its own, hidden
// while OPA turned every non-administrator away from governance. On the
// migrated schema, through the handler.
func TestARequestIsReadOnlyByThePeopleItIsAddressedTo(t *testing.T) {
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
	user := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
			org, name+"-"+suffix)
	}
	sponsor, approver, stranger, admin := user("rs-sponsor"), user("rs-approver"), user("rs-stranger"), user("rs-admin")
	internal := user("rs-internal")
	vendor := scalar(`INSERT INTO vendor_organizations (org_id, name, contract_end) VALUES ($1, $2, '2099-12-31') RETURNING id::text`, org, "rs-vendor-"+suffix)
	external := scalar(`INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
		VALUES ($1, $2::text, $2::text || '@supplier.example.test', 'external', $3, $4, NOW() + interval '30 days') RETURNING id::text`,
		org, "rs-external-"+suffix, vendor, sponsor)
	request := func(requester string) string {
		return scalar(`INSERT INTO access_requests (org_id, requester_id, resource_type, resource_id, resource_name, justification, status)
			VALUES ($1, $2, 'role', gen_random_uuid(), 'role', 'release', 'pending') RETURNING id::text`, org, requester)
	}
	internalReq, externalReq := request(internal), request(external)
	scalar(`INSERT INTO access_request_approvals (request_id, approver_id, step_order, decision, org_id)
		VALUES ($1, $2, 1, 'pending', $3) RETURNING id::text`, internalReq, approver, org)

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	read := func(caller, requestID string, roles ...string) int {
		t.Helper()
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			c.Set("user_id", caller)
			c.Set("roles", append([]string{}, roles...))
			c.Next()
		})
		r.GET("/requests/:id", s.handleGetAccessRequest)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/requests/"+requestID, nil))
		return w.Code
	}
	for _, c := range []struct {
		who, caller, request string
		roles                []string
		want                 int
	}{
		{"its requester", internal, internalReq, []string{"user"}, http.StatusOK},
		{"an approver of it", approver, internalReq, []string{"user"}, http.StatusOK},
		{"an administrator", admin, internalReq, []string{"admin"}, http.StatusOK},
		{"another user", stranger, internalReq, []string{"user"}, http.StatusNotFound},
		{"the external requester's sponsor", sponsor, externalReq, []string{"user"}, http.StatusOK},
		{"a sponsor, of a request not from their external user", sponsor, internalReq, []string{"user"}, http.StatusNotFound},
		{"an approver, of a request not addressed to them", approver, externalReq, []string{"user"}, http.StatusNotFound},
	} {
		if got := read(c.caller, c.request, c.roles...); got != c.want {
			t.Errorf("%s reading the request: %d, want %d", c.who, got, c.want)
		}
	}
}
