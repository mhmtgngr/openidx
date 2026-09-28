package oauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// ONLY A PLATFORM ADMIN CHANGES AN ORGANIZATION'S PLAN, STATUS AND LIMITS.
//
// PUT /organizations/:id let an owner or admin of an organization set its plan
// and status -- upgrade itself, lift its own suspension. Driven through
// organization.RegisterRoutes behind the chain cmd/admin-api mounts, with tokens
// minted from database rows, against an organization that is suspended on the
// free plan:
//
//   - its owner and its admin are refused with 403 naming the field when they
//     change the plan, the status, max_users or max_applications, alone or
//     beside a new name, and nothing of the request is written;
//   - they still rename it, sending the plan and status as they are -- the body
//     the console sends -- or the name alone, and the plan, status and limits
//     are left as they were;
//   - a member, and another organization's owner, are refused as before;
//   - the platform admin changes all four, and gets 404 for an organization
//     that does not exist.
func TestOnlyAPlatformAdminChangesAnOrganizationsPlanStatusAndLimits(t *testing.T) {
	h := newTokenHarness(t)
	orgA, orgB := h.seedOrg("plan-a"), h.seedOrg("plan-b")
	h.exec(`UPDATE organizations SET plan = 'free', status = 'suspended', max_users = 10, max_applications = 5 WHERE id = $1::uuid`, orgA.ID)
	join := func(org orgctx.Org, userID, role string) {
		h.exec(`INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, $3)`, org.ID, userID, role)
	}
	owner := h.seedUser(orgA.ID, "plan-owner", "admin")
	join(orgA, owner, "owner")
	orgAdmin := h.seedUser(orgA.ID, "plan-org-admin", "admin")
	join(orgA, orgAdmin, "admin")
	member := h.seedUser(orgA.ID, "plan-member")
	join(orgA, member, "member")
	ownerB := h.seedUser(orgB.ID, "plan-owner-b", "admin")
	join(orgB, ownerB, "owner")
	platform := h.seedUser(middleware.DefaultOrgID, "plan-platform", "super_admin")

	api := h.adminAPIAfterAuth()
	put := func(bearer, org, body string) *httptest.ResponseRecorder {
		t.Helper()
		return serve(api, http.MethodPut, "/api/v1/organizations/"+org, "application/json", body, "Authorization", "Bearer "+bearer)
	}
	record := func() string {
		return h.scalar(`SELECT name || '|' || plan || '|' || status || '|' || max_users || '|' || max_applications
			FROM organizations WHERE id = $1::uuid`, orgA.ID)
	}
	name := orgA.Slug // seedOrg names an organization after its slug
	original := name + "|free|suspended|10|5"
	if got := record(); got != original {
		t.Fatalf("A seeded as %s, want %s", got, original)
	}

	callers := []struct {
		name, bearer string
	}{
		{"A's owner", h.accessToken(orgA, owner)},
		{"A's admin", h.accessToken(orgA, orgAdmin)},
	}
	for _, cl := range callers {
		for _, attempt := range []struct {
			body, field string
		}{
			{`{"plan":"enterprise"}`, "plan"},
			{`{"status":"active"}`, "status"},
			{`{"max_users":100000}`, "max_users"},
			{`{"max_applications":100000}`, "max_applications"},
			{`{"name":"renamed by ` + cl.name + `","plan":"enterprise","status":"suspended"}`, "plan"},
			{`{"name":"renamed by ` + cl.name + `","plan":"free","status":"active"}`, "status"},
		} {
			w := put(cl.bearer, orgA.ID, attempt.body)
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"`+attempt.field+`"`) {
				t.Errorf("%s sending %s: %d %s, want 403 naming %s", cl.name, attempt.body, w.Code, w.Body.String(), attempt.field)
			}
			if got := record(); got != original {
				t.Fatalf("%s sending %s was refused but A is now %s, was %s", cl.name, attempt.body, got, original)
			}
		}
	}

	// Renaming, with the plan and status restated as they are and alone.
	w := put(callers[0].bearer, orgA.ID, `{"name":"Renamed by its owner","plan":"free","status":"suspended","max_users":10,"max_applications":5}`)
	if w.Code != http.StatusOK || record() != "Renamed by its owner|free|suspended|10|5" {
		t.Errorf("A's owner renaming A with the rest restated: %d %s, A is %s", w.Code, w.Body.String(), record())
	}
	w = put(callers[1].bearer, orgA.ID, `{"name":"Renamed by its admin"}`)
	if w.Code != http.StatusOK || record() != "Renamed by its admin|free|suspended|10|5" {
		t.Errorf("A's admin renaming A: %d %s, A is %s", w.Code, w.Body.String(), record())
	}

	// Callers the write gate already refused are refused still.
	for _, cl := range []struct {
		name, bearer string
	}{
		{"A's member", h.accessToken(orgA, member)},
		{"B's owner", h.accessToken(orgB, ownerB)},
	} {
		before := record()
		if w := put(cl.bearer, orgA.ID, `{"name":"taken","plan":"enterprise","status":"active"}`); w.Code != http.StatusForbidden || record() != before {
			t.Errorf("%s updating A: %d %s, A is %s; want 403 and A unchanged", cl.name, w.Code, w.Body.String(), record())
		}
	}

	// The platform admin changes the plan, the status and the limits.
	platformBearer := h.accessToken(defaultOrg, platform)
	w = put(platformBearer, orgA.ID, `{"plan":"enterprise","status":"active","max_users":500,"max_applications":50}`)
	if w.Code != http.StatusOK || record() != "Renamed by its admin|enterprise|active|500|50" {
		t.Errorf("the platform admin changing A's plan, status and limits: %d %s, A is %s", w.Code, w.Body.String(), record())
	}
	for _, bad := range []string{`{}`, `{"name":"  "}`, `{"plan":""}`, `{"max_users":-1}`} {
		if w := put(platformBearer, orgA.ID, bad); w.Code != http.StatusBadRequest {
			t.Errorf("the platform admin sending %s: %d %s, want 400", bad, w.Code, w.Body.String())
		}
	}
	for _, id := range []string{uuid.NewString(), "not-a-uuid"} {
		if w := put(platformBearer, id, `{"plan":"enterprise"}`); w.Code != http.StatusNotFound {
			t.Errorf("the platform admin updating organization %s: %d %s, want 404", id, w.Code, w.Body.String())
		}
	}
	if got := record(); got != "Renamed by its admin|enterprise|active|500|50" {
		t.Errorf("A after the refused requests: %s", got)
	}
}
