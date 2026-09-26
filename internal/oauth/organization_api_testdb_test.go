package oauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// seedAdminID is the administrator the installer seeds, an owner of the
// default organization.
const seedAdminID = "00000000-0000-0000-0000-000000000001"

// THE ORGANIZATION API KEEPS ORGANIZATIONS APART.
//
// organizations and organization_members span the install, outside the RLS
// belt, so the organization API's own checks are all that keeps one tenant's
// callers out of another's rows there. Driven through
// organization.RegisterRoutes behind the chain cmd/admin-api mounts --
// AuthWithAPIKey, then the tenant resolver with the platform-admin predicate --
// with tokens minted from database rows:
//
//   - an organization's record and member list are read by its members, in
//     any role, and by the platform admin; anyone else -- another
//     organization's owner or super_admin, an admin of the default
//     organization -- gets the 404 an unknown id gets, carrying nothing of the
//     organization;
//   - only the platform admin creates an organization, and owns it; the
//     members of A, B's super_admin and an admin of the default organization
//     are refused with 403 and no organization appears;
//   - /me/organizations refuses a credential with no user behind it instead
//     of answering with the seed admin's organizations.
func TestTheOrganizationAPIKeepsOrganizationsApart(t *testing.T) {
	h := newTokenHarness(t)
	orgA, orgB := h.seedOrg("orgapi-a"), h.seedOrg("orgapi-b")
	join := func(org orgctx.Org, userID, role string) {
		h.exec(`INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, $3)
			ON CONFLICT (organization_id, user_id) DO UPDATE SET role = EXCLUDED.role`, org.ID, userID, role)
	}
	member := h.seedUser(orgA.ID, "orgapi-member")
	join(orgA, member, "member")
	owner := h.seedUser(orgA.ID, "orgapi-owner", "admin")
	join(orgA, owner, "owner")
	ownerB := h.seedUser(orgB.ID, "orgapi-owner-b", "admin")
	join(orgB, ownerB, "owner")
	superB := h.seedUser(orgB.ID, "orgapi-super-b", "super_admin")
	join(orgB, superB, "admin")
	defaultAdmin := h.seedUser(middleware.DefaultOrgID, "orgapi-default-admin", "admin")
	platform := h.seedUser(middleware.DefaultOrgID, "orgapi-platform", "super_admin")
	// An operator's account that created B owns it, as the seed admin does
	// here; it owns the default organization from the installer on.
	join(orgB, seedAdminID, "owner")

	api := h.adminAPIAfterAuth()
	call := func(method, path, bearer, body string) *httptest.ResponseRecorder {
		t.Helper()
		contentType := ""
		if body != "" {
			contentType = "application/json"
		}
		return serve(api, method, path, contentType, body, "Authorization", "Bearer "+bearer)
	}

	type caller struct {
		name   string
		bearer string
		reads  map[string]bool // organization id -> may read it
	}
	callers := []caller{
		{"A's member", h.accessToken(orgA, member), map[string]bool{orgA.ID: true}},
		{"A's owner", h.accessToken(orgA, owner), map[string]bool{orgA.ID: true}},
		{"B's owner", h.accessToken(orgB, ownerB), map[string]bool{orgB.ID: true}},
		{"B's super_admin", h.accessToken(orgB, superB), map[string]bool{orgB.ID: true}},
		{"an admin of the default organization", h.accessToken(defaultOrg, defaultAdmin), map[string]bool{}},
		{"the platform admin", h.accessToken(defaultOrg, platform), map[string]bool{orgA.ID: true, orgB.ID: true}},
	}

	// What a response carrying the organization would show: its slug in its
	// record, and an owner's user id in its member list.
	record := map[string]string{orgA.ID: orgA.Slug, orgB.ID: orgB.Slug}
	roster := map[string]string{orgA.ID: owner, orgB.ID: ownerB}

	for _, cl := range callers {
		for _, org := range []orgctx.Org{orgA, orgB} {
			for _, r := range []struct {
				path, marker string
			}{
				{"/api/v1/organizations/" + org.ID, record[org.ID]},
				{"/api/v1/organizations/" + org.ID + "/members", roster[org.ID]},
			} {
				w := call(http.MethodGet, r.path, cl.bearer, "")
				shows := strings.Contains(w.Body.String(), r.marker)
				if cl.reads[org.ID] {
					if w.Code != http.StatusOK || !shows {
						t.Errorf("%s reading %s: %d %s, want 200 carrying %s", cl.name, r.path, w.Code, w.Body.String(), r.marker)
					}
					continue
				}
				if w.Code != http.StatusNotFound || shows {
					t.Errorf("%s reading %s: %d %s, want 404 carrying nothing of it", cl.name, r.path, w.Code, w.Body.String())
				}
			}
		}
	}

	// An id that names no organization reads as one the caller may not see,
	// for a member and for the platform admin alike, and an id that is not a
	// UUID is the same 404 rather than a database error.
	unknown := uuid.NewString()
	for _, cl := range []caller{callers[0], callers[len(callers)-1]} {
		for _, path := range []string{
			"/api/v1/organizations/" + unknown,
			"/api/v1/organizations/not-a-uuid",
		} {
			if w := call(http.MethodGet, path, cl.bearer, ""); w.Code != http.StatusNotFound {
				t.Errorf("%s reading %s: %d %s, want 404", cl.name, path, w.Code, w.Body.String())
			}
		}
	}
	if w := call(http.MethodGet, "/api/v1/organizations/"+unknown+"/members", callers[0].bearer, ""); w.Code != http.StatusNotFound {
		t.Errorf("A's member listing the members of an unknown organization: %d, want 404", w.Code)
	}

	// Creating an organization.
	organizations := func(slug string) string {
		return h.scalar(`SELECT COUNT(*)::text FROM organizations WHERE slug = $1`, slug)
	}
	for i, cl := range callers[:len(callers)-1] {
		slug := fmt.Sprintf("orgapi-new-%d-%s", i, h.suffix)
		w := call(http.MethodPost, "/api/v1/organizations", cl.bearer, `{"name":"created by the test","slug":"`+slug+`"}`)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s creating an organization: %d %s, want 403", cl.name, w.Code, w.Body.String())
		}
		if got := organizations(slug); got != "0" {
			t.Errorf("%s was refused but the organization exists (%s rows)", cl.name, got)
		}
	}
	slug := "orgapi-new-platform-" + h.suffix
	if w := call(http.MethodPost, "/api/v1/organizations", callers[len(callers)-1].bearer,
		`{"name":"created by the test","slug":"`+slug+`"}`); w.Code != http.StatusCreated {
		t.Fatalf("the platform admin creating an organization: %d %s, want 201", w.Code, w.Body.String())
	}
	if got := h.scalar(`SELECT COALESCE((SELECT m.role FROM organization_members m JOIN organizations o ON o.id = m.organization_id
		WHERE o.slug = $1 AND m.user_id = $2::uuid), '<none>')`, slug, platform); got != "owner" {
		t.Errorf("the platform admin's new organization: their membership is %q, want owner", got)
	}

	// Whose organizations /me/organizations lists.
	machine := h.tokenFor(orgA, "", h.registerClient(orgA, "orgapi-machine", true))
	w := call(http.MethodGet, "/api/v1/me/organizations", machine, "")
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), orgB.ID) ||
		strings.Contains(w.Body.String(), middleware.DefaultOrgID) {
		t.Errorf("a client-credentials token of A: %d %s, want 403 and none of the seed admin's organizations", w.Code, w.Body.String())
	}
	w = call(http.MethodGet, "/api/v1/me/organizations", callers[0].bearer, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), orgA.ID) || strings.Contains(w.Body.String(), orgB.ID) {
		t.Errorf("A's member: %d %s, want 200 listing A and not B", w.Code, w.Body.String())
	}
}
