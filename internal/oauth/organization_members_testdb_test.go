package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// memberRoutes drives the organization API's member routes, mounted behind the
// chain cmd/admin-api mounts, and reads memberships back from the database.
type memberRoutes struct {
	t *testing.T
	h *tokenHarness
	r http.Handler
}

func (h *tokenHarness) memberRoutes(t *testing.T) memberRoutes {
	return memberRoutes{t: t, h: h, r: h.adminAPIAfterAuth()}
}

func (m memberRoutes) do(method, path, bearer, body string) *httptest.ResponseRecorder {
	m.t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	m.r.ServeHTTP(w, req)
	return w
}

func (m memberRoutes) add(bearer string, org orgctx.Org, userID, role string) *httptest.ResponseRecorder {
	m.t.Helper()
	return m.do(http.MethodPost, "/api/v1/organizations/"+org.ID+"/members", bearer,
		`{"user_id":"`+userID+`","role":"`+role+`"}`)
}

func (m memberRoutes) remove(bearer string, org orgctx.Org, userID string) *httptest.ResponseRecorder {
	m.t.Helper()
	return m.do(http.MethodDelete, "/api/v1/organizations/"+org.ID+"/members/"+userID, bearer, "")
}

// role is userID's role in org, or "none".
func (m memberRoutes) role(org orgctx.Org, userID string) string {
	m.t.Helper()
	return m.h.scalar(`SELECT COALESCE((SELECT role FROM organization_members
		WHERE organization_id = $1::uuid AND user_id = $2::uuid), 'none')`, org.ID, userID)
}

func (m memberRoutes) owners(org orgctx.Org) string {
	m.t.Helper()
	return m.h.scalar(`SELECT COUNT(*)::text FROM organization_members WHERE organization_id = $1::uuid AND role = 'owner'`, org.ID)
}

// AN ORGANIZATION'S MEMBERS ARE ITS OWN USERS, IN THE ROLES IT GRANTS.
//
// POST /organizations/:id/members accepted any user id -- another
// organization's user, or no user at all -- and any role string, and the
// member routes let an admin demote or remove the owners and an owner remove
// the last owner. Driven through organization.RegisterRoutes behind the chain
// cmd/admin-api mounts, with tokens minted from database rows:
//
//   - A's owner and admin are refused a user of B and an id that names no user
//     with the same 404, and a role the organization does not grant with 400,
//     and nothing is stored; they add A's own users, and change and remove
//     members and admins;
//   - an admin cannot grant the owner role or demote or remove an owner; an
//     owner can;
//   - the last owner can be neither demoted nor removed, by themselves or by
//     the platform admin;
//   - the platform admin adds any user, of any organization, and still only in
//     a role the organization grants and to an organization that exists;
//   - a member of A, and B's owner, are refused as before.
func TestAnOrganizationsMembersAreItsOwnUsersInTheRolesItGrants(t *testing.T) {
	h := newTokenHarness(t)
	orgA, orgB := h.seedOrg("members-a"), h.seedOrg("members-b")
	join := func(org orgctx.Org, userID, role string) {
		h.exec(`INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, $3)`, org.ID, userID, role)
	}
	owner := h.seedUser(orgA.ID, "members-owner", "admin")
	join(orgA, owner, "owner")
	orgAdmin := h.seedUser(orgA.ID, "members-admin", "admin")
	join(orgA, orgAdmin, "admin")
	member := h.seedUser(orgA.ID, "members-member")
	join(orgA, member, "member")
	userA1 := h.seedUser(orgA.ID, "members-user-1")
	userA2 := h.seedUser(orgA.ID, "members-user-2")
	userB := h.seedUser(orgB.ID, "members-user-b")
	ownerB := h.seedUser(orgB.ID, "members-owner-b", "admin")
	join(orgB, ownerB, "owner")
	platform := h.seedUser(middleware.DefaultOrgID, "members-platform", "super_admin")
	nobody := uuid.NewString()

	m := h.memberRoutes(t)
	asOwner, asAdmin := h.accessToken(orgA, owner), h.accessToken(orgA, orgAdmin)
	asPlatform := h.accessToken(defaultOrg, platform)
	expect := func(what string, w *httptest.ResponseRecorder, status int, org orgctx.Org, userID, role string) {
		t.Helper()
		if w.Code != status {
			t.Errorf("%s: %d %s, want %d", what, w.Code, w.Body.String(), status)
		}
		if got := m.role(org, userID); got != role {
			t.Errorf("%s: the user's role in %s is %s, want %s", what, org.Slug, got, role)
		}
	}

	// Another organization's user, and no user at all, read the same.
	for _, cl := range []struct{ name, bearer string }{{"A's owner", asOwner}, {"A's admin", asAdmin}} {
		foreign := m.add(cl.bearer, orgA, userB, "member")
		expect(cl.name+" adding B's user", foreign, http.StatusNotFound, orgA, userB, "none")
		missing := m.add(cl.bearer, orgA, nobody, "member")
		expect(cl.name+" adding an id that names no user", missing, http.StatusNotFound, orgA, nobody, "none")
		if foreign.Body.String() != missing.Body.String() {
			t.Errorf("%s: B's user is answered %s and no user %s; they must read the same", cl.name, foreign.Body.String(), missing.Body.String())
		}
		for _, role := range []string{"superadmin", "Owner", "guest", "super_admin", ""} {
			expect(cl.name+" adding A's user as "+role, m.add(cl.bearer, orgA, userA1, role), http.StatusBadRequest, orgA, userA1, "none")
		}
		expect(cl.name+" adding a user id that is not a UUID", m.add(cl.bearer, orgA, "not-a-uuid", "member"),
			http.StatusBadRequest, orgA, userA1, "none")
	}

	// A's own users, in the roles A grants.
	expect("A's owner adding A's user as a member", m.add(asOwner, orgA, userA1, "member"), http.StatusCreated, orgA, userA1, "member")
	if got := h.scalar(`SELECT invited_by::text FROM organization_members WHERE organization_id = $1::uuid AND user_id = $2::uuid`,
		orgA.ID, userA1); got != owner {
		t.Errorf("the new member was invited by %s, want A's owner %s", got, owner)
	}
	expect("A's admin adding A's user as an admin", m.add(asAdmin, orgA, userA2, "admin"), http.StatusCreated, orgA, userA2, "admin")
	expect("A's admin making a member an admin", m.add(asAdmin, orgA, userA1, "admin"), http.StatusOK, orgA, userA1, "admin")
	expect("A's admin removing an admin", m.remove(asAdmin, orgA, userA1), http.StatusOK, orgA, userA1, "none")

	// An admin does not touch the owners.
	expect("A's admin making an admin an owner", m.add(asAdmin, orgA, userA2, "owner"), http.StatusForbidden, orgA, userA2, "admin")
	expect("A's admin adding A's user as an owner", m.add(asAdmin, orgA, userA1, "owner"), http.StatusForbidden, orgA, userA1, "none")
	expect("A's admin demoting the owner", m.add(asAdmin, orgA, owner, "member"), http.StatusForbidden, orgA, owner, "owner")
	expect("A's admin removing the owner", m.remove(asAdmin, orgA, owner), http.StatusForbidden, orgA, owner, "owner")

	// An owner does, and an organization keeps its last owner.
	expect("A's owner making an admin an owner", m.add(asOwner, orgA, userA2, "owner"), http.StatusOK, orgA, userA2, "owner")
	expect("A's owner stepping down while another owner remains", m.add(asOwner, orgA, owner, "admin"), http.StatusOK, orgA, owner, "admin")
	asLastOwner := h.accessToken(orgA, userA2)
	expect("the last owner demoting themselves", m.add(asLastOwner, orgA, userA2, "admin"), http.StatusConflict, orgA, userA2, "owner")
	expect("the last owner removing themselves", m.remove(asLastOwner, orgA, userA2), http.StatusConflict, orgA, userA2, "owner")
	expect("the platform admin removing the last owner", m.remove(asPlatform, orgA, userA2), http.StatusConflict, orgA, userA2, "owner")
	expect("the platform admin demoting the last owner", m.add(asPlatform, orgA, userA2, "member"), http.StatusConflict, orgA, userA2, "owner")
	if got := m.owners(orgA); got != "1" {
		t.Errorf("A has %s owners, want 1", got)
	}

	// The platform admin adds any existing user, in a role A grants.
	expect("the platform admin adding B's user to A", m.add(asPlatform, orgA, userB, "member"), http.StatusCreated, orgA, userB, "member")
	expect("the platform admin adding an id that names no user", m.add(asPlatform, orgA, nobody, "member"), http.StatusNotFound, orgA, nobody, "none")
	expect("the platform admin adding A's user as superadmin", m.add(asPlatform, orgA, userA1, "superadmin"), http.StatusBadRequest, orgA, userA1, "none")
	unknownOrg := orgctx.Org{ID: uuid.NewString(), Slug: "unknown"}
	expect("the platform admin adding a member to an organization that does not exist", m.add(asPlatform, unknownOrg, userA1, "member"),
		http.StatusNotFound, unknownOrg, userA1, "none")

	// Removing someone who is not a member is 404, not a server error.
	expect("the last owner removing a non-member", m.remove(asLastOwner, orgA, userA1), http.StatusNotFound, orgA, userA1, "none")
	if w := m.remove(asLastOwner, orgA, "not-a-uuid"); w.Code != http.StatusNotFound {
		t.Errorf("the last owner removing a member id that is not a UUID: %d %s, want 404", w.Code, w.Body.String())
	}

	// Callers the write gate refused are refused still.
	expect("A's member adding a user", m.add(h.accessToken(orgA, member), orgA, userA1, "member"), http.StatusForbidden, orgA, userA1, "none")
	expect("B's owner adding their own user to A", m.add(h.accessToken(orgB, ownerB), orgA, ownerB, "owner"), http.StatusForbidden, orgA, ownerB, "none")
	expect("B's owner removing A's owner", m.remove(h.accessToken(orgB, ownerB), orgA, userA2), http.StatusForbidden, orgA, userA2, "owner")
}

// Membership changes to one organization wait for each other. Two owners are
// each removed at once -- one removal in flight in a transaction the test
// holds, the other through the API -- and the organization keeps one owner:
// the API's removal waits for the organization's row, then finds the other
// owner gone and refuses to remove the last. Without the lock it would count
// two owners, remove its own, and leave none once the other committed.
func TestTheLastOwnerSurvivesTwoRemovalsAtOnce(t *testing.T) {
	h := newTokenHarness(t)
	org := h.seedOrg("members-race")
	first := h.seedUser(org.ID, "members-race-1")
	second := h.seedUser(org.ID, "members-race-2")
	for _, u := range []string{first, second} {
		h.exec(`INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'owner')`, org.ID, u)
	}
	m := h.memberRoutes(t)
	asPlatform := h.accessToken(defaultOrg, h.seedUser(middleware.DefaultOrgID, "members-race-platform", "super_admin"))

	ctx := context.Background()
	tx, err := h.db.Pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT id FROM organizations WHERE id = $1::uuid FOR UPDATE`, org.ID); err != nil {
		t.Fatalf("lock the organization: %v", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM organization_members WHERE organization_id = $1::uuid AND user_id = $2::uuid`, org.ID, first); err != nil {
		t.Fatalf("remove the first owner: %v", err)
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- m.remove(asPlatform, org, second) }()
	select {
	case w := <-done:
		t.Fatalf("removing the second owner answered %d %s while another removal held the organization; it must wait for it",
			w.Code, w.Body.String())
	case <-time.After(2 * time.Second):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit the first removal: %v", err)
	}
	select {
	case w := <-done:
		if w.Code != http.StatusConflict {
			t.Errorf("removing the second owner once the first was gone: %d %s, want 409", w.Code, w.Body.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("removing the second owner never answered")
	}
	if got, owners := m.role(org, second), m.owners(org); got != "owner" || owners != "1" {
		t.Errorf("after both removals the second user is %s and the organization has %s owners; want owner and 1", got, owners)
	}
}
