package admin

import (
	"testing"

	"github.com/gin-gonic/gin"
)

// A certification decision that could not be enforced is not recorded.
//
// The decision and the access removal used to be two separate statements, and
// only the first was checked. The item was marked decision='revoked' by a
// statement that answers 500 on failure; the DELETE that actually removed the
// role, the application assignment or the group membership ran underneath with
// its error discarded. So a reviewer clicked Revoke, the certification recorded
// that the access was revoked, the campaign counted the item as decided -- and
// the access was still there.
//
// In an identity governance product that is the worst available failure: the
// evidence says the access was removed and it was not. They share a transaction
// now, which is what this test is about.
func TestAttestationRevokeAndItsDecisionAreAtomic(t *testing.T) {
	f, cleanup := newAttFixture(t)
	if f == nil {
		return
	}
	defer cleanup()

	// A role, and a user holding it, for the item to revoke.
	var roleID string
	if err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO roles (name, description, org_id) VALUES ('att-revoke-role', 'seeded', $1::uuid) RETURNING id::text`,
		f.orgA).Scan(&roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	holder := f.seedUser("att-a-holder", f.orgA, true)
	if _, err := f.db.Pool.Exec(f.ctx,
		`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		holder, roleID, f.orgA); err != nil {
		t.Fatalf("seed user_role: %v", err)
	}
	if _, err := f.db.Pool.Exec(f.ctx,
		`UPDATE attestation_items SET user_id = $1::uuid, resource_id = $2::uuid WHERE id = $3::uuid`,
		holder, roleID, f.itemA); err != nil {
		t.Fatalf("point the item at the role: %v", err)
	}

	held := func() int {
		t.Helper()
		var n int
		if err := f.db.Pool.QueryRow(f.ctx,
			`SELECT COUNT(*) FROM user_roles WHERE user_id = $1::uuid AND role_id = $2::uuid`,
			holder, roleID).Scan(&n); err != nil {
			t.Fatalf("count the role assignment: %v", err)
		}
		return n
	}
	decide := func() int {
		t.Helper()
		return f.call(f.orgA, "PUT", "/attestation/campaigns/"+f.campaignA+"/items/"+f.itemA+"/decide",
			gin.Params{{Key: "id", Value: f.campaignA}, {Key: "itemId", Value: f.itemA}},
			map[string]string{"decision": "revoked", "comments": "not needed"},
			f.svc.handleDecideAttestationItem).Code
	}

	t.Run("a revocation that cannot run leaves the item pending", func(t *testing.T) {
		// user_roles out of reach, so the DELETE cannot run. Everything before
		// it succeeds, which is exactly the case the discarded error hid:
		// the decision recorded, the access untouched.
		if _, err := f.db.Pool.Exec(f.ctx, `ALTER TABLE user_roles RENAME TO user_roles_hidden`); err != nil {
			t.Fatalf("hide user_roles: %v", err)
		}
		code := decide()
		if _, err := f.db.Pool.Exec(f.ctx, `ALTER TABLE user_roles_hidden RENAME TO user_roles`); err != nil {
			t.Fatalf("restore user_roles: %v", err)
		}

		if code != 500 {
			t.Errorf("a revocation that could not remove the access answered %d, want 500", code)
		}
		if decision, _ := f.itemState(f.itemA); decision != "pending" {
			t.Errorf("the item reads %q after a revocation that did not happen; want pending -- "+
				"a certification that records access as removed when it is still held is the "+
				"worst failure this product has", decision)
		}
		if n := held(); n != 1 {
			t.Errorf("the role assignment count is %d, want 1: it should not have been touched", n)
		}
	})

	t.Run("a revocation that runs removes the access and records the decision", func(t *testing.T) {
		if code := decide(); code != 200 {
			t.Fatalf("revoke answered %d, want 200", code)
		}
		if decision, _ := f.itemState(f.itemA); decision != "revoked" {
			t.Errorf("the item reads %q, want revoked", decision)
		}
		if n := held(); n != 0 {
			t.Errorf("%d role assignment(s) survived a revoked certification", n)
		}
	})
}
