package governance

import (
	"net/http"
	"testing"
)

// An external (vendor) user is never an approver (invariant I2 of the
// third-party access framework).
//
// A role an external user cannot hold already keeps most of them out of a
// chain, but a step can still name one: a group step on a group opened to
// external users, a manager step, a specific user. The step resolver drops
// them, so the step routes to its internal members only, and a step that has
// nobody else left is refused like any other short step instead of filing a
// request an external user could approve. The database refuses such an
// approval row as well (migration v214), which without the resolver's filter
// would fail the request outright.
func TestAnExternalUserIsNeverAnApprover(t *testing.T) {
	f := newApprovalFixture(t)
	f.seedApprovers()
	// erin is a vendor's person; dave is an employee. Both are in the step.
	f.exec(`UPDATE users SET user_type = 'external' WHERE id = $1`, apErin)
	f.exec(`INSERT INTO groups (id, name, org_id) VALUES ('88888888-8888-8888-8888-888888888888', 'mixed', $1)`, arOrg)
	f.exec(`INSERT INTO group_memberships (user_id, group_id, org_id)
	        VALUES ($1, '88888888-8888-8888-8888-888888888888', $3), ($2, '88888888-8888-8888-8888-888888888888', $3)`,
		apDave, apErin, arOrg)
	f.policy(`[{"order":1,"type":"group","group_id":"88888888-8888-8888-8888-888888888888"}]`, 0)

	w := f.createAs(arAlice, "role", arRole)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	id := body(t, w)["id"].(string)
	rows, err := f.svc.db.Pool.Query(f.ctx, `SELECT approver_id::text FROM access_request_approvals WHERE request_id = $1`, id)
	if err != nil {
		t.Fatal(err)
	}
	var approvers []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		approvers = append(approvers, a)
	}
	rows.Close()
	if len(approvers) != 1 || approvers[0] != apDave {
		t.Fatalf("approvers = %v, want only the internal member %s", approvers, apDave)
	}
	if contains(f.queueOf(apErin), id) {
		t.Error("the request is in the external user's approval queue")
	}

	// A step whose only approver is external has nobody left to approve.
	f.exec(`DELETE FROM approval_policies`)
	f.policy(`[{"order":1,"type":"specific_user","approver_id":"`+apErin+`"}]`, 0)
	if w := f.createAs(arAlice, "role", arRole); w.Code == http.StatusCreated {
		t.Fatalf("a request routed only to an external user was created: %s", w.Body.String())
	}
}
