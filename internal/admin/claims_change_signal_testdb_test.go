package admin

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/ssfsignal"
)

// The console's bulk operations and a certification's revocation tell the
// tenant's SSF receivers when they change a user's roles or groups (CAEP
// token-claims-change), once, with the path as the reason, and say nothing
// when they changed nothing. On the migrated schema:
//
//   - a bulk role assignment and group addition, and the removals;
//   - a bulk assignment of a role the user already holds, and a removal of
//     one the user does not hold;
//   - a certification that revokes a role and one that revokes a group.
func TestConsoleRoleAndGroupChangesTellTheReceivers(t *testing.T) {
	f, cleanup := newAttFixture(t)
	if f == nil {
		return
	}
	defer cleanup()
	org := f.orgA
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := f.db.Pool.QueryRow(f.ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := f.db.Pool.Exec(f.ctx, q, args...); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
	}
	role := scalar(`INSERT INTO roles (name, description, org_id) VALUES ('cc-bulk-role', 'seeded', $1::uuid) RETURNING id::text`, org)
	certRole := scalar(`INSERT INTO roles (name, description, org_id) VALUES ('cc-cert-role', 'seeded', $1::uuid) RETURNING id::text`, org)
	group := scalar(`INSERT INTO groups (name, org_id) VALUES ('cc-bulk-group', $1::uuid) RETURNING id::text`, org)
	certGroup := scalar(`INSERT INTO groups (name, org_id) VALUES ('cc-cert-group', $1::uuid) RETURNING id::text`, org)

	assigned, already := f.seedUser("cc-assigned", org, true), f.seedUser("cc-already", org, true)
	removed, stranger := f.seedUser("cc-removed", org, true), f.seedUser("cc-stranger", org, true)
	joined, left := f.seedUser("cc-joined", org, true), f.seedUser("cc-left", org, true)
	exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid), ($4::uuid, $2::uuid, $3::uuid)`,
		already, role, org, removed)
	exec(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`, left, group, org)

	bulk := func(opType, param, value string, ids ...string) {
		t.Helper()
		params, _ := json.Marshal(map[string]string{param: value})
		op := scalar(`INSERT INTO bulk_operations (type, status, total_items, parameters, org_id)
			VALUES ($1, 'running', $2, $3, $4::uuid) RETURNING id::text`, opType, len(ids), params, org)
		f.svc.executeBulkOperation(org, op, opType, ids, params)
	}
	bulk("assign_role", "role_id", role, assigned, already)
	bulk("remove_role", "role_id", role, removed, stranger)
	bulk("add_to_group", "group_id", group, joined)
	bulk("remove_from_group", "group_id", group, left, stranger)

	certify := func(name, holder, resourceType, resourceID string) {
		t.Helper()
		campaign, item, _ := f.seedCampaign(org, name)
		exec(`UPDATE attestation_items SET user_id = $1::uuid, resource_id = $2::uuid, resource_type = $3 WHERE id = $4::uuid`,
			holder, resourceID, resourceType, item)
		code := f.call(org, "PUT", "/attestation/campaigns/"+campaign+"/items/"+item+"/decide",
			gin.Params{{Key: "id", Value: campaign}, {Key: "itemId", Value: item}},
			map[string]string{"decision": "revoked", "comments": "not needed"},
			f.svc.handleDecideAttestationItem).Code
		if code != 200 {
			t.Fatalf("revoke %s answered %d, want 200", name, code)
		}
	}
	certRoleHolder, certGroupMember := f.seedUser("cc-cert-holder", org, true), f.seedUser("cc-cert-member", org, true)
	exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`, certRoleHolder, certRole, org)
	exec(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`, certGroupMember, certGroup, org)
	certify("cc-cert-role", certRoleHolder, "role", certRole)
	certify("cc-cert-group", certGroupMember, "group", certGroup)

	reasons := func(userID string) string {
		return scalar(`SELECT COALESCE(string_agg(claims->>'reason', ',' ORDER BY id), '') FROM ssf_pending_events
			WHERE subject_id = $1 AND event_type = $2 AND org_id = $3::uuid`, userID, ssfsignal.TokenClaimsChange, org)
	}
	for _, c := range []struct{ who, userID, want string }{
		{"a bulk role assignment", assigned, "bulk assign_role"},
		{"a bulk assignment of a role already held", already, ""},
		{"a bulk role removal", removed, "bulk remove_role"},
		{"bulk removals of what the user does not hold", stranger, ""},
		{"a bulk group addition", joined, "bulk add_to_group"},
		{"a bulk group removal", left, "bulk remove_from_group"},
		{"a certification revoking a role", certRoleHolder, "attestation.revoked"},
		{"a certification revoking a group", certGroupMember, "attestation.revoked"},
	} {
		if got := reasons(c.userID); got != c.want {
			t.Errorf("%s: token-claims-change reasons %q, want %q", c.who, got, c.want)
		}
	}
	if n := scalar(`SELECT count(*)::text FROM ssf_pending_events WHERE event_type = $1`, ssfsignal.TokenClaimsChange); n != fmt.Sprint(6) {
		t.Errorf("%s token-claims-change signals in all, want 6", n)
	}
}
