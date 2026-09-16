package admin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"

	"github.com/openidx/openidx/internal/common/database"
)

// TAKING A ROLE AWAY AND CUTTING THE TOKEN THAT NAMES IT ARE TWO THINGS.
//
// The sever census guards the first shape — an account disabled or deleted. It
// never saw this one, because removing a role or a group does not touch the
// user row. The token carries both: the enforcement point reads the role list
// from the "roles" claim and resolves that set's permissions itself, and
// "groups" is a claim for the same reason. So a certification that refuses
// somebody's access, or a bulk "remove admin from these 400 users", removed the
// row, reported success, and left every token still asserting what was taken.
//
// Both paths here are measured against a real PostgreSQL and a real Redis, with
// the general and revocation roles on SEPARATE Redis databases so a marker
// written to the wrong role is visible, and read back through the key the
// enforcement point reads.

// attRedis attaches Redis to the attestation fixture, which builds its Service
// without one.
func attRedis(t *testing.T, f *attFixture) (general, revocationDB *goredis.Client) {
	t.Helper()
	general, revocationDB = openAdminSeverRedis(t)
	f.svc.redis = &database.RedisClient{Client: general, Revocation: revocationDB}
	return general, revocationDB
}

// A certification that refuses access is the sibling of an access-review
// revocation, which cuts tokens. This one did not.
func TestARefusedCertificationCutsTheTokenStillNamingTheRole(t *testing.T) {
	f, cleanup := newAttFixture(t)
	if f == nil {
		return
	}
	defer cleanup()
	general, revocationDB := attRedis(t, f)

	var roleID string
	if err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO roles (name, description, org_id) VALUES ('cert-cut-role', 'seeded', $1::uuid) RETURNING id::text`,
		f.orgA).Scan(&roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	holder := f.seedUser("cert-cut-holder", f.orgA, true)
	if _, err := f.db.Pool.Exec(f.ctx,
		`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		holder, roleID, f.orgA); err != nil {
		t.Fatalf("seed user_role: %v", err)
	}
	if _, err := f.db.Pool.Exec(f.ctx,
		`UPDATE attestation_items SET user_id = $1::uuid, resource_id = $2::uuid, resource_type = 'role' WHERE id = $3::uuid`,
		holder, roleID, f.itemA); err != nil {
		t.Fatalf("point the item at the role: %v", err)
	}

	code := f.call(f.orgA, "PUT", "/attestation/campaigns/"+f.campaignA+"/items/"+f.itemA+"/decide",
		gin.Params{{Key: "id", Value: f.campaignA}, {Key: "itemId", Value: f.itemA}},
		map[string]string{"decision": "revoked", "comments": "not needed"},
		f.svc.handleDecideAttestationItem).Code
	if code != 200 {
		t.Fatalf("revoke answered %d, want 200", code)
	}

	if !revoked(t, revocationDB, holder) {
		t.Error("the certification removed the role and left the token that names it working; " +
			"an access certification whose evidence says the access was removed is the worst place for this")
	}
	if revoked(t, general, holder) {
		t.Error("the marker went to the general Redis, where the enforcement point does not look")
	}
}

// A revocation that could not remove the access must not cut the token either:
// the transaction rolls back, the user still holds the role, and a marker there
// is a logout that fixes nothing while reading as though the certification had
// been enforced.
func TestACertificationThatCouldNotRevokeCutsNothing(t *testing.T) {
	f, cleanup := newAttFixture(t)
	if f == nil {
		return
	}
	defer cleanup()
	_, revocationDB := attRedis(t, f)

	var roleID string
	if err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO roles (name, description, org_id) VALUES ('cert-fail-role', 'seeded', $1::uuid) RETURNING id::text`,
		f.orgA).Scan(&roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	holder := f.seedUser("cert-fail-holder", f.orgA, true)
	if _, err := f.db.Pool.Exec(f.ctx,
		`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		holder, roleID, f.orgA); err != nil {
		t.Fatalf("seed user_role: %v", err)
	}
	if _, err := f.db.Pool.Exec(f.ctx,
		`UPDATE attestation_items SET user_id = $1::uuid, resource_id = $2::uuid, resource_type = 'role' WHERE id = $3::uuid`,
		holder, roleID, f.itemA); err != nil {
		t.Fatalf("point the item at the role: %v", err)
	}

	if _, err := f.db.Pool.Exec(f.ctx, `ALTER TABLE user_roles RENAME TO user_roles_hidden`); err != nil {
		t.Fatalf("hide user_roles: %v", err)
	}
	code := f.call(f.orgA, "PUT", "/attestation/campaigns/"+f.campaignA+"/items/"+f.itemA+"/decide",
		gin.Params{{Key: "id", Value: f.campaignA}, {Key: "itemId", Value: f.itemA}},
		map[string]string{"decision": "revoked", "comments": "not needed"},
		f.svc.handleDecideAttestationItem).Code
	if _, err := f.db.Pool.Exec(f.ctx, `ALTER TABLE user_roles_hidden RENAME TO user_roles`); err != nil {
		t.Fatalf("restore user_roles: %v", err)
	}

	if code != 500 {
		t.Fatalf("a revocation that could not remove the access answered %d, want 500", code)
	}
	if revoked(t, revocationDB, holder) {
		t.Error("nothing was removed, so nothing should have been cut")
	}
}

// A bulk remove_role is the shape where the gap is widest: one operator action,
// hundreds of users, every one of them keeping a live token that still names
// the role.
func TestABulkRoleRemovalCutsTheTokensOfEveryUserItTouched(t *testing.T) {
	pool := openAdminSeverPool(t)
	general, revocationDB := openAdminSeverRedis(t)
	svc := newAdminSeverService(t, pool, general, revocationDB)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `
		CREATE TABLE user_roles (user_id uuid, role_id uuid, org_id uuid, assigned_at timestamptz,
			PRIMARY KEY (user_id, role_id));
		CREATE TABLE group_memberships (user_id uuid, group_id uuid, org_id uuid, joined_at timestamptz);
		CREATE TABLE bulk_operations (id uuid PRIMARY KEY, org_id uuid, status text,
			processed_items int, success_count int, error_count int, errors jsonb, completed_at timestamptz);
		CREATE TABLE bulk_operation_items (operation_id uuid, entity_id uuid, org_id uuid,
			status text, error_message text, processed_at timestamptz);`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	org := uuid.NewString()
	roleID := uuid.NewString()
	held := uuid.NewString()   // actually has the role
	unheld := uuid.NewString() // does not
	opID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO bulk_operations (id, org_id, status) VALUES ($1,$2,'processing')`, opID, org); err != nil {
		t.Fatalf("seed operation: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, held, roleID, org); err != nil {
		t.Fatalf("seed assignment: %v", err)
	}

	params, _ := json.Marshal(map[string]string{"role_id": roleID})
	svc.executeBulkOperation(org, opID, "remove_role", []string{held, unheld}, params)

	if !revoked(t, revocationDB, held) {
		t.Error("a bulk role removal left the token naming that role working; one operator action, " +
			"one live credential per user, and the operation reported success")
	}
	if revoked(t, general, held) {
		t.Error("the marker went to the general Redis, where the enforcement point does not look")
	}
	// Nothing was taken from this one, so nothing should be cut: a logout that
	// takes nothing away is an outage the operator did not ask for.
	if revoked(t, revocationDB, unheld) {
		t.Error("a user who never held the role was logged out by its removal")
	}
}

// "groups" is a claim too, so the same holds for a bulk group removal.
func TestABulkGroupRemovalCutsTheTokensOfEveryUserItTouched(t *testing.T) {
	pool := openAdminSeverPool(t)
	general, revocationDB := openAdminSeverRedis(t)
	svc := newAdminSeverService(t, pool, general, revocationDB)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `
		CREATE TABLE user_roles (user_id uuid, role_id uuid, org_id uuid, assigned_at timestamptz);
		CREATE TABLE group_memberships (user_id uuid, group_id uuid, org_id uuid, joined_at timestamptz);
		CREATE TABLE bulk_operations (id uuid PRIMARY KEY, org_id uuid, status text,
			processed_items int, success_count int, error_count int, errors jsonb, completed_at timestamptz);
		CREATE TABLE bulk_operation_items (operation_id uuid, entity_id uuid, org_id uuid,
			status text, error_message text, processed_at timestamptz);`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	org := uuid.NewString()
	groupID := uuid.NewString()
	member := uuid.NewString()
	stranger := uuid.NewString()
	opID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO bulk_operations (id, org_id, status) VALUES ($1,$2,'processing')`, opID, org); err != nil {
		t.Fatalf("seed operation: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1,$2,$3)`, member, groupID, org); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	params, _ := json.Marshal(map[string]string{"group_id": groupID})
	svc.executeBulkOperation(org, opID, "remove_from_group", []string{member, stranger}, params)

	if !revoked(t, revocationDB, member) {
		t.Error("a bulk group removal left the token asserting that group working")
	}
	if revoked(t, revocationDB, stranger) {
		t.Error("a user who was never in the group was logged out by its removal")
	}
}

// Adding is not removing. A bulk assign_role must not cut anybody: a grant that
// has not reached the token permits nothing it should not, so cutting there is
// a logout with no security gain — the asymmetry identity's lostRoles is built
// on.
func TestABulkRoleAssignmentCutsNobody(t *testing.T) {
	pool := openAdminSeverPool(t)
	general, revocationDB := openAdminSeverRedis(t)
	svc := newAdminSeverService(t, pool, general, revocationDB)
	ctx := context.Background()
	_ = general

	if _, err := pool.Exec(ctx, `
		CREATE TABLE user_roles (user_id uuid, role_id uuid, org_id uuid, assigned_at timestamptz,
			PRIMARY KEY (user_id, role_id));
		CREATE TABLE group_memberships (user_id uuid, group_id uuid, org_id uuid, joined_at timestamptz);
		CREATE TABLE bulk_operations (id uuid PRIMARY KEY, org_id uuid, status text,
			processed_items int, success_count int, error_count int, errors jsonb, completed_at timestamptz);
		CREATE TABLE bulk_operation_items (operation_id uuid, entity_id uuid, org_id uuid,
			status text, error_message text, processed_at timestamptz);`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	org := uuid.NewString()
	user := uuid.NewString()
	opID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO bulk_operations (id, org_id, status) VALUES ($1,$2,'processing')`, opID, org); err != nil {
		t.Fatalf("seed operation: %v", err)
	}

	params, _ := json.Marshal(map[string]string{"role_id": uuid.NewString()})
	svc.executeBulkOperation(org, opID, "assign_role", []string{user}, params)

	if revoked(t, revocationDB, user) {
		t.Error("granting a role ended the user's session; a grant not yet in the token permits nothing it should not")
	}
}

// THE CASE THAT SAYS WHY THE REVOKE IS AFTER THE COMMIT AND NOT INSIDE IT.
//
// Redis cannot join a Postgres transaction. If the marker were written beside
// the DELETE, a transaction that removed the role and then failed to commit
// would roll the removal back and leave the marker standing: the user still
// holds the role and has been logged out of it, and the log reads as though a
// certification had been enforced.
//
// A failing DELETE does not produce that — the handler returns before anything
// else runs — so this forces the only shape that does, with a DEFERRABLE
// constraint trigger that fires at COMMIT. The DELETE succeeds, the commit does
// not, and nothing must have been cut.
func TestACertificationWhoseCommitFailsCutsNothing(t *testing.T) {
	f, cleanup := newAttFixture(t)
	if f == nil {
		return
	}
	defer cleanup()
	_, revocationDB := attRedis(t, f)

	var roleID string
	if err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO roles (name, description, org_id) VALUES ('cert-commit-role', 'seeded', $1::uuid) RETURNING id::text`,
		f.orgA).Scan(&roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	holder := f.seedUser("cert-commit-holder", f.orgA, true)
	if _, err := f.db.Pool.Exec(f.ctx,
		`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		holder, roleID, f.orgA); err != nil {
		t.Fatalf("seed user_role: %v", err)
	}
	if _, err := f.db.Pool.Exec(f.ctx,
		`UPDATE attestation_items SET user_id = $1::uuid, resource_id = $2::uuid, resource_type = 'role' WHERE id = $3::uuid`,
		holder, roleID, f.itemA); err != nil {
		t.Fatalf("point the item at the role: %v", err)
	}

	if _, err := f.db.Pool.Exec(f.ctx, `
		CREATE FUNCTION att_refuse_at_commit() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refused at commit'; END; $$ LANGUAGE plpgsql;
		CREATE CONSTRAINT TRIGGER att_refuse AFTER DELETE ON user_roles
			DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION att_refuse_at_commit();`); err != nil {
		t.Fatalf("install the deferred refusal: %v", err)
	}
	defer func() {
		_, _ = f.db.Pool.Exec(f.ctx, `DROP TRIGGER IF EXISTS att_refuse ON user_roles`)
		_, _ = f.db.Pool.Exec(f.ctx, `DROP FUNCTION IF EXISTS att_refuse_at_commit()`)
	}()

	code := f.call(f.orgA, "PUT", "/attestation/campaigns/"+f.campaignA+"/items/"+f.itemA+"/decide",
		gin.Params{{Key: "id", Value: f.campaignA}, {Key: "itemId", Value: f.itemA}},
		map[string]string{"decision": "revoked", "comments": "not needed"},
		f.svc.handleDecideAttestationItem).Code
	if code != 500 {
		t.Fatalf("a decision whose commit failed answered %d, want 500", code)
	}

	var held int
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id = $1::uuid AND role_id = $2::uuid`,
		holder, roleID).Scan(&held); err != nil {
		t.Fatalf("count the role assignment: %v", err)
	}
	if held != 1 {
		t.Fatalf("the rollback should have left the assignment in place, found %d", held)
	}
	if revoked(t, revocationDB, holder) {
		t.Error("the commit failed and the user still holds the role, but their tokens were cut: " +
			"a marker written inside a transaction survives the rollback that undoes the revocation")
	}
}

// An application assignment is in no claim: access to an application is read
// from the table at the moment it is used, so the row being gone IS the
// enforcement, and cutting here would be a re-login that changes no decision.
// Asserted so that changing the decision has to be deliberate.
func TestARefusedApplicationCertificationCutsNothing(t *testing.T) {
	f, cleanup := newAttFixture(t)
	if f == nil {
		return
	}
	defer cleanup()
	_, revocationDB := attRedis(t, f)

	holder := f.seedUser("cert-app-holder", f.orgA, true)
	appID := uuid.NewString()
	if _, err := f.db.Pool.Exec(f.ctx,
		`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1::uuid,$2::uuid,$3::uuid)`,
		holder, appID, f.orgA); err != nil {
		t.Skipf("user_application_assignments not in this fixture's schema: %v", err)
	}
	if _, err := f.db.Pool.Exec(f.ctx,
		`UPDATE attestation_items SET user_id = $1::uuid, resource_id = $2::uuid, resource_type = 'application' WHERE id = $3::uuid`,
		holder, appID, f.itemA); err != nil {
		t.Fatalf("point the item at the application: %v", err)
	}

	code := f.call(f.orgA, "PUT", "/attestation/campaigns/"+f.campaignA+"/items/"+f.itemA+"/decide",
		gin.Params{{Key: "id", Value: f.campaignA}, {Key: "itemId", Value: f.itemA}},
		map[string]string{"decision": "revoked", "comments": "not needed"},
		f.svc.handleDecideAttestationItem).Code
	if code != 200 {
		t.Fatalf("revoke answered %d, want 200", code)
	}

	var held int
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT COUNT(*) FROM user_application_assignments WHERE user_id = $1::uuid`, holder).Scan(&held); err != nil {
		t.Fatalf("count: %v", err)
	}
	if held != 0 {
		t.Fatalf("the application assignment survived a revoked certification (%d rows)", held)
	}
	if revoked(t, revocationDB, holder) {
		t.Error("an application grant is in no claim; cutting the token changes no decision")
	}
}
