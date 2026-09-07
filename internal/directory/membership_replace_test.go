package directory

import (
	"context"
	"os"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/database"
)

// A directory sync must not report success over a group whose membership it
// failed to apply.
//
// syncMemberships and syncAzureADMemberships each ran, per group, a DELETE of
// the directory-managed rows followed by an INSERT per current member, with
// both errors discarded and no transaction around the pair. The dangerous
// ordering is DELETE fails, INSERTs succeed: a membership the directory REMOVED
// survives, and RunSync goes on to write sync_status = 'synced'. That is
// deprovisioning that did not happen, on exactly the schedule an operator
// relies on to take access away when somebody leaves a team -- and the console
// says the sync worked.
//
// The pair is one transaction now, and the caller is told which groups kept the
// membership they had.

// membershipTestDB uses the database named by OPENIDX_TEST_DATABASE_URL. This
// test is about what PostgreSQL does when a statement inside a transaction
// fails, so a fake would test the fake.
func membershipTestDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()
	url := os.Getenv("OPENIDX_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("OPENIDX_TEST_DATABASE_URL not set")
		return nil, func() {}
	}
	db, err := database.NewPostgres(url)
	if err != nil {
		t.Skipf("OPENIDX_TEST_DATABASE_URL set but unreachable: %v", err)
		return nil, func() {}
	}
	ctx := context.Background()
	for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			db.Close()
			t.Fatalf("reset test schema (%s): %v", stmt, err)
		}
	}
	return db, func() { db.Close() }
}

const (
	memOrg   = "00000000-0000-0000-0000-000000000060"
	memDir   = "11111111-0000-0000-0000-000000000060"
	memGroup = "22222222-0000-0000-0000-000000000060"
	memKeep  = "33333333-0000-0000-0000-000000000061"
	memGone  = "33333333-0000-0000-0000-000000000062"
)

func seedMembershipFixture(t *testing.T, ctx context.Context, db *database.PostgresDB) {
	t.Helper()
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE users (
			id UUID PRIMARY KEY,
			directory_id UUID,
			org_id UUID NOT NULL);
		CREATE TABLE group_memberships (
			user_id UUID NOT NULL,
			group_id UUID NOT NULL,
			org_id UUID NOT NULL,
			UNIQUE (user_id, group_id, org_id));
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	for _, u := range []string{memKeep, memGone} {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO users (id, directory_id, org_id) VALUES ($1, $2, $3)`, u, memDir, memOrg); err != nil {
			t.Fatalf("seed user: %v", err)
		}
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1, $2, $3)`,
			u, memGroup, memOrg); err != nil {
			t.Fatalf("seed membership: %v", err)
		}
	}
}

func membersOf(t *testing.T, ctx context.Context, db *database.PostgresDB) map[string]bool {
	t.Helper()
	rows, err := db.Pool.Query(ctx,
		`SELECT user_id FROM group_memberships WHERE group_id = $1 AND org_id = $2`, memGroup, memOrg)
	if err != nil {
		t.Fatalf("read memberships: %v", err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[id] = true
	}
	return got
}

func TestTheDirectorysMembershipReplacesTheOldOne(t *testing.T) {
	db, cleanup := membershipTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	seedMembershipFixture(t, ctx, db)
	e := &SyncEngine{db: db, logger: zaptest.NewLogger(t)}

	// The directory now lists only one of the two.
	if err := e.replaceDirectoryMemberships(ctx, memGroup, memDir, memOrg, []string{memKeep}); err != nil {
		t.Fatalf("applying a membership the directory gave must succeed: %v", err)
	}

	got := membersOf(t, ctx, db)
	if !got[memKeep] {
		t.Error("the member the directory still lists was dropped")
	}
	if got[memGone] {
		t.Error("the member the directory removed is still in the group; that is the access a leaver keeps")
	}
}

func TestAMembershipThatCannotBeAppliedLeavesTheOldOneAndIsReported(t *testing.T) {
	db, cleanup := membershipTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	seedMembershipFixture(t, ctx, db)

	// Refuse the INSERT half. The DELETE will already have run inside the
	// transaction, so this is exactly the state the old code could commit:
	// everyone removed, nobody added back.
	if _, err := db.Pool.Exec(ctx, `
		CREATE FUNCTION refuse_membership_insert() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refusing the membership insert'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER refuse_membership_insert BEFORE INSERT ON group_memberships
		FOR EACH ROW EXECUTE FUNCTION refuse_membership_insert();`); err != nil {
		t.Fatalf("install the failure: %v", err)
	}

	e := &SyncEngine{db: db, logger: zaptest.NewLogger(t)}
	if err := e.replaceDirectoryMemberships(ctx, memGroup, memDir, memOrg, []string{memKeep}); err == nil {
		t.Fatal("a membership that could not be written reported success; the sync would then record " +
			"sync_status = 'synced' over a group it did not sync")
	}

	got := membersOf(t, ctx, db)
	if !got[memKeep] || !got[memGone] {
		t.Errorf("a failed application changed the group: %v. The DELETE must roll back with the INSERT, or a "+
			"transient failure silently strips a group of everyone in it.", got)
	}
}
