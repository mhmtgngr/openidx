package identity

import (
	"context"
	"testing"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// An invitation is a single-use credential, and it was never spent.
//
// handleAcceptInvitation used to SELECT the invitation WHERE status = 'pending',
// create the account, and forty lines later run
//
//	s.db.Pool.Exec(ctx, "UPDATE user_invitations SET status = 'accepted' ...")
//
// with the error discarded. Two things follow. If that UPDATE failed, the
// invitation stayed pending and the token stayed usable -- a second POST with
// the same token made a second account, and nothing anywhere recorded that the
// first one had been made. And even had the error been checked, SELECT-then-
// UPDATE is a check-then-act: two requests arriving together both pass the
// SELECT before either writes.
//
// The fix is one statement that reads and burns at once. This test drives that
// statement directly, against a real database, because the property it is here
// for is a concurrency property of the SQL and not of the Go around it.

func TestAnInvitationTokenCanBeClaimedOnce(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const orgID = "00000000-0000-0000-0000-000000000050"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE user_invitations (
			id UUID PRIMARY KEY,
			email TEXT NOT NULL,
			token TEXT NOT NULL,
			roles TEXT[] NOT NULL DEFAULT '{}',
			groups TEXT[] NOT NULL DEFAULT '{}',
			status VARCHAR(20) NOT NULL,
			accepted_at TIMESTAMPTZ,
			expires_at TIMESTAMPTZ NOT NULL,
			org_id UUID NOT NULL);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	const (
		invID = "dddddddd-0000-0000-0000-000000000050"
		token = "an-invitation-token"
	)
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO user_invitations (id, email, token, roles, groups, status, expires_at, org_id)
		 VALUES ($1, 'new@example.com', $2, ARRAY['auditor'], ARRAY['finance'], 'pending', NOW() + INTERVAL '1 day', $3)`,
		invID, token, orgID); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}

	// The claim statement the handler runs, verbatim in shape.
	claim := func() (string, error) {
		var id, email string
		var roles, groups []string
		err := db.Pool.QueryRow(ctx,
			`UPDATE user_invitations SET status = 'accepted', accepted_at = NOW()
			 WHERE token = $1 AND org_id = $2 AND status = 'pending' AND expires_at > NOW()
			 RETURNING id, email, roles, groups`,
			token, orgID).Scan(&id, &email, &roles, &groups)
		return id, err
	}

	got, err := claim()
	if err != nil {
		t.Fatalf("the first acceptance of a valid invitation must succeed: %v", err)
	}
	if got != invID {
		t.Fatalf("claimed %q, want %q", got, invID)
	}

	if _, err := claim(); err == nil {
		t.Error("the same invitation token was claimed twice. A single-use credential that is never spent " +
			"lets one invitation create as many accounts as the holder cares to ask for.")
	}

	var status string
	var acceptedAt *string
	if err := db.Pool.QueryRow(ctx,
		`SELECT status, accepted_at::text FROM user_invitations WHERE id = $1 AND org_id = $2`,
		invID, orgID).Scan(&status, &acceptedAt); err != nil {
		t.Fatalf("read the invitation back: %v", err)
	}
	if status != "accepted" {
		t.Errorf("invitation status is %q after a successful acceptance, want \"accepted\"", status)
	}
	if acceptedAt == nil {
		t.Error("accepted_at is null after a successful acceptance; the record does not say when it was used")
	}
}

// An expired invitation must not be claimable, and the predicate that says so
// now lives on the write rather than on a separate read.
func TestAnExpiredInvitationCannotBeClaimed(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const orgID = "00000000-0000-0000-0000-000000000051"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE user_invitations (
			id UUID PRIMARY KEY,
			email TEXT NOT NULL,
			token TEXT NOT NULL,
			roles TEXT[] NOT NULL DEFAULT '{}',
			groups TEXT[] NOT NULL DEFAULT '{}',
			status VARCHAR(20) NOT NULL,
			accepted_at TIMESTAMPTZ,
			expires_at TIMESTAMPTZ NOT NULL,
			org_id UUID NOT NULL);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO user_invitations (id, email, token, status, expires_at, org_id)
		 VALUES ($1, 'late@example.com', 'stale-token', 'pending', NOW() - INTERVAL '1 hour', $2)`,
		"dddddddd-0000-0000-0000-000000000051", orgID); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}

	var id, email string
	var roles, groups []string
	err := db.Pool.QueryRow(ctx,
		`UPDATE user_invitations SET status = 'accepted', accepted_at = NOW()
		 WHERE token = $1 AND org_id = $2 AND status = 'pending' AND expires_at > NOW()
		 RETURNING id, email, roles, groups`,
		"stale-token", orgID).Scan(&id, &email, &roles, &groups)
	if err == nil {
		t.Error("an expired invitation was claimed; the expiry predicate did not move onto the claim")
	}

	var status string
	if err := db.Pool.QueryRow(ctx,
		`SELECT status FROM user_invitations WHERE token = 'stale-token' AND org_id = $1`, orgID).Scan(&status); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if status != "pending" {
		t.Errorf("a refused claim changed the row to %q; a failed acceptance must leave the invitation as it was", status)
	}
}

// The password and the grants are one promise: an account that exists with
// neither is not a partial success, it is a support ticket. They now share a
// transaction, so a failure in the middle leaves none of them.
func TestTheInvitedAccountGetsItsPasswordAndItsGrantsOrNeither(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const orgID = "00000000-0000-0000-0000-000000000052"
	const userID = "aaaaaaaa-0000-0000-0000-000000000052"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	// The DDL carries no parameters: pgx prepares any statement given args, and
	// a prepared statement cannot hold several commands.
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE users (
			id UUID PRIMARY KEY,
			password_hash TEXT,
			password_changed_at TIMESTAMPTZ,
			org_id UUID NOT NULL);
		CREATE TABLE roles (id UUID PRIMARY KEY, name TEXT NOT NULL, org_id UUID NOT NULL);
		CREATE TABLE groups (id UUID PRIMARY KEY, name TEXT NOT NULL, org_id UUID NOT NULL);
		CREATE TABLE user_roles (user_id UUID NOT NULL, role_id UUID NOT NULL, org_id UUID NOT NULL);
		CREATE TABLE group_memberships (user_id UUID NOT NULL, group_id UUID NOT NULL, org_id UUID NOT NULL);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	for _, seed := range []struct {
		q    string
		args []interface{}
	}{
		{`INSERT INTO users (id, org_id) VALUES ($1, $2)`, []interface{}{userID, orgID}},
		{`INSERT INTO roles (id, name, org_id) VALUES ('bbbbbbbb-0000-0000-0000-000000000052', 'auditor', $1)`, []interface{}{orgID}},
		{`INSERT INTO groups (id, name, org_id) VALUES ('cccccccc-0000-0000-0000-000000000052', 'finance', $1)`, []interface{}{orgID}},
	} {
		if _, err := db.Pool.Exec(ctx, seed.q, seed.args...); err != nil {
			t.Fatalf("seed (%s): %v", seed.q, err)
		}
	}

	s := &Service{db: db}

	if err := s.grantInvitedAccess(ctx, userID, orgID, "a-hash", []string{"auditor"}, []string{"finance"}); err != nil {
		t.Fatalf("the happy path must grant what the invitation named: %v", err)
	}
	assertCount(t, ctx, db, `SELECT COUNT(*) FROM user_roles WHERE user_id = $1`, userID, 1, "role")
	assertCount(t, ctx, db, `SELECT COUNT(*) FROM group_memberships WHERE user_id = $1`, userID, 1, "group membership")

	// Now refuse the group insert and require the role to be rolled back with it.
	if _, err := db.Pool.Exec(ctx, `
		DELETE FROM user_roles; DELETE FROM group_memberships;
		CREATE FUNCTION refuse_group() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refusing the group membership'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER refuse_group BEFORE INSERT ON group_memberships
		FOR EACH ROW EXECUTE FUNCTION refuse_group();`); err != nil {
		t.Fatalf("install the failure: %v", err)
	}

	if err := s.grantInvitedAccess(ctx, userID, orgID, "another-hash", []string{"auditor"}, []string{"finance"}); err == nil {
		t.Fatal("a group the invitation named could not be granted and the caller was told it worked")
	}
	assertCount(t, ctx, db, `SELECT COUNT(*) FROM user_roles WHERE user_id = $1`, userID, 0,
		"role granted while the group grant failed; the account holds half of what its invitation promised and the caller cannot tell which half")

	var hash *string
	if err := db.Pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, userID).Scan(&hash); err != nil {
		t.Fatalf("read the password back: %v", err)
	}
	if hash != nil && *hash == "another-hash" {
		t.Error("the password from the failed attempt was committed; the whole point of the transaction is that " +
			"a half-finished acceptance leaves an account that cannot be used rather than one that half works")
	}
}

// assertCount runs a COUNT and says, when it is wrong, what that means rather
// than only what it is.
func assertCount(t *testing.T, ctx context.Context, db *database.PostgresDB, q, arg string, want int, what string) {
	t.Helper()
	var got int
	if err := db.Pool.QueryRow(ctx, q, arg).Scan(&got); err != nil {
		t.Fatalf("count (%s): %v", what, err)
	}
	if got != want {
		t.Errorf("found %d row(s) where %d expected: %s", got, want, what)
	}
}
