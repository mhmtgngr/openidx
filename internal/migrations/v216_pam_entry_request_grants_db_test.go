// Package migrations_test, not migrations, so that it can reach
// adminPoolOrSkip in least_privilege_owner_test.go.
package migrations_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV216KeepsARequestsGrantBesideAStandingOne applies v216 and checks the
// split key both ways under raw SQL: a request's connect grant stands beside
// the user's standing grant on the same entry; a second standing grant for the
// same principal and a second grant for the same request are refused; the
// administrator's upsert still finds the standing row; deleting the request
// removes its grant. Rolling back deletes the request-made grants and restores
// the old one-grant-per-principal constraint.
func TestV216KeepsARequestsGrantBesideAStandingOne(t *testing.T) {
	db, _, cleanup := adminPoolOrSkip(t)
	defer cleanup()
	ctx := context.Background()
	pool := db.Pool
	for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("reset schema (%s): %v", stmt, err)
		}
	}
	m := migrations.NewMigrator(pool.Raw(), zap.NewNop())
	if err := m.MigrateTo(ctx, 216); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	exec := func(q string, args ...interface{}) error {
		_, err := pool.Exec(ctx, q, args...)
		return err
	}
	violates := func(err error, constraint string) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == constraint
	}
	org := scalar("SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1")
	user := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1::uuid, 'v216-user', 'u@example.test') RETURNING id::text`, org)
	entry := scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port)
		VALUES ($1::uuid, 'v216 host', 'ssh', 'host.example.test', 22) RETURNING id::text`, org)
	newRequest := func() string {
		return scalar(`INSERT INTO access_requests (requester_id, resource_type, resource_id, resource_name, status, org_id)
			VALUES ($1::uuid, 'pam_entry', $2::uuid, 'v216 host', 'fulfilled', $3::uuid) RETURNING id::text`, user, entry, org)
	}
	standing := `INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
		VALUES ($1::uuid, $2::uuid, 'user', $3, $4)`
	requestGrant := `INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions, expires_at, request_id)
		VALUES ($1::uuid, $2::uuid, 'user', $3, '{connect}', NOW() + interval '4 hours', $4::uuid)`

	if err := exec(standing, org, entry, user, []string{"view"}); err != nil {
		t.Fatalf("a standing grant: %v", err)
	}
	req := newRequest()
	if err := exec(requestGrant, org, entry, user, req); err != nil {
		t.Fatalf("a request's grant beside the standing one: %v", err)
	}
	if err := exec(standing, org, entry, user, []string{"connect"}); !violates(err, "pam_entry_grants_standing_key") {
		t.Errorf("a second standing grant for the same principal: %v, want pam_entry_grants_standing_key", err)
	}
	if err := exec(requestGrant, org, entry, user, req); !violates(err, "pam_entry_grants_request_key") {
		t.Errorf("a second grant for the same request: %v, want pam_entry_grants_request_key", err)
	}

	// The administrator's upsert (internal/access handlePamAddEntryGrant) finds
	// the standing row and leaves the request's alone.
	if err := exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
		VALUES ($1::uuid, $2::uuid, 'user', $3, '{view,reveal}')
		ON CONFLICT (entry_id, principal_type, principal_id) WHERE request_id IS NULL
		DO UPDATE SET actions = EXCLUDED.actions`, org, entry, user); err != nil {
		t.Fatalf("the administrator's upsert: %v", err)
	}
	if got := scalar(`SELECT array_to_string(actions, ',') FROM pam_entry_grants WHERE entry_id = $1::uuid AND request_id IS NULL`, entry); got != "view,reveal" {
		t.Errorf("the standing grant after the upsert: %s, want view,reveal", got)
	}
	if got := scalar(`SELECT array_to_string(actions, ',') FROM pam_entry_grants WHERE request_id = $1::uuid`, req); got != "connect" {
		t.Errorf("the upsert changed the request's grant to %s", got)
	}

	if err := exec(`DELETE FROM access_requests WHERE id = $1::uuid`, req); err != nil {
		t.Fatal(err)
	}
	if n := scalar(`SELECT count(*)::text FROM pam_entry_grants WHERE entry_id = $1::uuid`, entry); n != "1" {
		t.Errorf("after the request was deleted %s grant(s) remain, want only the standing one", n)
	}

	if err := exec(requestGrant, org, entry, user, newRequest()); err != nil {
		t.Fatal(err)
	}
	if err := m.RollbackTo(ctx, 215); err != nil {
		t.Fatalf("roll back: %v", err)
	}
	if n := scalar(`SELECT count(*)::text FROM pam_entry_grants WHERE entry_id = $1::uuid`, entry); n != "1" {
		t.Errorf("after rollback %s grant(s) remain, want the standing one only", n)
	}
	if err := exec(standing, org, entry, user, []string{"connect"}); !violates(err, "pam_entry_grants_entry_id_principal_type_principal_id_key") {
		t.Errorf("after rollback a second grant for the principal: %v, want the old constraint", err)
	}
}
