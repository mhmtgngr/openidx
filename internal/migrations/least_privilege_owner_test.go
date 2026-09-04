package migrations_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/testsupport"
	"github.com/openidx/openidx/internal/migrations"
)

// The bundled Helm data plane is the first deployment where migrations do NOT
// run as a superuser: the Bitnami PostgreSQL subchart creates `openidx` as a
// plain LOGIN role that owns the database, and the migration Job connects as
// that role. Two things break there and nowhere else, both invisible to
// `helm lint`, `helm template` and every static test in this package:
//
//  1. v53 creates the openidx_app runtime role, and a role without CREATEROLE
//     cannot create a role. The chart now pre-creates it from
//     postgresql.primary.initdb.scripts so v53's IF NOT EXISTS guard skips it.
//  2. The v37 RLS belt FORCEs row-level security so the table OWNER is subject
//     to it too, and the seeds (v84's OAuth client, v138's backfill) are
//     cross-org by definition. Migrator.applyMigration now issues
//     SET LOCAL app.bypass_rls = 'on' for the duration of each migration
//     transaction. Without it v84 fails with 42501.
//
// This test is that deployment, in miniature: a NOSUPERUSER NOCREATEROLE
// NOBYPASSRLS owner, its own database, and the full migration set.
func adminPoolOrSkip(t *testing.T) (*database.PostgresDB, string, func()) {
	t.Helper()
	ctx := context.Background()

	if url := os.Getenv("OPENIDX_TEST_DATABASE_URL"); url != "" {
		db, err := database.NewPostgres(url)
		if err != nil {
			t.Skipf("OPENIDX_TEST_DATABASE_URL set but unreachable: %v", err)
		}
		return db, url, func() { db.Close() }
	}

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}
	container := testsupport.RunOrSkip(t, req.Image, func() (testcontainers.Container, error) {
		return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req, Started: true,
		})
	})
	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("container port: %v", err)
	}
	url := fmt.Sprintf("postgres://test:test@%s:%s/testdb?sslmode=disable", host, port.Port())
	db, err := database.NewPostgres(url)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("connect: %v", err)
	}
	return db, url, func() { db.Close(); container.Terminate(context.Background()) }
}

func TestMigrationsRunAsLeastPrivilegedOwner(t *testing.T) {
	admin, adminURL, closeAdmin := adminPoolOrSkip(t)
	defer closeAdmin()

	ctx := context.Background()
	const (
		ownerRole = "openidx_lpo_owner"
		ownerPass = "lpo-owner-not-a-credential"
		ownerDB   = "openidx_lpo_test"
	)

	// Clean slate, then the deployment's shape: an owner that can do DDL on its
	// own database and nothing else.
	for _, stmt := range []string{
		"DROP DATABASE IF EXISTS " + ownerDB,
		"DROP ROLE IF EXISTS " + ownerRole,
		fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS", ownerRole, ownerPass),
		fmt.Sprintf("CREATE DATABASE %s OWNER %s", ownerDB, ownerRole),
	} {
		if _, err := admin.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	defer func() {
		_, _ = admin.Pool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+ownerDB)
		_, _ = admin.Pool.Exec(context.Background(), "DROP ROLE IF EXISTS "+ownerRole)
	}()

	ownerURL := swapUserAndDB(t, adminURL, ownerRole, ownerPass, ownerDB)
	owner, err := database.NewPostgres(ownerURL)
	if err != nil {
		t.Fatalf("connect as %s: %v", ownerRole, err)
	}
	defer owner.Close()

	// The privilege the kind install actually lacked. If this ever starts
	// succeeding the environment is no longer least-privileged and the rest of
	// the test proves nothing.
	if _, err := owner.Pool.Exec(ctx, "CREATE ROLE openidx_lpo_probe"); err == nil {
		_, _ = admin.Pool.Exec(ctx, "DROP ROLE IF EXISTS openidx_lpo_probe")
		t.Fatalf("%s could create a role; it was created NOCREATEROLE", ownerRole)
	}

	// What postgresql.primary.initdb.scripts does in the chart, and what an
	// operator on an external database has to do by hand.
	if _, err := admin.Pool.Exec(ctx, `DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openidx_app') THEN
    CREATE ROLE openidx_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;`); err != nil {
		t.Fatalf("pre-create openidx_app: %v", err)
	}

	if err := migrations.NewMigrator(owner.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrations must apply as a non-superuser owner: %v", err)
	}

	// The belt is real for this role: the same INSERT the seeds do is refused
	// without the GUC and allowed with it. This is what makes the fix above a
	// mechanism rather than a coincidence — remove the SET LOCAL from
	// applyMigration and the MigrateTo above fails at v84 with 42501.
	assertBeltAppliesTo(ctx, t, owner)
}

// swapUserAndDB rewrites the harness URL to connect as the least-privileged
// owner against its own database, keeping host, port and query parameters.
func swapUserAndDB(t *testing.T, base, user, pass, dbname string) string {
	t.Helper()
	u, err := parseURL(base)
	if err != nil {
		t.Fatalf("parse %q: %v", base, err)
	}
	u.User = userinfo(user, pass)
	u.Path = "/" + dbname
	return u.String()
}

func assertBeltAppliesTo(ctx context.Context, t *testing.T, db *database.PostgresDB) {
	t.Helper()

	const insert = `INSERT INTO oauth_clients (id, client_id, name, type, redirect_uris, grant_types, response_types, scopes)
VALUES (gen_random_uuid(), 'lpo-belt-probe', 'belt probe', 'public', '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb)`

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(ctx, insert); err == nil {
		_ = tx.Rollback(ctx)
		t.Fatal("insert succeeded with no app.org_id and no app.bypass_rls: the FORCE'd belt is not applying to the owner, so nothing here proves the migrator needs the bypass")
	}
	_ = tx.Rollback(ctx)

	tx, err = db.Pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL app.bypass_rls = 'on'`); err != nil {
		t.Fatalf("set bypass: %v", err)
	}
	if _, err := tx.Exec(ctx, insert); err != nil {
		t.Fatalf("insert with app.bypass_rls='on' must be allowed: %v", err)
	}
}

func parseURL(raw string) (*url.URL, error) { return url.Parse(raw) }

func userinfo(user, pass string) *url.Userinfo { return url.UserPassword(user, pass) }
