package migrations_test

import (
	"context"
	"fmt"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/migrations"
)

// TestVersionOnlyReads runs `oidx-migrate version`'s query as a role that can
// read but not create, the shape of the runtime role (openidx_app) a deploy's
// preflight has at hand. Version used to go through ensureSchemaTable, so that
// role got 42501 (permission denied for schema public) instead of a number.
//
//   - on a database with no ledger it reports 0 and creates nothing;
//   - on a database with a ledger it reports the highest applied version.
func TestVersionOnlyReads(t *testing.T) {
	admin, adminURL, closeAdmin := adminPoolOrSkip(t)
	defer closeAdmin()
	ctx := context.Background()

	const (
		readerRole = "openidx_ver_ro_reader"
		readerPass = "ver-ro-not-a-credential"
		dbName     = "openidx_ver_ro_test"
	)
	for _, stmt := range []string{
		"DROP DATABASE IF EXISTS " + dbName,
		"DROP ROLE IF EXISTS " + readerRole,
		fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS", readerRole, readerPass),
		"CREATE DATABASE " + dbName,
	} {
		if _, err := admin.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	defer func() {
		_, _ = admin.Pool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName)
		_, _ = admin.Pool.Exec(context.Background(), "DROP ROLE IF EXISTS "+readerRole)
	}()

	u, err := parseURL(adminURL)
	if err != nil {
		t.Fatalf("parse admin url: %v", err)
	}
	u.Path = "/" + dbName
	ownerOfDB, err := database.NewPostgres(u.String())
	if err != nil {
		t.Fatalf("connect to %s as admin: %v", dbName, err)
	}
	defer ownerOfDB.Close()
	// PostgreSQL 15+ already denies CREATE on public to PUBLIC; say it anyway
	// so the test means the same thing on any server version.
	if _, err := ownerOfDB.Pool.Exec(ctx, "REVOKE CREATE ON SCHEMA public FROM PUBLIC"); err != nil {
		t.Fatalf("revoke create: %v", err)
	}

	reader, err := database.NewPostgres(swapUserAndDB(t, adminURL, readerRole, readerPass, dbName))
	if err != nil {
		t.Fatalf("connect as %s: %v", readerRole, err)
	}
	defer reader.Close()
	m := migrations.NewMigrator(reader.Pool.Raw(), zap.NewNop())

	v, err := m.Version(ctx)
	if err != nil {
		t.Fatalf("version on an empty database as a read-only role: %v", err)
	}
	if v != 0 {
		t.Errorf("version on an empty database = %d, want 0", v)
	}
	var tables int
	if err := ownerOfDB.Pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables
		WHERE table_name IN ('schema_migrations', 'schema_migration_lock')`).Scan(&tables); err != nil {
		t.Fatalf("count ledger tables: %v", err)
	}
	if tables != 0 {
		t.Errorf("version created %d ledger table(s); it must only read", tables)
	}

	for _, stmt := range []string{
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL,
			description TEXT, applied_at TIMESTAMP WITH TIME ZONE NOT NULL, duration_ms INTEGER)`,
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (1, 'one', now()), (236, 'latest', now())`,
		"GRANT SELECT ON schema_migrations TO " + readerRole,
	} {
		if _, err := ownerOfDB.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	v, err = m.Version(ctx)
	if err != nil {
		t.Fatalf("version with a ledger as a read-only role: %v", err)
	}
	if v != 236 {
		t.Errorf("version = %d, want 236", v)
	}
}
