// Package provisioning test helpers shared across the DB-backed test suite.
package provisioning

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/testsupport"
)

// setupTestDB creates a throwaway PostgreSQL container for DB-backed tests.
// It skips (not fails) when Docker is unavailable, matching the sibling
// suites in internal/access and internal/identity.
//
// OPENIDX_TEST_DATABASE_URL, when set, points the harness at an existing server
// instead of starting a container — for a workstation or sandbox that has
// Postgres but no Docker daemon. CI does not set it and keeps using throwaway
// containers. Same escape hatch internal/admin's harness grew in v138.
//
// The schema is DROPPED and rebuilt on that path, because these tests build
// their own subset schema (outboundSchema, inboundUsersSchema) with CREATE TABLE
// IF NOT EXISTS and seed fixed ids, so a second run against a persistent
// database would inherit the first run's rows. Run ONE package at a time against
// this variable.
func setupTestDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()

	ctx := context.Background()

	if url := os.Getenv("OPENIDX_TEST_DATABASE_URL"); url != "" {
		db, err := database.NewPostgres(url)
		if err != nil {
			t.Skipf("OPENIDX_TEST_DATABASE_URL set but unreachable: %v", err)
			return nil, func() {}
		}
		for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
			if _, err := db.Pool.Exec(ctx, stmt); err != nil {
				db.Close()
				t.Fatalf("reset test schema (%s): %v", stmt, err)
			}
		}
		return db, func() { db.Close() }
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
			WithStartupTimeout(30 * time.Second),
	}

	container := testsupport.RunOrSkip(t, req.Image, func() (testcontainers.Container, error) {
		return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
	})

	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container host: %v", err)
		return nil, func() {}
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container port: %v", err)
		return nil, func() {}
	}

	connString := "postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable"

	db, err := database.NewPostgres(connString)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to connect to test database: %v", err)
		return nil, func() {}
	}

	cleanup := func() {
		db.Close()
		container.Terminate(ctx)
	}

	return db, cleanup
}
