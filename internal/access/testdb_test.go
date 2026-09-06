// Package access test helpers shared across the access test suite.
package access

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
//
// OPENIDX_TEST_DATABASE_URL, when set, points the harness at an existing
// server instead of starting a container — for a workstation or sandbox that
// has Postgres but no Docker daemon (the same escape hatch internal/admin,
// internal/identity and internal/vault carry). CI does not set it and keeps
// using throwaway containers.
//
// On that path the public schema is DROPPED and recreated: the tests in this
// package each build the tables they need and several seed fixed UUIDs, which
// against a persistent database would be a wall of duplicate-key failures on
// the second run. The reset is per call, so run ONE package at a time against
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
