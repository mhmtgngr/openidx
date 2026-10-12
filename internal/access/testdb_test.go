// Package access test helpers shared across the access test suite.
package access

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/testsupport"
	"github.com/openidx/openidx/internal/migrations"
)

// setupTestDB creates a throwaway PostgreSQL container for DB-backed tests.
//
// TEST_POSTGRES_DSN (testsupport.PostgresDSN), when it names a role that may
// create databases, gives each call an empty scratch database of its own on
// that server (testsupport.ScratchDatabase) instead of starting a container --
// for a machine with Postgres and no Docker daemon. Several packages can share
// the server at once. Otherwise, as in CI, it starts a throwaway container.
func setupTestDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()

	ctx := context.Background()

	if url, ok := testsupport.ScratchDatabase(t); ok {
		db, err := database.NewPostgres(url)
		if err != nil {
			t.Fatalf("scratch database on %s unreachable: %v", testsupport.PostgresEnv, err)
			return nil, func() {}
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

// addRouteHost gives a proxy_routes table a test built by hand what migration
// v211 gives the real one: the host column, the proxy_route_host() function
// that fills it, and the unique index over the enabled routes' hosts. It runs
// the migration's own SQL, so these fixtures read hosts as the product does.
func addRouteHost(ctx context.Context, t *testing.T, db *database.PostgresDB) {
	t.Helper()
	for _, m := range migrations.All() {
		if m.Version == 211 {
			if _, err := db.Pool.Exec(ctx, m.UpSQL); err != nil {
				t.Fatalf("apply migration v211 to the hand-built schema: %v", err)
			}
			return
		}
	}
	t.Fatal("migration v211 is not registered")
}
