package appaccess

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/testsupport"
)

// setupTestDB starts a throwaway Postgres and creates only the tables this
// package reads. It skips the calling test cleanly when no container runtime
// is reachable — via testsupport.RunOrSkip, which recovers the panic that
// testcontainers-go raises in that case (see
// internal/common/testsupport/container.go) — so the suite stays green on
// machines without Docker, the same contract as
// internal/portal/device_org_scope_test.go:20.
func setupTestDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(60 * time.Second),
	}
	container := testsupport.RunOrSkip(t, req.Image, func() (testcontainers.Container, error) {
		return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
	})

	host, _ := container.Host(ctx)
	port, _ := container.MappedPort(ctx, "5432")
	dsn := fmt.Sprintf("postgres://test:test@%s:%s/testdb?sslmode=disable", host, port.Port())

	db, err := database.NewPostgres(dsn)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("connect: %v", err)
	}

	schema := []string{
		`CREATE TABLE applications (id UUID PRIMARY KEY, name VARCHAR(255), enabled BOOLEAN,
		    route_id UUID, require_assignment BOOLEAN NOT NULL DEFAULT false, org_id UUID)`,
		`CREATE TABLE user_application_assignments (user_id UUID, application_id UUID, org_id UUID)`,
		`CREATE TABLE group_application_assignments (group_id UUID, application_id UUID, org_id UUID)`,
		`CREATE TABLE group_memberships (user_id UUID, group_id UUID, org_id UUID)`,
	}
	for _, stmt := range schema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}

	return db, func() {
		db.Close()
		_ = container.Terminate(ctx)
	}
}
