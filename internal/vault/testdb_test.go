package vault

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/testsupport"
	"github.com/openidx/openidx/internal/migrations"
)

// The vault's own schema is spread over several migrations and carries FORCE
// RLS, so these tests migrate a real database rather than hand-rolling the
// tables: a test that builds its own approximation of vault_secrets can pass
// against a shape production does not have.
//
// TEST_POSTGRES_DSN (testsupport.PostgresDSN), when it names a role that may
// create databases, gives each call an empty scratch database of its own on
// that server (testsupport.ScratchDatabase) instead of starting a container --
// for a machine with Postgres and no Docker daemon. Several packages can share
// the server at once. Otherwise, as in CI, it starts a throwaway container.

// testOrg is the organization the migration set seeds.
const testOrg = "00000000-0000-0000-0000-000000000010"

func vaultTestDB(t *testing.T) *database.PostgresDB {
	t.Helper()
	ctx := context.Background()

	if url, ok := testsupport.ScratchDatabase(t); ok {
		db, err := database.NewPostgres(url)
		if err != nil {
			t.Fatalf("scratch database on %s unreachable: %v", testsupport.PostgresEnv, err)
		}
		if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
			db.Close()
			t.Fatalf("migrate: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		return db
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
	db, err := database.NewPostgres("postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("connect: %v", err)
	}
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		db.Close()
		container.Terminate(ctx)
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { db.Close(); container.Terminate(context.Background()) })
	return db
}

// noopAuditor records nothing; the audit path has its own tests.
type noopAuditor struct{}

func (noopAuditor) RecordEvent(context.Context, string, string, string, string, string, map[string]interface{}) error {
	return nil
}

func newVaultService(t *testing.T) (*Service, context.Context) {
	t.Helper()
	db := vaultTestDB(t)

	// A 32-byte KEK, the shape decodeKEK accepts.
	kek := base64.StdEncoding.EncodeToString([]byte("vault-test-kek-0123456789abcdef0"))
	ring, err := newKeyring("", 0, kek)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	svc, err := NewService(db, ring, noopAuditor{}, time.Minute, zap.NewNop())
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	return svc, orgctx.With(context.Background(), orgctx.Org{ID: testOrg})
}
