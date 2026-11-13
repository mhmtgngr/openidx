package credentials

import (
	"context"
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

const credTestOrg = "00000000-0000-0000-0000-000000000010"

func credTestDB(t *testing.T) *database.PostgresDB {
	t.Helper()
	ctx := context.Background()
	migrate := func(db *database.PostgresDB) {
		if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
			db.Close()
			t.Fatalf("migrate: %v", err)
		}
	}
	if url, ok := testsupport.ScratchDatabase(t); ok {
		db, err := database.NewPostgres(url)
		if err != nil {
			t.Fatalf("scratch database unreachable: %v", err)
		}
		migrate(db)
		t.Cleanup(func() { db.Close() })
		return db
	}
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env:          map[string]string{"POSTGRES_USER": "test", "POSTGRES_PASSWORD": "test", "POSTGRES_DB": "testdb"},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(60 * time.Second),
	}
	container := testsupport.RunOrSkip(t, req.Image, func() (testcontainers.Container, error) {
		return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
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
	migrate(db)
	t.Cleanup(func() { db.Close(); container.Terminate(context.Background()) })
	return db
}

// TestListPolicies_SecretFilter_OrgScoped: ?secret_id= narrows the list to one
// secret, and never returns another organization's policy for that secret id.
func TestListPolicies_SecretFilter_OrgScoped(t *testing.T) {
	db := credTestDB(t)
	bypass := orgctx.WithBypassRLS(context.Background())
	const otherOrg = "00000000-0000-0000-0000-0000000000aa"
	if _, err := db.Pool.Exec(bypass,
		`INSERT INTO organizations (id, name, slug) VALUES ($1, 'other', 'other-org') ON CONFLICT DO NOTHING`, otherOrg); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	newSecret := func(org, name string) string {
		var id string
		if err := db.Pool.QueryRow(bypass,
			`INSERT INTO vault_secrets (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, name).Scan(&id); err != nil {
			t.Fatalf("seed secret: %v", err)
		}
		return id
	}
	a, b := newSecret(credTestOrg, "a"), newSecret(credTestOrg, "b")
	svc := NewService(db, &fakeVault{}, []Rotator{NewGenerateOnlyRotator()}, nil, 24, zap.NewNop())
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: credTestOrg})
	for _, id := range []string{a, b} {
		if _, err := svc.CreatePolicy(ctx, PolicyInput{SecretID: id, ConnectorType: "generate_only", IntervalSeconds: 3600}); err != nil {
			t.Fatalf("create policy: %v", err)
		}
	}
	// Another org's policy on its own secret must never leak, even when the
	// caller asks for that secret id explicitly.
	foreign := newSecret(otherOrg, "f")
	if _, err := db.Pool.Exec(bypass,
		`INSERT INTO credential_rotation_policies (org_id, secret_id, connector_type, interval_seconds)
		 VALUES ($1, $2, 'generate_only', 60)`, otherOrg, foreign); err != nil {
		t.Fatalf("seed foreign policy: %v", err)
	}

	all, err := svc.ListPolicies(ctx, "")
	if err != nil || len(all) != 2 {
		t.Fatalf("list all = %d, %v; want 2", len(all), err)
	}
	got, err := svc.ListPolicies(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SecretID != a || got[0].OrgID != credTestOrg {
		t.Fatalf("filtered = %+v; want exactly org policy for %s", got, a)
	}
	leak, err := svc.ListPolicies(ctx, foreign)
	if err != nil || len(leak) != 0 {
		t.Fatalf("foreign secret filter = %d, %v; want 0", len(leak), err)
	}
}
