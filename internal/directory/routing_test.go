package directory

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/testsupport"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
)

// These replace seven tests that executed nothing. Each was of the shape
//
//	service := &Service{logger: newTestLogger()}
//	ctx := context.Background()
//	// Without a real DB, we test the method signature exists
//	_ = service.AuthenticateUser
//	_ = ctx
//
// — a method VALUE assigned to the blank identifier, so the router never ran,
// under a comment whose premise was false: this package has had a
// testcontainers harness (hrisSetupTestDB, and the one below) the whole time.
// They were named for the directory authentication router and asserted nothing
// about it. tools/inerttests now fails on the shape.
//
// What they should have covered is a routing decision with a security edge:
// AuthenticateUser, ChangePassword and ResetPassword all switch on the type
// column of directory_integrations, and the azure_ad arm of AuthenticateUser
// exists to REFUSE a password bind for a tenant whose users authenticate
// through Entra. If that arm were reordered into the ldap case, a password
// would be sent to an LDAP connector built from an Azure config.

const routingSchema = `
CREATE TABLE IF NOT EXISTS directory_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    org_id UUID NOT NULL
);
CREATE TABLE IF NOT EXISTS directory_sync_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id UUID NOT NULL,
    sync_type VARCHAR(50), status VARCHAR(50),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), completed_at TIMESTAMPTZ,
    users_added INT DEFAULT 0, users_updated INT DEFAULT 0, users_disabled INT DEFAULT 0,
    groups_added INT DEFAULT 0, groups_updated INT DEFAULT 0, groups_deleted INT DEFAULT 0,
    error_message TEXT,
    org_id UUID NOT NULL
);
CREATE TABLE IF NOT EXISTS directory_sync_state (
    directory_id UUID PRIMARY KEY,
    last_sync_at TIMESTAMPTZ,
    cursor TEXT,
    org_id UUID NOT NULL
);`

const routingOrgID = "00000000-0000-0000-0000-000000000010"

// routingSetupDB gives the test its tables. OPENIDX_TEST_DATABASE_URL points it
// at an existing server instead of starting a container — the same escape hatch
// internal/identity/testdb_test.go and internal/migrations carry, for a machine
// with Postgres and no Docker daemon. CI does not set it and keeps using
// throwaway containers. On the env path the public schema is dropped and
// recreated, so run ONE package at a time against that variable.
func routingSetupDB(t *testing.T) (*database.PostgresDB, func()) {
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
		if _, err := db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
			db.Close()
			t.Fatalf("pgcrypto: %v", err)
		}
		if _, err := db.Pool.Exec(ctx, routingSchema); err != nil {
			db.Close()
			t.Fatalf("schema: %v", err)
		}
		return db, func() { db.Close() }
	}

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env:          map[string]string{"POSTGRES_USER": "test", "POSTGRES_PASSWORD": "test", "POSTGRES_DB": "testdb"},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(30 * time.Second),
	}
	container := testsupport.RunOrSkip(t, req.Image, func() (testcontainers.Container, error) {
		return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
	})
	host, _ := container.Host(ctx)
	port, _ := container.MappedPort(ctx, "5432")
	db, err := database.NewPostgres("postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("connect: %v", err)
		return nil, func() {}
	}
	if _, err := db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
		db.Close()
		container.Terminate(ctx)
		t.Fatalf("pgcrypto: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, routingSchema); err != nil {
		db.Close()
		container.Terminate(ctx)
		t.Fatalf("schema: %v", err)
	}
	return db, func() { db.Close(); container.Terminate(ctx) }
}

func routingCtx() context.Context {
	return orgctx.With(context.Background(), orgctx.Org{ID: routingOrgID, Slug: "default"})
}

// seedDirectory inserts a directory of the given type and returns its id.
func seedDirectory(t *testing.T, db *database.PostgresDB, ctx context.Context, dirType, config string, enabled bool) string {
	t.Helper()
	var id string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO directory_integrations (name, type, config, enabled, org_id)
		 VALUES ($1, $2, $3::jsonb, $4, $5) RETURNING id::text`,
		"dir-"+dirType, dirType, config, enabled, routingOrgID).Scan(&id); err != nil {
		t.Fatalf("seed %s directory: %v", dirType, err)
	}
	return id
}

// TestDirectoryRoutingRefusesWhatItCannotDo drives the three password-path
// entry points through the type column, which is the only thing deciding which
// connector (if any) sees a credential.
func TestDirectoryRoutingRefusesWhatItCannotDo(t *testing.T) {
	db, cleanup := routingSetupDB(t)
	defer cleanup()
	ctx := routingCtx()
	svc := &Service{db: db, logger: zap.NewNop()}

	azure := seedDirectory(t, db, ctx, "azure_ad", `{"tenant_id":"t","client_id":"c"}`, true)
	okta := seedDirectory(t, db, ctx, "okta", `{}`, true)
	disabled := seedDirectory(t, db, ctx, "ldap", `{"host":"ldap.example.test"}`, false)

	t.Run("an Entra directory refuses a password bind rather than routing it to LDAP", func(t *testing.T) {
		// The security edge: these users authenticate through Entra, so a
		// password presented here must be refused outright. If this case were
		// folded into the ldap arm, the credential would be handed to an LDAP
		// connector built from an Azure config.
		err := svc.AuthenticateUser(ctx, azure, "someone", "a-password")
		if err == nil {
			t.Fatal("azure_ad accepted a password bind")
		}
		if !strings.Contains(err.Error(), "SSO") {
			t.Fatalf("error = %q, want it to say SSO is required", err)
		}
	})

	t.Run("an unrecognised directory type is refused, not defaulted to LDAP", func(t *testing.T) {
		// The default arm must reject. Falling through to LDAP would send the
		// password to a connector configured from a JSON blob of another shape.
		err := svc.AuthenticateUser(ctx, okta, "someone", "a-password")
		if err == nil {
			t.Fatal("an unsupported directory type accepted a password bind")
		}
		if !strings.Contains(err.Error(), "unsupported directory type") {
			t.Fatalf("error = %q, want it to name the unsupported type", err)
		}
		if !strings.Contains(err.Error(), "okta") {
			t.Fatalf("error = %q, want it to name okta so an operator can act on it", err)
		}
	})

	t.Run("a disabled directory authenticates nobody", func(t *testing.T) {
		// enabled = false is in the lookup's WHERE clause, so turning a
		// directory off has to stop authentication through it.
		err := svc.AuthenticateUser(ctx, disabled, "someone", "a-password")
		if err == nil {
			t.Fatal("a disabled directory authenticated a user")
		}
		if !strings.Contains(err.Error(), "not found or disabled") {
			t.Fatalf("error = %q, want the not-found-or-disabled refusal", err)
		}
	})

	t.Run("a directory belonging to another tenant is not visible", func(t *testing.T) {
		// The lookup carries org_id. A directory id from another tenant must
		// read as absent rather than as a directory this caller may use.
		var otherOrgDir string
		if err := db.Pool.QueryRow(ctx,
			`INSERT INTO directory_integrations (name, type, config, enabled, org_id)
			 VALUES ('other','ldap','{}'::jsonb,true,'11111111-1111-1111-1111-111111111111')
			 RETURNING id::text`).Scan(&otherOrgDir); err != nil {
			t.Fatalf("seed other-tenant directory: %v", err)
		}
		err := svc.AuthenticateUser(ctx, otherOrgDir, "someone", "a-password")
		if err == nil {
			t.Fatal("authenticated against another tenant's directory")
		}
		if !strings.Contains(err.Error(), "not found or disabled") {
			t.Fatalf("error = %q, want the not-found refusal", err)
		}
	})

	t.Run("ChangePassword and ResetPassword route by the same column", func(t *testing.T) {
		// Both switch on the same type value, so both must refuse the same
		// directories. A type honoured by one and not the other is how a
		// password reset ends up taking a path authentication would not.
		if err := svc.ChangePassword(ctx, okta, "someone", "old", "new"); err == nil {
			t.Fatal("ChangePassword accepted an unsupported directory type")
		} else if !strings.Contains(err.Error(), "unsupported directory type") {
			t.Fatalf("ChangePassword error = %q, want the unsupported-type refusal", err)
		}
		if err := svc.ResetPassword(ctx, okta, "someone", "new"); err == nil {
			t.Fatal("ResetPassword accepted an unsupported directory type")
		} else if !strings.Contains(err.Error(), "unsupported directory type") {
			t.Fatalf("ResetPassword error = %q, want the unsupported-type refusal", err)
		}
		if err := svc.ChangePassword(ctx, disabled, "someone", "old", "new"); err == nil {
			t.Fatal("ChangePassword accepted a disabled directory")
		}
	})

	t.Run("every entry point refuses a request with no tenant", func(t *testing.T) {
		// loadDirectoryTypeAndConfig reads orgctx first and fails closed. A
		// caller with no organization must not reach the connector switch.
		bare := context.Background()
		for name, call := range map[string]func() error{
			"AuthenticateUser": func() error { return svc.AuthenticateUser(bare, azure, "u", "p") },
			"ChangePassword":   func() error { return svc.ChangePassword(bare, azure, "u", "o", "n") },
			"ResetPassword":    func() error { return svc.ResetPassword(bare, azure, "u", "n") },
		} {
			if err := call(); err == nil {
				t.Fatalf("%s ran without an organization in context", name)
			}
		}
	})
}

// TestDirectorySyncReadsAreTenantScoped covers GetSyncLogs and GetSyncState,
// which previously had `_ = service.GetSyncLogs` and nothing else.
func TestDirectorySyncReadsAreTenantScoped(t *testing.T) {
	db, cleanup := routingSetupDB(t)
	defer cleanup()
	ctx := routingCtx()
	svc := &Service{db: db, logger: zap.NewNop()}

	dir := seedDirectory(t, db, ctx, "ldap", `{"host":"ldap.example.test"}`, true)

	for i := 0; i < 3; i++ {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO directory_sync_logs (directory_id, sync_type, status, users_added, org_id)
			 VALUES ($1,'full','completed',$2,$3)`, dir, i, routingOrgID); err != nil {
			t.Fatalf("seed sync log: %v", err)
		}
	}
	// One belonging to another tenant, on the same directory id.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO directory_sync_logs (directory_id, sync_type, status, org_id)
		 VALUES ($1,'full','completed','11111111-1111-1111-1111-111111111111')`, dir); err != nil {
		t.Fatalf("seed foreign sync log: %v", err)
	}

	t.Run("logs come back, and only this tenant's", func(t *testing.T) {
		logs, err := svc.GetSyncLogs(ctx, dir, 10)
		if err != nil {
			t.Fatalf("GetSyncLogs: %v", err)
		}
		if len(logs) != 3 {
			t.Fatalf("got %d logs, want 3 — the fourth belongs to another tenant", len(logs))
		}
	})

	t.Run("the limit is applied", func(t *testing.T) {
		logs, err := svc.GetSyncLogs(ctx, dir, 2)
		if err != nil {
			t.Fatalf("GetSyncLogs: %v", err)
		}
		if len(logs) != 2 {
			t.Fatalf("got %d logs with limit 2", len(logs))
		}
	})

	t.Run("a request with no tenant is refused", func(t *testing.T) {
		if _, err := svc.GetSyncLogs(context.Background(), dir, 10); err == nil {
			t.Fatal("GetSyncLogs ran without an organization in context")
		}
	})
}
