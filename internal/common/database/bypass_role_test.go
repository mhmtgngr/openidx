package database

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// TestBypassRoleReplacesTheGUC is the end-to-end proof for #964, against a
// real server: once the bypass role exists and migration 231 has run, the
// application role cannot read another tenant's rows by setting
// app.bypass_rls itself, bypass-marked work still sees every tenant (through
// the bypass pool), and a DATABASE_BYPASS_URL that points at the application
// role is refused at startup.
func TestBypassRoleReplacesTheGUC(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed RLS test in -short mode")
	}
	ctx := context.Background()
	container := startPostgresOrSkip(t, ctx)
	defer func() { _ = container.Terminate(ctx) }()
	host, err := container.Host(ctx)
	if err != nil {
		t.Skipf("could not resolve container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		t.Skipf("could not resolve container port: %v", err)
	}
	const (
		orgA = "aaaaaaaa-0000-0000-0000-000000000001"
		orgB = "bbbbbbbb-0000-0000-0000-000000000002"
	)
	adminDSN := fmt.Sprintf("postgres://test:test@%s:%s/testdb?sslmode=disable", host, port.Port())
	admin, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	defer admin.Close()

	// The canonical policy as every migration wrote it, with the GUC clause.
	for _, sql := range []string{
		`CREATE TABLE tenant_rows (id BIGSERIAL PRIMARY KEY, org_id UUID NOT NULL, note TEXT NOT NULL)`,
		`CREATE POLICY pol_tenant_rows_org_scope ON tenant_rows
		   USING (current_setting('app.bypass_rls', true) = 'on'
		          OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
		   WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
		          OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)`,
		`ALTER TABLE tenant_rows ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE tenant_rows FORCE ROW LEVEL SECURITY`,
		`CREATE ROLE openidx_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'app_secret'`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_rows TO openidx_app`,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO openidx_app`,
		`CREATE ROLE openidx_bypass LOGIN NOSUPERUSER BYPASSRLS INHERIT IN ROLE openidx_app PASSWORD 'bypass_secret'`,
		`INSERT INTO tenant_rows (org_id, note) VALUES ('` + orgA + `', 'a'), ('` + orgB + `', 'b')`,
	} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatalf("setup %q: %v", sql[:40], err)
		}
	}

	// Migration 231, as the superuser owner (can_bypass holds).
	var up string
	for _, m := range migrations.All() {
		if m.Version == 231 {
			up = m.UpSQL
		}
	}
	if up == "" {
		t.Fatal("migration 231 is not registered")
	}
	if _, err := admin.Exec(ctx, up); err != nil {
		t.Fatalf("migration 231: %v", err)
	}
	var qual string
	if err := admin.QueryRow(ctx, `SELECT qual FROM pg_policies WHERE policyname = 'pol_tenant_rows_org_scope'`).Scan(&qual); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(qual, "bypass_rls") {
		t.Fatalf("policy still mentions the GUC after migration 231: %s", qual)
	}

	appDSN := fmt.Sprintf("postgres://openidx_app:app_secret@%s:%s/testdb?sslmode=disable", host, port.Port())
	bypassDSN := fmt.Sprintf("postgres://openidx_bypass:bypass_secret@%s:%s/testdb?sslmode=disable", host, port.Port())

	// 1. The injection: the application role sets the GUC itself.
	app, err := pgxpool.New(ctx, appDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	var seen int
	if err := app.QueryRow(ctx, `SELECT count(*) FROM (SELECT set_config('app.bypass_rls', 'on', false)) s, tenant_rows`).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	if seen != 0 {
		t.Fatalf("the application role read %d rows after setting app.bypass_rls itself; the GUC still lifts the boundary", seen)
	}

	// 2. A DSN that is not the bypass role is refused at startup.
	t.Setenv("DATABASE_BYPASS_URL", appDSN)
	if _, err := NewPostgres(appDSN); err == nil || !strings.Contains(err.Error(), "BYPASSRLS") {
		t.Fatalf("a bypass DSN on the application role was accepted: %v", err)
	}

	// 3. The real configuration: tenant calls stay scoped, bypass calls see all.
	t.Setenv("DATABASE_BYPASS_URL", bypassDSN)
	was := bypassRouting.Load()
	t.Cleanup(func() { bypassRouting.Store(was) })
	db, err := NewPostgres(appDSN)
	if err != nil {
		t.Fatalf("NewPostgres with bypass pool: %v", err)
	}
	defer db.Close()
	if !db.HasBypassPool() {
		t.Fatal("no bypass pool although DATABASE_BYPASS_URL is set")
	}
	if err := db.Pool.QueryRow(orgctx.With(ctx, orgctx.Org{ID: orgA}), `SELECT count(*) FROM tenant_rows`).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	if seen != 1 {
		t.Errorf("tenant A sees %d rows, want its own 1", seen)
	}
	if err := db.Pool.QueryRow(orgctx.WithBypassRLS(ctx), `SELECT count(*) FROM tenant_rows`).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	if seen != 2 {
		t.Errorf("bypass-marked work sees %d rows, want every tenant's 2", seen)
	}
	var who string
	if err := db.Pool.QueryRow(orgctx.WithBypassRLS(ctx), `SELECT current_user`).Scan(&who); err != nil {
		t.Fatal(err)
	}
	if who != "openidx_bypass" {
		t.Errorf("bypass-marked work ran as %s, want openidx_bypass", who)
	}
}
