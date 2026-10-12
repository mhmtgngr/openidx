package migrations_test

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV236DropsTheRetiredTempAccessTables migrates to 235 with a link and a
// use on record, applies 236, and rolls back:
//
//   - at 235 both tables exist and hold the seeded rows (the history 236 is
//     about to drop, which is why the release notes ask for an export);
//   - 236 drops both tables, and their policies and indexes with them;
//   - rolling back to 235 recreates both tables empty, with the same columns,
//     indexes and FORCE'd org policies they had before.
func TestV236DropsTheRetiredTempAccessTables(t *testing.T) {
	db, _, cleanup := adminPoolOrSkip(t)
	defer cleanup()
	ctx := context.Background()
	pool := db.Pool
	for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("reset schema (%s): %v", stmt, err)
		}
	}
	m := migrations.NewMigrator(pool.Raw(), zap.NewNop())
	if err := m.MigrateTo(ctx, 235); err != nil {
		t.Fatalf("migrate to 235: %v", err)
	}
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	// The shape both tables have at 235, as one comparable string per aspect.
	shape := func() map[string]string {
		t.Helper()
		return map[string]string{
			"columns": scalar(`SELECT COALESCE(string_agg(table_name || '.' || column_name || ':' || data_type || ':' || is_nullable
				|| ':' || COALESCE(column_default, ''), ',' ORDER BY table_name, ordinal_position), '')
				FROM information_schema.columns WHERE table_schema = 'public'
				 AND table_name IN ('temp_access_links', 'temp_access_usage')`),
			"indexes": scalar(`SELECT COALESCE(string_agg(indexdef, ',' ORDER BY indexname), '')
				FROM pg_indexes WHERE schemaname = 'public'
				 AND tablename IN ('temp_access_links', 'temp_access_usage')`),
			"constraints": scalar(`SELECT COALESCE(string_agg(conrelid::regclass::text || ':' || pg_get_constraintdef(oid), ',' ORDER BY 1), '')
				FROM pg_constraint WHERE conrelid IN (SELECT oid FROM pg_class
				 WHERE relname IN ('temp_access_links', 'temp_access_usage') AND relnamespace = 'public'::regnamespace)`),
			"policies": scalar(`SELECT COALESCE(string_agg(tablename || '.' || policyname, ',' ORDER BY tablename), '')
				FROM pg_policies WHERE schemaname = 'public'
				 AND tablename IN ('temp_access_links', 'temp_access_usage')`),
			"rls": scalar(`SELECT COALESCE(string_agg(relname || ':' || relrowsecurity::text || ':' || relforcerowsecurity::text, ',' ORDER BY relname), '')
				FROM pg_class WHERE relname IN ('temp_access_links', 'temp_access_usage')
				 AND relnamespace = 'public'::regnamespace`),
		}
	}
	before := shape()
	if before["policies"] != "temp_access_links.pol_temp_access_links_org_scope,temp_access_usage.pol_temp_access_usage_org_scope" {
		t.Fatalf("at 235 the tables' policies are %q; the test's premise is wrong", before["policies"])
	}

	org := scalar("SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1")
	link := scalar(`INSERT INTO temp_access_links (org_id, token, name, protocol, target_host, target_port, created_by, expires_at)
		VALUES ($1::uuid, 'v236-token', 'Old vendor link', 'ssh', 'db1.internal', 22, gen_random_uuid(), now() + interval '1 day')
		RETURNING id::text`, org)
	if _, err := pool.Exec(ctx, `INSERT INTO temp_access_usage (link_id, ip_address, org_id) VALUES ($1::uuid, '192.0.2.10', $2::uuid)`, link, org); err != nil {
		t.Fatalf("seed usage: %v", err)
	}

	if err := m.MigrateTo(ctx, 236); err != nil {
		t.Fatalf("migrate to 236: %v", err)
	}
	if got := scalar(`SELECT count(*)::text FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name IN ('temp_access_links', 'temp_access_usage')`); got != "0" {
		t.Errorf("after 236 %s temp access table(s) remain, want 0", got)
	}
	if got := scalar(`SELECT count(*)::text FROM pg_policies WHERE policyname LIKE 'pol_temp_access_%'`); got != "0" {
		t.Errorf("after 236 %s temp access polic(ies) remain, want 0", got)
	}
	if got := scalar(`SELECT count(*)::text FROM pg_class WHERE relname LIKE 'idx_temp_access%'`); got != "0" {
		t.Errorf("after 236 %s temp access index(es) remain, want 0", got)
	}
	// Applying the up again (a re-run on an install that dropped the tables by
	// hand) must not fail.
	for _, stmt := range []string{
		"DROP POLICY IF EXISTS pol_temp_access_usage_org_scope ON temp_access_usage",
		"DROP POLICY IF EXISTS pol_temp_access_links_org_scope ON temp_access_links",
		"DROP TABLE IF EXISTS temp_access_usage",
		"DROP TABLE IF EXISTS temp_access_links",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Errorf("re-running %q: %v", stmt, err)
		}
	}

	if err := m.RollbackTo(ctx, 235); err != nil {
		t.Fatalf("roll back to 235: %v", err)
	}
	after := shape()
	for aspect, want := range before {
		if after[aspect] != want {
			t.Errorf("after the rollback the tables' %s differ from 235's:\n got  %s\n want %s", aspect, after[aspect], want)
		}
	}
	if got := scalar(`SELECT count(*)::text FROM temp_access_links`); got != "0" {
		t.Errorf("the rollback recreated %s link row(s); the tables come back empty", got)
	}
	if got := scalar(`SELECT has_table_privilege('openidx_app', 'temp_access_usage', 'SELECT, INSERT, UPDATE, DELETE')::text`); got != "true" {
		t.Errorf("after the rollback openidx_app lacks DML on temp_access_usage")
	}
}
