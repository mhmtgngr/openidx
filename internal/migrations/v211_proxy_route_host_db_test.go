// Package migrations_test, not migrations, so that it can reach
// adminPoolOrSkip in least_privilege_owner_test.go.
package migrations_test

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV211GivesEachHostToOneEnabledRoute applies v211 over an install whose
// organizations already share hosts -- one taking another's host at a higher
// priority under another spelling of it, two routing the same host in the
// order they were created, one with a second route on its own host -- next to
// routes that name no host at all, and checks the host each route gets, which
// routes keep their host, that the index then refuses a second enabled route
// on a host from any organization, and that rolling back removes the column
// and leaves the disabled routes disabled.
func TestV211GivesEachHostToOneEnabledRoute(t *testing.T) {
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
	if err := m.MigrateTo(ctx, 205); err != nil {
		t.Fatalf("migrate to 205: %v", err)
	}

	var orgA string
	if err := pool.QueryRow(ctx,
		"SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1").Scan(&orgA); err != nil {
		t.Fatalf("read the oldest org: %v", err)
	}
	newOrg := func(slug string) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO organizations (name, slug, status) VALUES ($1, $1, 'active') RETURNING id::text`, slug).Scan(&id); err != nil {
			t.Fatalf("create organization %s: %v", slug, err)
		}
		return id
	}
	orgB, orgC := newOrg("v211-b"), newOrg("v211-c")

	// Every route is last updated on this day, so the ones v211 changes are
	// the ones whose updated_at moved.
	const untouched = "2026-01-01T00:00:00Z"
	names := map[string]string{}
	insert := func(org, name, fromURL string, priority int, created string, enabled bool) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO proxy_routes (org_id, name, from_url, to_url, priority, created_at, updated_at, enabled)
			VALUES ($1::uuid, $2, $3, 'http://10.0.0.9:8080', $4, $5::timestamptz, $6::timestamptz, $7)
			RETURNING id::text`, org, name, fromURL, priority, created, untouched, enabled).Scan(&id); err != nil {
			t.Fatalf("insert route %s: %v", name, err)
		}
		names[id] = name
		return id
	}

	// payroll: A's route came first; B's came later at a higher priority, on
	// another spelling of the host; A added a second route at priority 5.
	aPayroll := insert(orgA, "a-payroll", "https://payroll.example.test", 0, "2026-01-01T00:00:00Z", true)
	bTakeover := insert(orgB, "b-takeover", "https://PAYROLL.example.test:8443/", 100, "2026-02-01T00:00:00Z", true)
	aPayrollAdmin := insert(orgA, "a-payroll-admin", "https://payroll.example.test/admin", 5, "2026-03-01T00:00:00Z", true)
	// wiki: B first, C second without a scheme; C's oldest route is disabled
	// and claims nothing.
	bWiki := insert(orgB, "b-wiki", "http://wiki.example.test", 0, "2026-01-05T00:00:00Z", true)
	cWiki := insert(orgC, "c-wiki", "wiki.example.test:8080", 0, "2026-01-06T00:00:00Z", true)
	cWikiOld := insert(orgC, "c-wiki-old", "https://wiki.example.test", 0, "2025-12-01T00:00:00Z", false)
	// Routes that name no host keep their duplicates: a path, a TCP service.
	aPath := insert(orgA, "a-path", "/svc", 0, "2026-01-01T00:00:00Z", true)
	bPath := insert(orgB, "b-path", "/svc", 0, "2026-01-01T00:00:00Z", true)
	aTCP := insert(orgA, "a-tcp", "tcp://10.0.0.5:5432", 0, "2026-01-01T00:00:00Z", true)
	bTCP := insert(orgB, "b-tcp", "tcp://10.0.0.5:5432", 0, "2026-01-01T00:00:00Z", true)
	// The substring match: B's from_url contains A's host, and is on its own.
	aVictim := insert(orgA, "a-victim", "https://victim.example.test", 0, "2026-01-01T00:00:00Z", true)
	bSubstring := insert(orgB, "b-substring", "https://attacker.example.test/?victim.example.test", 10, "2026-01-01T00:00:00Z", true)

	if err := m.MigrateTo(ctx, 211); err != nil {
		t.Fatalf("migrate to 211: %v", err)
	}

	type state struct {
		host    string
		enabled bool
		touched bool
	}
	read := func(id string) state {
		t.Helper()
		var st state
		var host *string
		var updated time.Time
		if err := pool.QueryRow(ctx,
			`SELECT host, enabled, updated_at FROM proxy_routes WHERE id = $1::uuid`, id).Scan(&host, &st.enabled, &updated); err != nil {
			t.Fatalf("read route %s: %v", names[id], err)
		}
		if host != nil {
			st.host = *host
		}
		st.touched = updated.After(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
		return st
	}
	for _, want := range []struct {
		id      string
		host    string
		enabled bool
	}{
		// The first claimant keeps payroll, with its highest-priority route.
		{aPayroll, "payroll.example.test", false},
		{bTakeover, "payroll.example.test", false},
		{aPayrollAdmin, "payroll.example.test", true},
		{bWiki, "wiki.example.test", true},
		{cWiki, "wiki.example.test", false},
		{cWikiOld, "wiki.example.test", false},
		{aPath, "", true},
		{bPath, "", true},
		{aTCP, "", true},
		{bTCP, "", true},
		{aVictim, "victim.example.test", true},
		{bSubstring, "attacker.example.test", true},
	} {
		got := read(want.id)
		if got.host != want.host {
			t.Errorf("%s: host = %q, want %q", names[want.id], got.host, want.host)
		}
		if got.enabled != want.enabled {
			t.Errorf("%s: enabled = %v after v211, want %v", names[want.id], got.enabled, want.enabled)
		}
		disabledByV211 := !want.enabled && want.id != cWikiOld
		if got.touched != disabledByV211 {
			t.Errorf("%s: updated_at moved = %v, want %v (only the routes v211 disables are changed)",
				names[want.id], got.touched, disabledByV211)
		}
	}

	// The operator's query in sql_v211.go lists what v211 disabled, beside a
	// route that was disabled already.
	rows, err := pool.Query(ctx, `
		SELECT d.name FROM proxy_routes d JOIN proxy_routes e ON e.host = d.host AND e.enabled
		 WHERE NOT d.enabled`)
	if err != nil {
		t.Fatalf("list the disabled routes: %v", err)
	}
	var listed []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		listed = append(listed, n)
	}
	rows.Close()
	sort.Strings(listed)
	if want := []string{"a-payroll", "b-takeover", "c-wiki", "c-wiki-old"}; !equalStrings(listed, want) {
		t.Errorf("the operator's query lists %v, want %v", listed, want)
	}

	// From here on the index holds the host, whoever asks and however they
	// spell it.
	refused := func(what string, err error) {
		t.Helper()
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" || pgErr.ConstraintName != "idx_proxy_routes_enabled_host" {
			t.Errorf("%s: got %v, want the host index to refuse it", what, err)
		}
	}
	addRoute := func(org, name, fromURL string, enabled bool) (string, error) {
		var id string
		err := pool.QueryRow(ctx, `
			INSERT INTO proxy_routes (org_id, name, from_url, to_url, enabled)
			VALUES ($1::uuid, $2, $3, 'http://10.0.0.9:8080', $4) RETURNING id::text`, org, name, fromURL, enabled).Scan(&id)
		return id, err
	}
	_, err = addRoute(orgC, "c-payroll", "http://Payroll.Example.Test.:9/", true)
	refused("another organization's enabled route on a held host", err)
	_, err = addRoute(orgA, "a-payroll-other", "https://payroll.example.test/other", true)
	refused("a second enabled route of the holder's own organization", err)
	parked, err := addRoute(orgC, "c-payroll-parked", "https://payroll.example.test", false)
	if err != nil {
		t.Fatalf("a disabled route may share a held host: %v", err)
	}
	_, err = pool.Exec(ctx, `UPDATE proxy_routes SET enabled = true WHERE id = $1::uuid`, parked)
	refused("enabling a route on a held host", err)
	_, err = pool.Exec(ctx, `UPDATE proxy_routes SET from_url = 'https://wiki.example.test' WHERE id = $1::uuid`, aVictim)
	refused("moving an enabled route onto a held host", err)
	if _, err := addRoute(orgC, "c-fresh", "https://fresh.example.test", true); err != nil {
		t.Errorf("a route on a free host: %v", err)
	}
	if _, err := addRoute(orgC, "c-path", "/svc", true); err != nil {
		t.Errorf("a route naming no host is not held to one: %v", err)
	}

	if err := m.RollbackTo(ctx, 205); err != nil {
		t.Fatalf("roll back to 205: %v", err)
	}
	var leftovers int
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'proxy_routes' AND column_name = 'host')
		     + (SELECT COUNT(*) FROM pg_proc WHERE proname = 'proxy_route_host')
		     + (SELECT COUNT(*) FROM pg_indexes WHERE indexname = 'idx_proxy_routes_enabled_host')`).Scan(&leftovers); err != nil {
		t.Fatalf("look for what v211 added: %v", err)
	}
	if leftovers != 0 {
		t.Errorf("rolling back v211 left %d of its column, function and index behind", leftovers)
	}
	for _, id := range []string{aPayroll, bTakeover, cWiki} {
		var enabled bool
		if err := pool.QueryRow(ctx, `SELECT enabled FROM proxy_routes WHERE id = $1::uuid`, id).Scan(&enabled); err != nil {
			t.Fatal(err)
		}
		if enabled {
			t.Errorf("%s was enabled again by the rollback, which would hand its host back", names[id])
		}
	}
}

// TestV211ProxyRouteHostReadsAHost pins what proxy_route_host() makes of the
// from_url shapes the product writes and of the Host headers requests carry:
// the same function decides both sides of every lookup.
func TestV211ProxyRouteHostReadsAHost(t *testing.T) {
	db, _, cleanup := adminPoolOrSkip(t)
	defer cleanup()
	ctx := context.Background()
	for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("reset schema (%s): %v", stmt, err)
		}
	}
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, 211); err != nil {
		t.Fatalf("migrate to 211: %v", err)
	}
	for in, want := range map[string]string{
		// from_url, as the route API, app publishing, quick create and the
		// BrowZer handlers write it
		"https://app.example.test":                "app.example.test",
		"https://App.Example.TEST/":               "app.example.test",
		"http://app.example.test:8080/path?q=1#f": "app.example.test",
		"HTTPS://APP.EXAMPLE.TEST":                "app.example.test",
		"https://user:pass@app.example.test/p":    "app.example.test",
		"http://a@b@app.example.test/":            "app.example.test",
		"https://app.example.test@evil.test/":     "evil.test",
		"https://app.example.test./":              "app.example.test",
		"http://[::1]:8080/":                      "::1",
		"https://attacker.test/?app.example.test": "attacker.test",
		"app.example.test":                        "app.example.test",
		"app.example.test/landing":                "app.example.test",
		// Host headers
		"app.example.test:8443": "app.example.test",
		"APP.example.test":      "app.example.test",
		"app.example.test.":     "app.example.test",
		"[::1]:8080":            "::1",
		"localhost:8007":        "localhost",
		// no host
		"":                    "",
		"/service-name":       "",
		"https://":            "",
		"https:///path":       "",
		"https://:8080/":      "",
		"tcp://10.0.0.5:5432": "",
		"ssh://jump.test:22":  "",
		"ziti://service":      "",
		"https:/app.test":     "",
		"a.test, b.test":      "",
	} {
		var got *string
		if err := db.Pool.QueryRow(ctx, `SELECT proxy_route_host($1)`, in).Scan(&got); err != nil {
			t.Fatalf("proxy_route_host(%q): %v", in, err)
		}
		gotS := ""
		if got != nil {
			gotS = *got
		}
		if gotS != want {
			t.Errorf("proxy_route_host(%q) = %q, want %q", in, gotS, want)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
