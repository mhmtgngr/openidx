package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// v211's shape: the function first, since the generated column calls it; the
// duplicates resolved before the unique index, which could not be built over
// them; and the index over enabled routes only. The database test in
// v211_proxy_route_host_db_test.go drives what each statement does.
func TestV211OrdersItsStatements(t *testing.T) {
	up := proxyRouteHostUp
	fn := strings.Index(up, "CREATE OR REPLACE FUNCTION proxy_route_host(url TEXT) RETURNS TEXT")
	col := strings.Index(up, "ADD COLUMN IF NOT EXISTS host TEXT GENERATED ALWAYS AS (proxy_route_host(from_url)) STORED")
	dedup := strings.Index(up, "UPDATE proxy_routes r SET enabled = false")
	idx := strings.Index(up, "CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_routes_enabled_host ON proxy_routes (host) WHERE enabled")
	for name, at := range map[string]int{"function": fn, "column": col, "duplicates": dedup, "index": idx} {
		require.GreaterOrEqual(t, at, 0, "the %s statement is missing", name)
	}
	require.Less(t, fn, col, "the generated column calls the function")
	require.Less(t, col, dedup, "the duplicates are found by the column")
	require.Less(t, dedup, idx, "the unique index cannot be built over duplicates")
	require.Contains(t, up, "IMMUTABLE", "a generated column may only call an immutable function")
}

func TestV211DownRemovesWhatUpAdded(t *testing.T) {
	down := proxyRouteHostDown
	for _, stmt := range []string{
		"DROP INDEX IF EXISTS idx_proxy_routes_enabled_host",
		"ALTER TABLE proxy_routes DROP COLUMN IF EXISTS host",
		"DROP FUNCTION IF EXISTS proxy_route_host(TEXT)",
	} {
		require.Contains(t, down, stmt)
	}
	require.Less(t, strings.Index(down, "DROP COLUMN"), strings.Index(down, "DROP FUNCTION"),
		"the column depends on the function")
}

// The function body is dollar-quoted across lines; splitSQL must hand it to
// the database as one statement.
func TestV211SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	var stmts []string
	for _, s := range m.splitSQL(proxyRouteHostUp) {
		if strings.TrimSpace(s) != "" {
			stmts = append(stmts, s)
		}
	}
	require.Len(t, stmts, 4, "function, column, duplicates, index")
	require.Contains(t, stmts[0], "$$\nSELECT")
	require.True(t, strings.HasSuffix(strings.TrimSpace(stmts[0]), "$$;"), "the function statement ends with its body")
}
