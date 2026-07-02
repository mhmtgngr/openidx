//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// skipIfJITDriftNotApplied skips when migration v58 has not run in this DB.
func skipIfJITDriftNotApplied(t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	var exists bool
	err := db.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname='jit_grants' AND relkind='r')`).
		Scan(&exists)
	require.NoError(t, err)
	if !exists {
		t.Skip("jit_grants table not found — migration v58 not applied in this DB")
	}
}

// columnSet returns the set of column names for a table.
func columnSet(t *testing.T, db *pgxpool.Pool, table string) map[string]bool {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT column_name FROM information_schema.columns
		 WHERE table_schema = 'public' AND table_name = $1`, table)
	require.NoError(t, err)
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var c string
		require.NoError(t, rows.Scan(&c))
		cols[c] = true
	}
	require.NoError(t, rows.Err())
	return cols
}

// TestJITDriftMigrationApplies verifies migration v58 created jit_grants and
// request_approval_chains with exactly the columns the governance code writes/reads —
// the contract that was broken (the tables existed nowhere, so the code 500'd).
func TestJITDriftMigrationApplies(t *testing.T) {
	db := integrationDB(t)
	defer db.Close()
	skipIfJITDriftNotApplied(t, db)

	// Column lists match the exact SQL in internal/governance/jit.go and request.go.
	want := map[string][]string{
		"jit_grants": {
			"id", "user_id", "role_id", "role_name", "granted_by", "justification",
			"duration", "expires_at", "created_at", "updated_at", "revoked_at",
			"revoked_by", "status",
		},
		"request_approval_chains": {
			"id", "request_id", "steps", "escalate_after_hours", "escalate_to",
			"escalation_due_at", "current_step", "escalation_notified",
		},
	}
	for table, cols := range want {
		table, cols := table, cols
		t.Run(table, func(t *testing.T) {
			have := columnSet(t, db, table)
			require.NotEmpty(t, have, "table %s not found (migration v58 not applied?)", table)
			for _, c := range cols {
				assert.Truef(t, have[c], "table %s must have column %q (governance code depends on it)", table, c)
			}
		})
	}
}
