package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// v212 records the terms a request was filed under. The per-row minimum
// arrives with DEFAULT 1, which is both the documented step semantics and the
// only reading under which every open request keeps advancing; the deadline
// arrives NULL so nothing already pending is expired by the upgrade itself.
func TestV212FillsExistingRowsWithOneAndNoDeadline(t *testing.T) {
	up := approvalPolicyFieldsUp
	require.Contains(t, up, "ADD COLUMN IF NOT EXISTS step_min_approvals INTEGER NOT NULL DEFAULT 1",
		"an open request's rows must read as needing one approval, the reading their approvers were shown")
	require.Contains(t, up, "ADD COLUMN IF NOT EXISTS answer_by TIMESTAMP WITH TIME ZONE",
		"a request filed before the deadline existed keeps waiting")
	require.NotContains(t, up, "answer_by TIMESTAMP WITH TIME ZONE NOT NULL", "the deadline is NULL for existing rows")
	require.NotContains(t, up, "UPDATE", "no row is rewritten under the RLS belt")
}

func TestV212DownRemovesBothColumns(t *testing.T) {
	require.Contains(t, approvalPolicyFieldsDown, "DROP COLUMN IF EXISTS answer_by")
	require.Contains(t, approvalPolicyFieldsDown, "DROP COLUMN IF EXISTS step_min_approvals")
}

func TestV212SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	var stmts []string
	for _, s := range m.splitSQL(approvalPolicyFieldsUp) {
		if strings.TrimSpace(s) != "" {
			stmts = append(stmts, s)
		}
	}
	require.Len(t, stmts, 3, "the up migration is three statements")
}
