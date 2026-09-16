package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The v195 DDL carries four decisions, and each one is pinned HERE, against the
// migration's own text, rather than only against a database that has already
// been migrated.
//
// THAT DISTINCTION IS THE REASON THIS FILE EXISTS. celldir_test.go asserts the
// constraint by asking PostgreSQL to accept an empty cell_id and watching it
// refuse -- a real measurement, and one that says nothing about this migration:
// it runs against a database migrated before the test started, so deleting the
// CHECK from the SQL below leaves it green. Measured; that mutation survived
// until this file was written. A schema decision has two places it can be
// wrong, and a test against a live database only covers the second.
func TestV195PinsTheDirectorysSchemaDecisions(t *testing.T) {
	up := orgCellsUp

	// 1. cell_id cannot be empty. Downstream, cell.Misdirected reads an empty
	//    cell as "this token predates the claim" and SERVES the request, so a
	//    placement naming no cell is a tenant placed nowhere and refused by
	//    nobody.
	require.Contains(t, up, "CHECK (cell_id <> '')",
		"the CHECK on cell_id is gone; a placement with an empty cell reads downstream as no placement at all")

	// 2. NO foreign key to organizations. In a celled deployment the directory
	//    is global and organizations is per-cell, so the row that says "org X
	//    lives in us-1" is precisely a row about an org this cell does not
	//    have. A foreign key would make the table unable to record the only
	//    fact it exists for.
	require.NotContains(t, up, "REFERENCES organizations",
		"a foreign key to organizations makes the directory unable to name a tenant that lives in another cell")

	// 3. The belt, applied at creation. FORCE is the half that is easy to omit
	//    and the half that makes the policy apply to the table's owner.
	require.Contains(t, up, "ENABLE ROW LEVEL SECURITY")
	require.Contains(t, up, "FORCE  ROW LEVEL SECURITY",
		"without FORCE the policy does not apply to the owner, and the belt is decorative for the account that matters most")
	require.Contains(t, up, "app.bypass_rls",
		"the cross-tenant readers (edge resolver, placement tool) reach these rows by bypass; without the clause they cannot")

	// 4. One org, one home cell. A second row for the same tenant would make
	//    "where does this tenant live" a question with two answers, and the
	//    reader takes the first it is handed.
	require.Regexp(t, `org_id\s+UUID PRIMARY KEY`, up,
		"org_id must be the primary key; two placements for one tenant is a question with two answers")
}

// Down must remove the table rather than leave it belted and unreadable.
func TestV195DownRemovesTheTable(t *testing.T) {
	require.Contains(t, orgCellsDown, "DROP TABLE IF EXISTS org_cells")
}

// The DDL has to survive splitSQL as executable statements: the policy body
// spans lines and carries inner parentheses, and a shredded CREATE POLICY would
// apply a belt that is not the one written here.
func TestV195SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	for name, sql := range map[string]string{"up": orgCellsUp, "down": orgCellsDown} {
		var policy string
		for _, s := range m.splitSQL(sql) {
			if strings.Contains(s, "CREATE POLICY") {
				policy = s
			}
		}
		if name == "down" {
			require.Empty(t, policy, "down should not create a policy")
			continue
		}
		require.NotEmpty(t, policy, "%s: no intact CREATE POLICY statement", name)
		require.Contains(t, policy, "WITH CHECK",
			"%s: the policy was split between USING and WITH CHECK -- reads would be belted and writes would not", name)
	}
}
