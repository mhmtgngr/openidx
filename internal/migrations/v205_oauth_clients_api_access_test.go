package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The v205 DDL carries its whole decision in two statements: every client that
// exists when it runs keeps calling OpenIDX's APIs (the column arrives with
// DEFAULT true), and every client registered afterwards does not until it is
// allowed to (the default then becomes false). Reversing either is an outage
// or a hole, so both are pinned, and so is the order.
func TestV205KeepsExistingClientsAndClosesNewOnes(t *testing.T) {
	up := oauthClientsAPIAccessUp

	add := strings.Index(up, "ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS api_access BOOLEAN NOT NULL DEFAULT true")
	closeDefault := strings.Index(up, "ALTER TABLE oauth_clients ALTER COLUMN api_access SET DEFAULT false")
	require.GreaterOrEqual(t, add, 0, "the column must arrive with DEFAULT true, which is what fills the rows that exist")
	require.GreaterOrEqual(t, closeDefault, 0, "a client registered after the upgrade must default to no API access")
	require.Less(t, add, closeDefault, "the default can only be closed after the existing rows were filled")
	require.NotContains(t, up, "UPDATE", "the existing rows are filled by the column default, not by an UPDATE under the RLS belt")
}

func TestV205DownRemovesTheColumn(t *testing.T) {
	require.Contains(t, oauthClientsAPIAccessDown, "ALTER TABLE oauth_clients DROP COLUMN IF EXISTS api_access")
}

func TestV205SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	var stmts []string
	for _, s := range m.splitSQL(oauthClientsAPIAccessUp) {
		if strings.TrimSpace(s) != "" {
			stmts = append(stmts, s)
		}
	}
	require.Len(t, stmts, 2, "the up migration is two statements")
}
