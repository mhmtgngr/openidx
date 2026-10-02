package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// v213 links a brokered route to the PAM entry that now gates its launch. The
// backfill copies the connection record and invents no grant: a connect grant
// is what the route path never asked for, and it is what an administrator
// gives from now on.
func TestV213LinksEntriesToRoutesAndInventsNoGrant(t *testing.T) {
	up := pamEntriesProxyRouteUp
	require.Contains(t, up, "ADD COLUMN IF NOT EXISTS proxy_route_id UUID REFERENCES proxy_routes(id) ON DELETE CASCADE",
		"an entry standing for a route goes with the route, as its connection record does")
	require.Contains(t, up, "CREATE UNIQUE INDEX IF NOT EXISTS idx_pam_entries_proxy_route ON pam_entries(proxy_route_id) WHERE proxy_route_id IS NOT NULL",
		"one entry per route, and entries that stand for no route are not counted")
	require.Contains(t, up, "INSERT INTO pam_entries", "every existing brokered connection gets its entry")
	require.Contains(t, up, "NOT EXISTS (SELECT 1 FROM pam_entries pe WHERE pe.proxy_route_id = gc.route_id)",
		"the backfill is idempotent")
	require.NotContains(t, up, "pam_entry_grants", "no grant is invented for anyone")
	require.NotContains(t, up, "UPDATE ", "no existing row is rewritten")
}

func TestV213DownUnlinksAndKeepsTheEntries(t *testing.T) {
	require.Contains(t, pamEntriesProxyRouteDown, "DROP INDEX IF EXISTS idx_pam_entries_proxy_route")
	require.Contains(t, pamEntriesProxyRouteDown, "ALTER TABLE pam_entries DROP COLUMN IF EXISTS proxy_route_id")
	require.NotContains(t, pamEntriesProxyRouteDown, "DELETE", "the entries made are entries an administrator could have made")
}

func TestV213SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	var stmts []string
	for _, s := range m.splitSQL(pamEntriesProxyRouteUp) {
		if strings.TrimSpace(s) != "" {
			stmts = append(stmts, s)
		}
	}
	require.Len(t, stmts, 3, "the up migration is three statements")
}
