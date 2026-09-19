package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The v198 DDL carries decisions the drainer and the producers rely on without
// asking PostgreSQL about them; each is pinned against the source so that an
// edit has to argue with the sentence that explains it.
func TestV198PinsThePendingLogoutSchemaDecisions(t *testing.T) {
	up := backchannelLogoutPendingUp

	require.Contains(t, up, "CREATE TABLE IF NOT EXISTS backchannel_logout_pending")
	require.Contains(t, up, "CHECK (cardinality(client_ids) > 0)",
		"a capture naming no client is a row the drainer would mark delivered to nobody; the producer's SELECT filters it and the CHECK refuses it")
	require.Contains(t, up, "session_id   UUID NOT NULL",
		"the sid the relying party saw is the one claim the drainer cannot recover once the sessions row is deleted")
	require.Contains(t, up, "user_id      UUID NOT NULL",
		"sub is minted from the user id (pairwise or public); a deleted sessions row no longer carries it")
	require.NotContains(t, up, "REFERENCES sessions",
		"the row must outlive the session it is about: six producers DELETE the session in the same breath")
	require.NotContains(t, up, "REFERENCES organizations")
	require.Contains(t, up, "claimed_at",
		"without a claim column a drainer that dies mid-batch strands its rows unpublished forever")
	require.Contains(t, up, "delivered", "no relying party registered and every relying party refused look identical without the counts")
	require.Contains(t, up, "WHERE published_at IS NULL",
		"the backlog index must be partial: the hot query is the backlog, the table is the history")
	require.Contains(t, up, "ENABLE ROW LEVEL SECURITY")
	require.Contains(t, up, "FORCE  ROW LEVEL SECURITY")
	require.Contains(t, up, "app.bypass_rls", "the drainer reads every tenant under bypass; without the escape it drains nothing")
	require.Contains(t, up, "WITH CHECK", "a producer under one tenant must not be able to capture another tenant's session")
}

func TestV198DownRemovesTheTable(t *testing.T) {
	require.Contains(t, backchannelLogoutPendingDown, "DROP TABLE IF EXISTS backchannel_logout_pending")
}

func TestV198SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	var policy string
	for _, stmt := range m.splitSQL(backchannelLogoutPendingUp) {
		if strings.Contains(stmt, "CREATE POLICY") {
			policy = stmt
		}
	}
	require.NotEmpty(t, policy, "no intact CREATE POLICY statement")
	require.Contains(t, policy, "WITH CHECK", "the policy was split before its WITH CHECK")
}
