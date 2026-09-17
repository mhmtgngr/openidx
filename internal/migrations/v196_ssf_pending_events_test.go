package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The v196 DDL carries decisions that the drainer and the producers rely on
// without ever asking PostgreSQL about them. Each is pinned here, against the
// source, so that a later edit to the SQL has to argue with the sentence that
// explains it rather than silently change what the row means.
func TestV196PinsThePendingSignalSchemaDecisions(t *testing.T) {
	up := ssfPendingEventsUp

	require.Contains(t, up, "CREATE TABLE IF NOT EXISTS ssf_pending_events")
	require.Contains(t, up, "CHECK (event_type <> '')",
		"an empty event type would drain into EmitCAEPEvent as an event no stream asked for and vanish")
	require.Contains(t, up, "CHECK (subject_id <> '')",
		"a signal about nobody is a row the drainer marks published and no receiver can act on")
	require.NotContains(t, up, "REFERENCES organizations",
		"a signal outlives the org row that a delete cascade would take with it; the drainer scopes by org_id")
	require.Contains(t, up, "claimed_at",
		"without a claim column a drainer that dies mid-batch strands its rows unpublished forever")
	require.Contains(t, up, "streams_enqueued",
		"drained-into-zero-streams and lost look identical without this column")
	require.Contains(t, up, "WHERE published_at IS NULL",
		"the backlog index must be partial: the hot query is the backlog, the table is the history")
	require.Contains(t, up, "ENABLE ROW LEVEL SECURITY")
	require.Contains(t, up, "FORCE  ROW LEVEL SECURITY",
		"FORCE extends the policy to the owner; without it the belt is unobservable against the app role")
	require.Contains(t, up, "app.bypass_rls",
		"the drainer reads every tenant under bypass; without the escape it drains nothing")
	require.Contains(t, up, "WITH CHECK",
		"a producer under one tenant must not be able to write a signal about another")
}

func TestV196DownRemovesTheTable(t *testing.T) {
	require.Contains(t, ssfPendingEventsDown, "DROP TABLE IF EXISTS ssf_pending_events")
}

// The loader splits Up into statements; a policy with an embedded semicolon
// or a stray one in a comment would split wrongly and apply half a belt.
func TestV196SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	for name, sql := range map[string]string{"up": ssfPendingEventsUp, "down": ssfPendingEventsDown} {
		var policy string
		for _, stmt := range m.splitSQL(sql) {
			if strings.Contains(stmt, "CREATE POLICY") {
				policy = stmt
			}
		}
		if name == "down" {
			require.Empty(t, policy, "down should not create a policy")
			continue
		}
		require.NotEmpty(t, policy, "%s: no intact CREATE POLICY statement", name)
		require.Contains(t, policy, "WITH CHECK", "%s: the policy was split before its WITH CHECK", name)
	}
}
