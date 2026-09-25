package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The v203 DDL carries decisions the sign-in relies on without asking
// PostgreSQL about them; each is pinned against the source so that an edit has
// to argue with the sentence that explains it.
func TestV203PinsTheGraceSchemaDecisions(t *testing.T) {
	up := mfaPolicyGraceUp

	require.Contains(t, up, "CREATE TABLE IF NOT EXISTS mfa_policy_grace")
	require.Contains(t, up, "PRIMARY KEY (policy_id, user_id)",
		"one window per user per policy: the sign-in's INSERT ... ON CONFLICT DO NOTHING relies on this key to record the first start and keep it")
	require.Contains(t, up, "REFERENCES mfa_policies(id) ON DELETE CASCADE",
		"a deleted policy's windows go with it")
	require.Contains(t, up, "REFERENCES users(id) ON DELETE CASCADE",
		"a deleted user's windows go with them")
	require.Contains(t, up, "started_at TIMESTAMPTZ NOT NULL DEFAULT NOW()")
	require.NotContains(t, up, "deadline",
		"the deadline is computed at sign-in from grace_period_hours, so raising the period extends every running window; a stored deadline would not move")
	require.Contains(t, up, "ENABLE ROW LEVEL SECURITY")
	require.Contains(t, up, "FORCE  ROW LEVEL SECURITY")
	require.Contains(t, up, "app.bypass_rls")
	require.Contains(t, up, "WITH CHECK", "a sign-in under one tenant must not record a window in another")
}

// Stored methods and grace periods were never enforced before this release.
// The upgrade clears them, so that no install starts a window, or refuses a
// sign-in a day later, that nobody chose.
func TestV203ClearsWhatWasNeverEnforced(t *testing.T) {
	up := mfaPolicyGraceUp
	require.Contains(t, up, "SET required_methods = '[]'::jsonb, grace_period_hours = 0")
	require.Contains(t, up, "ALTER TABLE mfa_policies ALTER COLUMN grace_period_hours SET DEFAULT 0",
		"the old default of 24 gave every policy a grace period its author never set")
	require.NotContains(t, up, "conditions =",
		"conditions are not enforced yet either, and the console still flags them; clearing them is not this migration's decision")
}

func TestV203DownRemovesTheTableAndRestoresTheDefault(t *testing.T) {
	require.Contains(t, mfaPolicyGraceDown, "DROP TABLE IF EXISTS mfa_policy_grace")
	require.Contains(t, mfaPolicyGraceDown, "ALTER TABLE mfa_policies ALTER COLUMN grace_period_hours SET DEFAULT 24")
}

func TestV203SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	var policy string
	for _, stmt := range m.splitSQL(mfaPolicyGraceUp) {
		if strings.Contains(stmt, "CREATE POLICY") {
			policy = stmt
		}
	}
	require.NotEmpty(t, policy, "no intact CREATE POLICY statement")
	require.Contains(t, policy, "WITH CHECK", "the policy was split before its WITH CHECK")
}
