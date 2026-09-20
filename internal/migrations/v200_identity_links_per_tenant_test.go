package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// v200 closes orgscope's needsScoping register. What the DDL must carry is the
// belt the other 200-odd scoped tables carry, and what it must NOT carry is a
// column DEFAULT or a change to the uniqueness key -- both decisions are in the
// file's comment and both are pinned here so a later edit cannot quietly undo
// them.
func TestV200BeltsBothLinkTables(t *testing.T) {
	up := identityLinksPerTenantUp
	for _, table := range []string{"user_identity_links", "social_account_links"} {
		t.Run(table, func(t *testing.T) {
			require.Contains(t, up, "ALTER TABLE "+table+" ", "the table must be touched at all")
			require.Regexp(t, `ALTER TABLE `+table+`\s+ADD COLUMN IF NOT EXISTS org_id UUID;`, up)
			require.Regexp(t, `ALTER TABLE `+table+`\s+ALTER COLUMN org_id SET NOT NULL;`, up)
			require.Contains(t, up, "FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE")
			require.Contains(t, up, "CREATE POLICY pol_"+table+"_org_scope ON "+table)
			require.Contains(t, up, "ALTER TABLE "+table+" ENABLE ROW LEVEL SECURITY")
			require.Contains(t, up, "ALTER TABLE "+table+" FORCE  ROW LEVEL SECURITY")
			require.Regexp(t, `GRANT SELECT, INSERT, UPDATE, DELETE ON `+table+`\s+TO openidx_app`, up)
		})
	}
}

// The provider is the exact backfill source: identity_providers.org_id has
// been NOT NULL-scoped since v155, so a link goes to the organization of the
// provider it was made through, before any inference from the user.
func TestV200BackfillsFromTheProviderFirst(t *testing.T) {
	up := identityLinksPerTenantUp
	for _, table := range []string{"user_identity_links", "social_account_links"} {
		provider := strings.Index(up, "UPDATE "+table+" l SET org_id = ip.org_id FROM identity_providers ip")
		user := strings.Index(up, "UPDATE "+table+" l SET org_id = u.org_id FROM users u")
		oldest := strings.Index(up, "UPDATE "+table+" SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1)")
		require.Greater(t, provider, -1, "%s: no provider backfill", table)
		require.Greater(t, user, provider, "%s: the user's organization must be the second source, not the first", table)
		require.Greater(t, oldest, user, "%s: the oldest organization is the last resort", table)
	}
}

func TestV200KeepsTheUniquenessKeyAndAddsNoDefault(t *testing.T) {
	up := identityLinksPerTenantUp
	require.NotContains(t, up, "DEFAULT",
		"a column DEFAULT would land every insert that forgets its tenant in one organization, silently")
	require.NotContains(t, up, "UNIQUE",
		"provider_id already names one tenant (identity_providers.org_id, v155); widening the key would give Down a statement that can fail on data for no gain")
	require.NotContains(t, up, "DROP CONSTRAINT IF EXISTS user_identity_links_provider_id_external_id_key")
}

func TestV200DownLiftsBothBeltsAndDropsTheColumns(t *testing.T) {
	down := identityLinksPerTenantDown
	for _, table := range []string{"user_identity_links", "social_account_links"} {
		require.Contains(t, down, "ALTER TABLE "+table+" NO FORCE ROW LEVEL SECURITY")
		require.Contains(t, down, "DROP POLICY IF EXISTS pol_"+table+"_org_scope ON "+table)
		require.Regexp(t, `ALTER TABLE `+table+`\s+DROP COLUMN IF EXISTS org_id;`, down)
	}
}

func TestV200SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	var stmts []string
	for _, s := range m.splitSQL(identityLinksPerTenantUp) {
		if strings.TrimSpace(s) != "" {
			stmts = append(stmts, s)
		}
	}
	require.Greater(t, len(stmts), 20, "the up migration is many statements, one per DDL step")
}
