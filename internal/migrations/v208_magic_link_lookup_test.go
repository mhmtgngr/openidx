package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The v208 column is what VerifyMagicLink finds a link by, and the index is
// what makes that one row rather than a scan.
func TestV208AddsAnIndexedLookupForMagicLinks(t *testing.T) {
	require.Contains(t, magicLinkLookupUp, "ALTER TABLE magic_links ADD COLUMN IF NOT EXISTS token_lookup VARCHAR(64)",
		"a SHA-256 digest, hex-encoded, is 64 characters")
	require.Contains(t, magicLinkLookupUp,
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_magic_links_token_lookup ON magic_links (token_lookup)",
		"the lookup must be indexed, and a token is minted once")
	require.NotContains(t, magicLinkLookupUp, "UPDATE", "links minted before the upgrade are not rewritten: they have no lookup and stop working")
	require.NotContains(t, magicLinkLookupUp, "NOT NULL", "links minted before the upgrade keep a NULL lookup")
}

func TestV208DownRemovesTheIndexAndTheColumn(t *testing.T) {
	require.Contains(t, magicLinkLookupDown, "DROP INDEX IF EXISTS idx_magic_links_token_lookup")
	require.Contains(t, magicLinkLookupDown, "ALTER TABLE magic_links DROP COLUMN IF EXISTS token_lookup")
}

func TestV208SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	var stmts []string
	for _, s := range m.splitSQL(magicLinkLookupUp) {
		if strings.TrimSpace(s) != "" {
			stmts = append(stmts, s)
		}
	}
	require.Len(t, stmts, 2, "the up migration is two statements")
}
