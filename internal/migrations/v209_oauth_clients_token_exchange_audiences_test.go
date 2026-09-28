package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// v209 adds the per-client list of audiences token exchange may issue for. The
// column arrives with no default: every existing client lists nothing, which
// is what makes an exchange for another audience refused until an
// administrator names it. A default here would be a list nobody chose.
func TestV209AddsTheAudienceListEmpty(t *testing.T) {
	up := oauthClientsTokenExchangeAudiencesUp
	require.Contains(t, up, "ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS token_exchange_audiences JSONB")
	require.NotContains(t, up, "DEFAULT", "an existing client must list no audience after the upgrade")
	require.NotContains(t, up, "UPDATE", "no row is rewritten under the row-level-security belt")
}

func TestV209DownRemovesTheColumn(t *testing.T) {
	require.Contains(t, oauthClientsTokenExchangeAudiencesDown, "ALTER TABLE oauth_clients DROP COLUMN IF EXISTS token_exchange_audiences")
}

func TestV209SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	var stmts []string
	for _, s := range m.splitSQL(oauthClientsTokenExchangeAudiencesUp) {
		if strings.TrimSpace(s) != "" {
			stmts = append(stmts, s)
		}
	}
	require.Len(t, stmts, 1, "the up migration is one statement")
}
