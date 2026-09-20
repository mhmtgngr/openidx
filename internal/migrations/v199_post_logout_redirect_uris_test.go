package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The v199 DDL is one statement, but it carries two decisions the logout path
// relies on: the column is nullable (an empty list is the fallback signal, not
// an error) and it is JSONB (the store marshals string slices that way).
func TestV199AddsTheRegisteredPostLogoutList(t *testing.T) {
	up := postLogoutRedirectURIsUp

	require.Contains(t, up, "ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS post_logout_redirect_uris JSONB")
	require.NotContains(t, up, "NOT NULL",
		"an unregistered client must be distinguishable from one that registered an empty list; NULL is that signal and the origin fallback reads it")
	require.NotContains(t, up, "DEFAULT",
		"a default would make every existing client look like it had registered something")
}

func TestV199DownRemovesTheColumn(t *testing.T) {
	require.Contains(t, postLogoutRedirectURIsDown, "DROP COLUMN IF EXISTS post_logout_redirect_uris")
}

func TestV199SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	var stmts []string
	for _, s := range m.splitSQL(postLogoutRedirectURIsUp) {
		if strings.TrimSpace(s) != "" {
			stmts = append(stmts, s)
		}
	}
	require.Len(t, stmts, 1, "the up migration is one statement")
}
