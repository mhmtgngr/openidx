package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The v207 column carries the verifier's whole replay rule, and its default is
// what keeps every credential enrolled before the upgrade working: a NULL, or
// any default above a real step, would refuse every existing user's next code.
func TestV207AddsTheLastStepBelowEveryRealStep(t *testing.T) {
	require.Contains(t, totpLastStepUp,
		"ALTER TABLE mfa_totp ADD COLUMN IF NOT EXISTS last_step BIGINT NOT NULL DEFAULT 0",
		"the column must be NOT NULL with a default below every real step, so `last_step < $step` admits an existing credential's next code")
	require.NotContains(t, totpLastStepUp, "UPDATE", "existing rows take the default from the catalog, not from an UPDATE under the RLS belt")
}

func TestV207DownRemovesTheColumn(t *testing.T) {
	require.Contains(t, totpLastStepDown, "ALTER TABLE mfa_totp DROP COLUMN IF EXISTS last_step")
}

func TestV207SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	var stmts []string
	for _, s := range m.splitSQL(totpLastStepUp) {
		if strings.TrimSpace(s) != "" {
			stmts = append(stmts, s)
		}
	}
	require.Len(t, stmts, 1, "the up migration is one statement")
}
