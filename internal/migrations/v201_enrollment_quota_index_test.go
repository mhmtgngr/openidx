package migrations

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The quota counts (org_id, created_at > now - 1h) on every mint; v197's index
// on org_id alone answers that by scanning the tenant's whole history.
func TestV201IndexesTheQuotaPredicate(t *testing.T) {
	require.Contains(t, enrollmentQuotaIndexUp, "CREATE INDEX IF NOT EXISTS idx_agent_enrollment_tokens_org_created")
	require.Regexp(t, `ON agent_enrollment_tokens \(org_id, created_at\)`, enrollmentQuotaIndexUp,
		"the index must lead with org_id and range on created_at, in that order")
	require.Contains(t, enrollmentQuotaIndexDown, "DROP INDEX IF EXISTS idx_agent_enrollment_tokens_org_created")
	require.NotContains(t, enrollmentQuotaIndexUp, "ALTER TABLE", "v201 changes no data and no column")
}
