package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// v206 moves tenant_domains' uniqueness from every claim to verified claims,
// and gives a token to a pending claim that has none. Undoing any part of it
// either lets a squatter's unverified claim block a domain's owner again, lets
// two organizations hold one domain verified, or leaves a pending claim no
// record can verify, so each part is pinned.
func TestV206UniquenessIsAmongVerifiedClaims(t *testing.T) {
	up := tenantDomainDNSProofUp
	require.Contains(t, up, "ALTER TABLE tenant_domains DROP CONSTRAINT IF EXISTS tenant_domains_domain_key",
		"v38's install-wide UNIQUE is what let an unverified claim block the domain's owner")
	require.Contains(t, up, "CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_domains_org_domain ON tenant_domains(org_id, domain)",
		"an organization claims a domain once")
	require.Contains(t, up, "CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_domains_verified_domain ON tenant_domains(domain) WHERE verified",
		"at most one claim to a domain is verified")
	require.Less(t, strings.Index(up, "ALTER COLUMN verified SET NOT NULL"), strings.Index(up, "idx_tenant_domains_verified_domain"),
		"the partial index reads verified after NULL has been ruled out")
}

func TestV206GivesEveryPendingClaimAToken(t *testing.T) {
	require.Contains(t, tenantDomainDNSProofUp,
		"UPDATE tenant_domains SET verification_token = replace(gen_random_uuid()::text, '-', '')\n WHERE NOT verified AND COALESCE(verification_token, '') = ''",
		"only pending claims without a token get one; verified rows and existing tokens are left alone")
}

func TestV206DownRestoresOneClaimPerDomain(t *testing.T) {
	down := tenantDomainDNSProofDown
	require.Contains(t, down, "DROP INDEX IF EXISTS idx_tenant_domains_verified_domain")
	require.Contains(t, down, "DROP INDEX IF EXISTS idx_tenant_domains_org_domain")
	require.Contains(t, down, "ALTER TABLE tenant_domains ADD CONSTRAINT tenant_domains_domain_key UNIQUE (domain)")
	require.NotContains(t, down, "DELETE", "a rollback refuses rather than deleting a claim to make the UNIQUE hold")
}

func TestV206SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	count := func(sql string) int {
		n := 0
		for _, s := range m.splitSQL(sql) {
			if strings.TrimSpace(s) != "" {
				n++
			}
		}
		return n
	}
	require.Equal(t, 6, count(tenantDomainDNSProofUp), "the up migration is six statements")
	require.Equal(t, 4, count(tenantDomainDNSProofDown), "the down migration is four statements")
}
