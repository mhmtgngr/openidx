package migrations

// Migration v206 -- a tenant domain is verified by a DNS record, and an
// unverified claim to a domain blocks no one.
//
// A verified row in tenant_domains tells the public login-branding endpoint
// which organization's branding -- logo, texts, custom CSS -- the login page
// served at that host shows. Verification proved nothing: the verify route
// compared the token in the request with the one the domain list had just shown
// the same administrator, so an administrator of any organization could mark
// any host verified, the install's own login host included. The admin API now
// marks a claim verified only when the TXT record _openidx-challenge.<domain>
// holds openidx-domain-verification=<the claim's token>.
//
// UNIQUENESS MOVES TO VERIFIED CLAIMS. v38 declared domain UNIQUE across the
// install, verified or not, so the first organization to type a name held it
// and a squatter's unverified claim kept the domain's real owner from adding it
// at all. The rule now: an organization claims a domain once ((org_id, domain)
// unique); any number of organizations may hold an unverified claim to the same
// domain; at most one claim to a domain is verified (a partial unique index);
// and verifying a claim deletes the other organizations' unverified claims to
// that domain.
//
// EXISTING ROWS. A verified domain stays verified. A NULL verified is read as
// unverified, as every reader already read it, and the column becomes NOT NULL
// so the partial index's predicate means what it says. An unverified row with
// no token -- rows written by hand carry none -- is given one, so that every
// pending claim has a record its organization can publish. The token is
// gen_random_uuid()'s 122 random bits in hex, the length and alphabet of the
// ones the API issues; it binds a record to one claim and is published in DNS,
// so it needs to be unguessable only in the sense that no other claim may share
// it. Tokens a claim already has are kept.
//
// Down restores v38's install-wide UNIQUE on domain, which is the one statement
// that can fail: once two organizations have each claimed the same domain -- the
// point of this migration -- the constraint cannot be recreated and the rollback
// stops. Refusing beats deleting an organization's claim to make a rollback
// succeed. The tokens given here are left in place; v38's code shows them.

var tenantDomainDNSProofUp = `-- Migration 206: tenant domains are verified by DNS, and uniqueness is among verified claims.
ALTER TABLE tenant_domains DROP CONSTRAINT IF EXISTS tenant_domains_domain_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_domains_org_domain ON tenant_domains(org_id, domain);
UPDATE tenant_domains SET verified = false WHERE verified IS NULL;
ALTER TABLE tenant_domains ALTER COLUMN verified SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_domains_verified_domain ON tenant_domains(domain) WHERE verified;
UPDATE tenant_domains SET verification_token = replace(gen_random_uuid()::text, '-', '')
 WHERE NOT verified AND COALESCE(verification_token, '') = '';
`

var tenantDomainDNSProofDown = `-- Migration 206 down: one claim per domain across the install again.
DROP INDEX IF EXISTS idx_tenant_domains_verified_domain;
ALTER TABLE tenant_domains ALTER COLUMN verified DROP NOT NULL;
DROP INDEX IF EXISTS idx_tenant_domains_org_domain;
ALTER TABLE tenant_domains ADD CONSTRAINT tenant_domains_domain_key UNIQUE (domain);
`
