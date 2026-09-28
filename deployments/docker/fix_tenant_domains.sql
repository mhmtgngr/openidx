-- Create tenant_domains table if it doesn't exist (the shape migrations v38 and
-- v206 give it: one claim per organization and domain, one verified claim per
-- domain).
CREATE TABLE IF NOT EXISTS tenant_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    domain_type VARCHAR(50) NOT NULL DEFAULT 'subdomain',
    verified BOOLEAN NOT NULL DEFAULT false,
    verification_token VARCHAR(255),
    verified_at TIMESTAMP WITH TIME ZONE,
    ssl_enabled BOOLEAN DEFAULT false,
    primary_domain BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenant_domains_org ON tenant_domains(org_id);
CREATE INDEX IF NOT EXISTS idx_tenant_domains_domain ON tenant_domains(domain);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_domains_org_domain ON tenant_domains(org_id, domain);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_domains_verified_domain ON tenant_domains(domain) WHERE verified;

-- Add openidx.tdv.org domain mapping, verified by hand: the operator runs this
-- and controls the DNS. Every other organization's claim to the domain goes,
-- as a verification through the admin API removes them.
DELETE FROM tenant_domains
WHERE domain = 'openidx.tdv.org' AND org_id <> '01234567-89ab-cdef-0123-456789abcdef';

INSERT INTO tenant_domains (org_id, domain, domain_type, verified, verified_at, primary_domain)
VALUES (
    '01234567-89ab-cdef-0123-456789abcdef',
    'openidx.tdv.org',
    'custom',
    true,
    NOW(),
    true
)
ON CONFLICT (org_id, domain) DO UPDATE SET
    verified = EXCLUDED.verified,
    verified_at = COALESCE(tenant_domains.verified_at, EXCLUDED.verified_at),
    primary_domain = EXCLUDED.primary_domain,
    updated_at = NOW();
