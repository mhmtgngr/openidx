-- Create tenant_domains table if it doesn't exist
CREATE TABLE IF NOT EXISTS tenant_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL UNIQUE,
    domain_type VARCHAR(50) NOT NULL DEFAULT 'subdomain',
    verified BOOLEAN DEFAULT false,
    verification_token VARCHAR(255),
    verified_at TIMESTAMP WITH TIME ZONE,
    ssl_enabled BOOLEAN DEFAULT false,
    primary_domain BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenant_domains_org ON tenant_domains(org_id);
CREATE INDEX IF NOT EXISTS idx_tenant_domains_domain ON tenant_domains(domain);

-- Add openidx.tdv.org domain mapping
INSERT INTO tenant_domains (org_id, domain, domain_type, verified, primary_domain)
VALUES (
    '01234567-89ab-cdef-0123-456789abcdef',
    'openidx.tdv.org',
    'custom',
    true,
    true
)
ON CONFLICT (domain) DO UPDATE SET
    org_id = EXCLUDED.org_id,
    verified = EXCLUDED.verified,
    primary_domain = EXCLUDED.primary_domain,
    updated_at = NOW();
