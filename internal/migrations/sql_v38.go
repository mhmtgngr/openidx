package migrations

// Migration v38 — tenant branding / domains / settings tables.
//
// These three tables back the multi-tenant login experience: tenant_branding
// (per-org logo/colors/CSS read by the public branding endpoint and the OAuth
// login page), tenant_domains (domain → org mapping used by the TenantResolver
// middleware and the domain-based branding lookup), and tenant_settings
// (per-org category settings written by the admin API).
//
// They previously existed only in deployments/docker/init-db.sql, which is
// mounted into the docker-compose Postgres container on first boot. Production
// (managed RDS via Helm/Terraform) only runs the versioned Go migrations, so
// without this migration the tables never existed there — admins could not save
// branding, and domain-based tenant resolution silently fell back to defaults.
// This migration brings the schema into the versioned set, matching init-db.sql.
//
// DDL is idempotent (CREATE TABLE IF NOT EXISTS) so it is a no-op on clusters
// that were bootstrapped from init-db.sql. The tables are intentionally NOT
// placed under the RLS belt: tenant_branding is read unauthenticated by the
// login page, and tenant_domains is read during tenant resolution before any
// org context exists.
var tenantTablesUp = `-- Migration 038: tenant branding / domains / settings.
CREATE TABLE IF NOT EXISTS tenant_branding (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    logo_url VARCHAR(500) DEFAULT '',
    favicon_url VARCHAR(500) DEFAULT '',
    primary_color VARCHAR(20) DEFAULT '#1e40af',
    secondary_color VARCHAR(20) DEFAULT '#3b82f6',
    background_color VARCHAR(20) DEFAULT '#f8fafc',
    background_image_url VARCHAR(500) DEFAULT '',
    login_page_title VARCHAR(255) DEFAULT 'Sign In',
    login_page_message TEXT DEFAULT '',
    portal_title VARCHAR(255) DEFAULT 'OpenIDX Portal',
    custom_css TEXT DEFAULT '',
    custom_footer TEXT DEFAULT '',
    powered_by_visible BOOLEAN DEFAULT true,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(org_id)
);
CREATE INDEX IF NOT EXISTS idx_tenant_branding_org ON tenant_branding(org_id);

CREATE TABLE IF NOT EXISTS tenant_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    category VARCHAR(100) NOT NULL,
    settings JSONB NOT NULL DEFAULT '{}',
    updated_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(org_id, category)
);
CREATE INDEX IF NOT EXISTS idx_tenant_settings_org ON tenant_settings(org_id);

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
`

var tenantTablesDown = `-- Migration 038 down: drop the tenant branding / domains / settings tables.
DROP TABLE IF EXISTS tenant_domains;
DROP TABLE IF EXISTS tenant_settings;
DROP TABLE IF EXISTS tenant_branding;
`
