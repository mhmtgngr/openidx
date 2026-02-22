-- Create tenant_branding table for Phase 17 Multi-Tenancy feature
-- This table stores custom branding settings per organization

CREATE TABLE IF NOT EXISTS tenant_branding (
    org_id UUID PRIMARY KEY,
    logo_url TEXT,
    favicon_url TEXT,
    primary_color VARCHAR(7) DEFAULT '#1e40af',
    secondary_color VARCHAR(7) DEFAULT '#3b82f6',
    background_color VARCHAR(7) DEFAULT '#f8fafc',
    background_image_url TEXT,
    login_page_title VARCHAR(255) DEFAULT 'Sign In',
    login_page_message TEXT,
    portal_title VARCHAR(255) DEFAULT 'OpenIDX Portal',
    custom_css TEXT,
    custom_footer TEXT,
    powered_by_visible BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add comments
COMMENT ON TABLE tenant_branding IS 'Stores custom branding configuration for each organization';
COMMENT ON COLUMN tenant_branding.org_id IS 'Organization ID (foreign key to organizations.id)';
COMMENT ON COLUMN tenant_branding.powered_by_visible IS 'Whether to show "Powered by OpenIDX" in the login page';

-- Create index
CREATE INDEX IF NOT EXISTS idx_tenant_branding_org_id ON tenant_branding(org_id);

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_branding TO openidx;
GRANT USAGE, SELECT ON SEQUENCE tenant_branding_id_seq TO openidx;
