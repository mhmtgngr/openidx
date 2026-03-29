-- Migration 025: Multi-Tenancy Support with Organizations

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    domain VARCHAR(255) UNIQUE,
    plan VARCHAR(50) DEFAULT 'free',
    status VARCHAR(50) DEFAULT 'active',
    settings JSONB DEFAULT '{}',
    max_users INTEGER DEFAULT 10,
    max_applications INTEGER DEFAULT 5,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    invited_by UUID,
    UNIQUE(organization_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);
CREATE INDEX IF NOT EXISTS idx_organizations_domain ON organizations(domain);
CREATE INDEX IF NOT EXISTS idx_org_members_org ON organization_members(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);

-- Add org_id to key tables
ALTER TABLE users ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE roles ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE access_reviews ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE service_accounts ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE webhook_subscriptions ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS org_id UUID;

CREATE INDEX IF NOT EXISTS idx_users_org_id ON users(org_id);
CREATE INDEX IF NOT EXISTS idx_groups_org_id ON groups(org_id);
CREATE INDEX IF NOT EXISTS idx_roles_org_id ON roles(org_id);
CREATE INDEX IF NOT EXISTS idx_applications_org_id ON applications(org_id);

-- Default organization for backward compatibility
INSERT INTO organizations (id, name, slug, domain, plan, status, max_users, max_applications)
VALUES ('00000000-0000-0000-0000-000000000010', 'Default Organization', 'default', NULL, 'enterprise', 'active', 999999, 999999)
ON CONFLICT (id) DO NOTHING;

-- Assign existing data to default org
UPDATE users SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE groups SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE roles SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE applications SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;

INSERT INTO organization_members (organization_id, user_id, role)
VALUES ('00000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-000000000001', 'owner')
ON CONFLICT DO NOTHING;
