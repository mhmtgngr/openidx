-- OpenIDX Database Schema Migration
-- Version: 008
-- Description: Add SCIM-compatible identity tables with organizations

-- This migration creates new SCIM 2.0 compliant tables for users, groups, and organizations
-- while maintaining backward compatibility with the existing tables.

-- ============================================================================
-- SCIM-COMPATIBLE USERS TABLE
-- ============================================================================

-- Drop the old users table if it exists in a development environment
-- Note: In production, you would migrate data instead
-- DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE IF NOT EXISTS users_v2 (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id VARCHAR(255) UNIQUE,

    -- SCIM Core Fields
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255),
    active BOOLEAN DEFAULT true,
    name JSONB, -- Name object with givenName, familyName, etc.

    -- SCIM Multi-value Fields
    emails JSONB DEFAULT '[]'::jsonb,
    phone_numbers JSONB DEFAULT '[]'::jsonb,
    photos JSONB DEFAULT '[]'::jsonb,
    addresses JSONB DEFAULT '[]'::jsonb,
    groups JSONB DEFAULT '[]'::jsonb, -- Array of group IDs
    entitlements JSONB DEFAULT '[]'::jsonb,
    roles JSONB DEFAULT '[]'::jsonb,

    -- OpenIDX Extension Fields
    enabled BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    attributes JSONB, -- Flexible key-value attributes
    organization_id UUID REFERENCES organizations_v2(id) ON DELETE SET NULL,
    directory_id UUID, -- For external sync (LDAP, SCIM, etc.)
    ldap_dn VARCHAR(500),
    source VARCHAR(50), -- 'ldap', 'scim', 'manual', etc.

    -- Password & Security Fields
    password_hash VARCHAR(255),
    password_changed_at TIMESTAMP,
    password_must_change BOOLEAN DEFAULT false,
    failed_login_count INTEGER DEFAULT 0,
    last_failed_login_at TIMESTAMP,
    locked_until TIMESTAMP,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP, -- Soft delete
    last_login_at TIMESTAMP,

    -- SCIM Meta
    meta JSONB, -- ResourceType, Location, Created, LastModified, Version

    CONSTRAINT check_username_not_empty CHECK (trim(username) != '')
);

-- Index for performance
CREATE INDEX IF NOT EXISTS idx_users_v2_username ON users_v2(username);
CREATE INDEX IF NOT EXISTS idx_users_v2_external_id ON users_v2(external_id);
CREATE INDEX IF NOT EXISTS idx_users_v2_emails ON users_v2 USING GIN (emails);
CREATE INDEX IF NOT EXISTS idx_users_v2_groups ON users_v2 USING GIN (groups);
CREATE INDEX IF NOT EXISTS idx_users_v2_organization_id ON users_v2(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_v2_directory_id ON users_v2(directory_id);
CREATE INDEX IF NOT EXISTS idx_users_v2_source ON users_v2(source);
CREATE INDEX IF NOT EXISTS idx_users_v2_active ON users_v2(active);
CREATE INDEX IF NOT EXISTS idx_users_v2_deleted_at ON users_v2(deleted_at);
CREATE INDEX IF NOT EXISTS idx_users_v2_created_at ON users_v2(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_users_v2_last_login_at ON users_v2(last_login_at DESC);

-- Full-text search for users
CREATE INDEX IF NOT EXISTS idx_users_v2_fulltext ON users_v2 USING GIN (
    to_tsvector('english',
        COALESCE(username, '') || ' ' ||
        COALESCE(display_name, '') || ' ' ||
        COALESCE(emails::text, '')
    )
);

-- ============================================================================
-- SCIM-COMPATIBLE GROUPS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS groups_v2 (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id VARCHAR(255) UNIQUE,

    -- SCIM Core Fields
    display_name VARCHAR(255) NOT NULL,
    members JSONB DEFAULT '[]'::jsonb, -- Array of Member objects

    -- OpenIDX Extension Fields
    organization_id UUID REFERENCES organizations_v2(id) ON DELETE SET NULL,
    attributes JSONB,
    directory_id UUID, -- For external sync
    source VARCHAR(50), -- 'ldap', 'scim', 'manual', etc.

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP, -- Soft delete

    -- SCIM Meta
    meta JSONB,

    CONSTRAINT check_display_name_not_empty CHECK (trim(display_name) != '')
);

-- Index for performance
CREATE INDEX IF NOT EXISTS idx_groups_v2_display_name ON groups_v2(display_name);
CREATE INDEX IF NOT EXISTS idx_groups_v2_external_id ON groups_v2(external_id);
CREATE INDEX IF NOT EXISTS idx_groups_v2_members ON groups_v2 USING GIN (members);
CREATE INDEX IF NOT EXISTS idx_groups_v2_organization_id ON groups_v2(organization_id);
CREATE INDEX IF NOT EXISTS idx_groups_v2_directory_id ON groups_v2(directory_id);
CREATE INDEX IF NOT EXISTS idx_groups_v2_source ON groups_v2(source);
CREATE INDEX IF NOT EXISTS idx_groups_v2_deleted_at ON groups_v2(deleted_at);
CREATE INDEX IF NOT EXISTS idx_groups_v2_created_at ON groups_v2(created_at DESC);

-- ============================================================================
-- SCIM-COMPATIBLE ORGANIZATIONS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS organizations_v2 (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id VARCHAR(255) UNIQUE,

    -- Core Fields
    name VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    active BOOLEAN DEFAULT true,

    -- Domain & Branding
    domain VARCHAR(255) UNIQUE,
    branding JSONB, -- Logo, colors, theme, custom CSS

    -- Settings
    attributes JSONB,
    settings JSONB, -- Flexible organization settings

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP, -- Soft delete

    -- SCIM Meta
    meta JSONB,

    CONSTRAINT check_org_name_not_empty CHECK (trim(name) != ''),
    CONSTRAINT check_org_display_name_not_empty CHECK (trim(display_name) != '')
);

-- Index for performance
CREATE INDEX IF NOT EXISTS idx_organizations_v2_name ON organizations_v2(name);
CREATE INDEX IF NOT EXISTS idx_organizations_v2_external_id ON organizations_v2(external_id);
CREATE INDEX IF NOT EXISTS idx_organizations_v2_domain ON organizations_v2(domain);
CREATE INDEX IF NOT EXISTS idx_organizations_v2_active ON organizations_v2(active);
CREATE INDEX IF NOT EXISTS idx_organizations_v2_deleted_at ON organizations_v2(deleted_at);
CREATE INDEX IF NOT EXISTS idx_organizations_v2_created_at ON organizations_v2(created_at DESC);

-- Full-text search for organizations
CREATE INDEX IF NOT EXISTS idx_organizations_v2_fulltext ON organizations_v2 USING GIN (
    to_tsvector('english',
        COALESCE(name, '') || ' ' ||
        COALESCE(display_name, '')
    )
);

-- ============================================================================
-- FUNCTIONS AND TRIGGERS
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for users_v2
DROP TRIGGER IF EXISTS update_users_v2_updated_at ON users_v2;
CREATE TRIGGER update_users_v2_updated_at
    BEFORE UPDATE ON users_v2
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger for groups_v2
DROP TRIGGER IF EXISTS update_groups_v2_updated_at ON groups_v2;
CREATE TRIGGER update_groups_v2_updated_at
    BEFORE UPDATE ON groups_v2
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger for organizations_v2
DROP TRIGGER IF EXISTS update_organizations_v2_updated_at ON organizations_v2;
CREATE TRIGGER update_organizations_v2_updated_at
    BEFORE UPDATE ON organizations_v2
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE users_v2 IS 'SCIM 2.0 compatible users table with flexible schema';
COMMENT ON COLUMN users_v2.id IS 'Unique identifier (UUID)';
COMMENT ON COLUMN users_v2.external_id IS 'External identifier from identity provider';
COMMENT ON COLUMN users_v2.username IS 'Unique username (SCIM required)';
COMMENT ON COLUMN users_v2.active IS 'Account active status (SCIM)';
COMMENT ON COLUMN users_v2.emails IS 'Email addresses array (SCIM multi-value)';
COMMENT ON COLUMN users_v2.groups IS 'Group membership array (group IDs)';
COMMENT ON COLUMN users_v2.meta IS 'SCIM metadata (resourceType, location, version, etc.)';

COMMENT ON TABLE groups_v2 IS 'SCIM 2.0 compatible groups table';
COMMENT ON COLUMN groups_v2.display_name IS 'Group display name (SCIM required)';
COMMENT ON COLUMN groups_v2.members IS 'Group members array (Member objects with value, type, display)';
COMMENT ON COLUMN groups_v2.meta IS 'SCIM metadata (resourceType, location, version, etc.)';

COMMENT ON TABLE organizations_v2 IS 'Organizations/Tenants with SCIM-compatible fields';
COMMENT ON COLUMN organizations_v2.name IS 'Unique organization name';
COMMENT ON COLUMN organizations_v2.display_name IS 'Human-readable display name';
COMMENT ON COLUMN organizations_v2.domain IS 'Primary domain for the organization';
COMMENT ON COLUMN organizations_v2.branding IS 'Branding settings (logo, colors, theme)';
