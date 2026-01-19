-- OpenIDX Database Schema Migration
-- Version: 002
-- Description: Add roles and user_roles tables for role-based access control

-- ============================================================================
-- ROLES TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    is_composite BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
);

-- Composite roles (roles that contain other roles)
CREATE TABLE IF NOT EXISTS composite_roles (
    parent_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    child_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (parent_role_id, child_role_id)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_composite_roles_parent ON composite_roles(parent_role_id);
CREATE INDEX IF NOT EXISTS idx_composite_roles_child ON composite_roles(child_role_id);

-- ============================================================================
-- SEED DATA
-- ============================================================================

INSERT INTO roles (id, name, description, is_composite)
VALUES
    ('00000000-0000-0000-0000-000000000100', 'admin', 'Full system administrator access', false),
    ('00000000-0000-0000-0000-000000000101', 'user', 'Standard user access', false),
    ('00000000-0000-0000-0000-000000000102', 'auditor', 'Read-only access for compliance auditing', false),
    ('00000000-0000-0000-0000-000000000103', 'developer', 'Developer access with API permissions', false)
ON CONFLICT (name) DO NOTHING;

-- Assign admin role to admin user
INSERT INTO user_roles (user_id, role_id, assigned_by)
VALUES ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000100', '00000000-0000-0000-0000-000000000001')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE roles IS 'Role definitions for RBAC';
COMMENT ON TABLE user_roles IS 'User to role assignments';
COMMENT ON TABLE composite_roles IS 'Composite role relationships (role hierarchy)';
