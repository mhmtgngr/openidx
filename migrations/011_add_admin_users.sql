-- Migration: Add admin users and sessions tables
-- Description: Creates tables for admin console authentication
-- Version: 011

-- Create admin_users table
CREATE TABLE IF NOT EXISTS admin_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true NOT NULL,
    is_super_admin BOOLEAN DEFAULT false NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    last_login_at TIMESTAMP WITH TIME ZONE
);

-- Create index on email for fast lookup
CREATE INDEX IF NOT EXISTS idx_admin_users_email ON admin_users(email);
CREATE INDEX IF NOT EXISTS idx_admin_users_is_active ON admin_users(is_active);

-- Create admin_sessions table
CREATE TABLE IF NOT EXISTS admin_sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    token VARCHAR(500) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    user_agent TEXT,
    ip_address INET
);

-- Create indexes for session lookups and cleanup
CREATE INDEX IF NOT EXISTS idx_admin_sessions_user_id ON admin_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON admin_sessions(token);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions(expires_at);

-- Create admin_audit_log table for tracking admin actions
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES admin_users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

-- Create indexes for audit log queries
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_user_id ON admin_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_action ON admin_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_resource ON admin_audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_created_at ON admin_audit_log(created_at DESC);

-- Create admin_roles table for role-based access control
CREATE TABLE IF NOT EXISTS admin_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

-- Create admin_user_roles junction table
CREATE TABLE IF NOT EXISTS admin_user_roles (
    user_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES admin_roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    assigned_by UUID REFERENCES admin_users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, role_id)
);

-- Create indexes for role lookups
CREATE INDEX IF NOT EXISTS idx_admin_user_roles_user_id ON admin_user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_user_roles_role_id ON admin_user_roles(role_id);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_admin_users_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update updated_at
CREATE TRIGGER admin_users_updated_at
    BEFORE UPDATE ON admin_users
    FOR EACH ROW
    EXECUTE FUNCTION update_admin_users_updated_at();

CREATE TRIGGER admin_roles_updated_at
    BEFORE UPDATE ON admin_roles
    FOR EACH ROW
    EXECUTE FUNCTION update_admin_users_updated_at();

-- Insert default super admin user
-- Password: 'admin123' (change this immediately after first login!)
INSERT INTO admin_users (email, name, password_hash, is_super_admin)
VALUES (
    'admin@openidx.local',
    'Super Administrator',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj0S8UWdQq9i',
    true
) ON CONFLICT (email) DO NOTHING;

-- Insert default admin roles
INSERT INTO admin_roles (name, description, permissions) VALUES
    ('super_admin', 'Full system access', '["*"]'::jsonb),
    ('admin', 'Administrative access', '["users.read", "users.write", "roles.read", "reports.read"]'::jsonb),
    ('operator', 'Operational access', '["users.read", "reports.read"]'::jsonb),
    ('auditor', 'Audit and reporting access', '["audit.read", "reports.read"]'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- Assign super admin role to default admin user
INSERT INTO admin_user_roles (user_id, role_id)
SELECT u.id, r.id
FROM admin_users u, admin_roles r
WHERE u.email = 'admin@openidx.local' AND r.name = 'super_admin'
ON CONFLICT DO NOTHING;

-- Create view for active admin sessions with user info
CREATE OR REPLACE VIEW active_admin_sessions AS
SELECT
    s.id,
    s.user_id,
    u.email,
    u.name,
    s.created_at,
    s.expires_at,
    s.user_agent,
    s.ip_address
FROM admin_sessions s
JOIN admin_users u ON u.id = s.user_id
WHERE s.expires_at > NOW();

-- Create view for admin users with roles
CREATE OR REPLACE VIEW admin_users_with_roles AS
SELECT
    u.id,
    u.email,
    u.name,
    u.is_active,
    u.is_super_admin,
    u.created_at,
    u.last_login_at,
    COALESCE(jsonb_agg(DISTINCT jsonb_build_object('id', r.id, 'name', r.name)) FILTER (WHERE r.id IS NOT NULL), '[]'::jsonb) as roles
FROM admin_users u
LEFT JOIN admin_user_roles ur ON ur.user_id = u.id
LEFT JOIN admin_roles r ON r.id = ur.role_id
GROUP BY u.id;

-- Add comment for documentation
COMMENT ON TABLE admin_users IS 'Administrative users who can access the admin console';
COMMENT ON TABLE admin_sessions IS 'Active sessions for admin console users';
COMMENT ON TABLE admin_audit_log IS 'Audit trail of admin actions for compliance';
COMMENT ON TABLE admin_roles IS 'Role definitions for admin users';
COMMENT ON TABLE admin_user_roles IS 'Junction table assigning roles to admin users';
