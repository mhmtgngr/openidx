-- Migration 013: Permissions and Role Permissions

CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(resource, action)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL,
    permission_id UUID NOT NULL,
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);

-- Seed default permissions
INSERT INTO permissions (id, name, description, resource, action) VALUES
('a0000000-0000-0000-0000-000000000001', 'Read Users', 'View user accounts', 'users', 'read'),
('a0000000-0000-0000-0000-000000000002', 'Write Users', 'Create and edit user accounts', 'users', 'write'),
('a0000000-0000-0000-0000-000000000003', 'Delete Users', 'Delete user accounts', 'users', 'delete'),
('a0000000-0000-0000-0000-000000000004', 'Read Roles', 'View roles', 'roles', 'read'),
('a0000000-0000-0000-0000-000000000005', 'Write Roles', 'Create and edit roles', 'roles', 'write'),
('a0000000-0000-0000-0000-000000000006', 'Read Applications', 'View applications', 'applications', 'read'),
('a0000000-0000-0000-0000-000000000007', 'Write Applications', 'Create and edit applications', 'applications', 'write'),
('a0000000-0000-0000-0000-000000000008', 'Read Audit', 'View audit logs', 'audit', 'read'),
('a0000000-0000-0000-0000-000000000009', 'Write Settings', 'Modify system settings', 'settings', 'write')
ON CONFLICT (resource, action) DO NOTHING;
