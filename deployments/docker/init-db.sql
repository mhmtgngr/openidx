-- ============================================================================
-- OpenIDX Database Schema - Complete (Merged)
-- ============================================================================
-- This file creates all tables and seed data for OpenIDX
-- Run automatically by PostgreSQL on container initialization
-- Combines: OAuth/OIDC, SCIM, Governance, MFA, User Roles, Applications
-- ============================================================================

-- ============================================================================
-- USERS AND GROUPS TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    enabled BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE,
    -- Password policy fields
    password_changed_at TIMESTAMP WITH TIME ZONE,
    password_must_change BOOLEAN DEFAULT false,
    -- Account lockout fields
    failed_login_count INTEGER DEFAULT 0,
    last_failed_login_at TIMESTAMP WITH TIME ZONE,
    locked_until TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    parent_id UUID REFERENCES groups(id),
    allow_self_join BOOLEAN DEFAULT false,
    require_approval BOOLEAN DEFAULT false,
    max_members INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS group_memberships (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    is_composite BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id),
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

-- OAUTH 2.0 / OIDC TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    redirect_uris JSONB,
    grant_types JSONB,
    response_types JSONB,
    scopes JSONB,
    logo_uri VARCHAR(500),
    policy_uri VARCHAR(500),
    tos_uri VARCHAR(500),
    pkce_required BOOLEAN DEFAULT false,
    allow_refresh_token BOOLEAN DEFAULT true,
    access_token_lifetime INTEGER DEFAULT 3600,
    refresh_token_lifetime INTEGER DEFAULT 86400,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL,
    redirect_uri VARCHAR(500) NOT NULL,
    scope TEXT,
    state VARCHAR(255),
    nonce VARCHAR(255),
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(20),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS oauth_access_tokens (
    token VARCHAR(1000) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id UUID,
    scope TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token VARCHAR(500) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL,
    scope TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- SCIM 2.0 PROVISIONING TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS scim_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id VARCHAR(255),
    username VARCHAR(255) UNIQUE NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scim_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id VARCHAR(255),
    display_name VARCHAR(255) UNIQUE NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- GOVERNANCE TABLES (Access Reviews & Policies)
-- ============================================================================

-- Access reviews
CREATE TABLE IF NOT EXISTS access_reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    reviewer_id UUID REFERENCES users(id),
    start_date TIMESTAMP WITH TIME ZONE NOT NULL,
    end_date TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS review_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID REFERENCES access_reviews(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    resource_name VARCHAR(255),
    decision VARCHAR(50) DEFAULT 'pending',
    decided_by UUID REFERENCES users(id),
    decided_at TIMESTAMP WITH TIME ZONE,
    comments TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    rules JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policy_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID REFERENCES policies(id) ON DELETE CASCADE,
    rule_type VARCHAR(50) NOT NULL,
    conditions JSONB NOT NULL,
    actions JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- MULTI-FACTOR AUTHENTICATION TABLES
-- ============================================================================

-- TOTP (Time-based One-Time Password)
CREATE TABLE IF NOT EXISTS mfa_totp (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    secret VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT false,
    enrolled_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Backup Codes
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    used BOOLEAN DEFAULT false,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- MFA Policies
CREATE TABLE IF NOT EXISTS mfa_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    conditions JSONB,
    required_methods JSONB,
    grace_period_hours INTEGER DEFAULT 24,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_mfa_policies (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES mfa_policies(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, policy_id)
);

-- WebAuthn / FIDO2 / Passkeys
CREATE TABLE IF NOT EXISTS mfa_webauthn (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    sign_count BIGINT DEFAULT 0,
    aaguid VARCHAR(36),
    transports TEXT[],
    name VARCHAR(255),
    backup_eligible BOOLEAN DEFAULT false,
    backup_state BOOLEAN DEFAULT false,
    attestation_format VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, credential_id)
);

-- Push Notification MFA
CREATE TABLE IF NOT EXISTS mfa_push_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_token TEXT UNIQUE NOT NULL,
    platform VARCHAR(20) NOT NULL,
    device_name VARCHAR(255),
    device_model VARCHAR(100),
    os_version VARCHAR(50),
    app_version VARCHAR(50),
    enabled BOOLEAN DEFAULT true,
    trusted BOOLEAN DEFAULT false,
    last_ip VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS mfa_push_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES mfa_push_devices(id) ON DELETE CASCADE,
    challenge_code VARCHAR(10) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    session_info JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    responded_at TIMESTAMP WITH TIME ZONE,
    ip_address VARCHAR(45),
    user_agent TEXT,
    location VARCHAR(255)
);

-- ============================================================================
-- SESSION MANAGEMENT
-- ============================================================================

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(500) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- APPLICATIONS - from dev
-- ============================================================================

CREATE TABLE IF NOT EXISTS applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    protocol VARCHAR(50) DEFAULT 'openid-connect',
    base_url VARCHAR(500),
    redirect_uris TEXT[],
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Application SSO settings - from dev
CREATE TABLE IF NOT EXISTS application_sso_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID REFERENCES applications(id) ON DELETE CASCADE,
    enabled BOOLEAN DEFAULT true,
    use_refresh_tokens BOOLEAN DEFAULT true,
    access_token_lifetime INTEGER DEFAULT 3600,
    refresh_token_lifetime INTEGER DEFAULT 86400,
    require_consent BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(application_id)
);

-- ============================================================================
-- AUDIT AND COMPLIANCE
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    action VARCHAR(255) NOT NULL,
    outcome VARCHAR(50) NOT NULL,
    actor_id VARCHAR(255),
    actor_type VARCHAR(50),
    actor_ip VARCHAR(45),
    target_id VARCHAR(255),
    target_type VARCHAR(100),
    resource_id VARCHAR(255),
    details JSONB,
    session_id VARCHAR(255),
    request_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Users and Groups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_groups_name ON groups(name);

-- Roles
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);

-- OAuth
CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_client_id ON oauth_authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_user_id ON oauth_authorization_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_client_id ON oauth_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_user_id ON oauth_access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_client_id ON oauth_refresh_tokens(client_id);

-- SCIM
CREATE INDEX IF NOT EXISTS idx_scim_users_external_id ON scim_users(external_id);
CREATE INDEX IF NOT EXISTS idx_scim_groups_external_id ON scim_groups(external_id);

-- Governance
CREATE INDEX IF NOT EXISTS idx_access_reviews_status ON access_reviews(status);
CREATE INDEX IF NOT EXISTS idx_review_items_review_id ON review_items(review_id);
CREATE INDEX IF NOT EXISTS idx_review_items_user_id ON review_items(user_id);
CREATE INDEX IF NOT EXISTS idx_policies_type ON policies(type);

-- MFA
CREATE INDEX IF NOT EXISTS idx_webauthn_user_id ON mfa_webauthn(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credential_id ON mfa_webauthn(credential_id);
CREATE INDEX IF NOT EXISTS idx_push_devices_user_id ON mfa_push_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_push_devices_token ON mfa_push_devices(device_token);
CREATE INDEX IF NOT EXISTS idx_push_challenges_user_id ON mfa_push_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_push_challenges_status ON mfa_push_challenges(status);
CREATE INDEX IF NOT EXISTS idx_push_challenges_expires_at ON mfa_push_challenges(expires_at);

-- Sessions
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);

-- Applications
CREATE INDEX IF NOT EXISTS idx_applications_client_id ON applications(client_id);
CREATE INDEX IF NOT EXISTS idx_application_sso_settings_application_id ON application_sso_settings(application_id);

-- Audit
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_category ON audit_events(category);

-- ============================================================================
-- SEED DATA - Admin User and Sample Data
-- ============================================================================

-- Insert default admin user
INSERT INTO users (id, username, email, first_name, last_name, enabled, email_verified)
VALUES ('00000000-0000-0000-0000-000000000001', 'admin', 'admin@openidx.local', 'System', 'Admin', true, true)
ON CONFLICT (id) DO NOTHING;

-- Insert sample roles (from dev)
-- Insert sample roles
INSERT INTO roles (id, name, description, is_composite) VALUES
('60000000-0000-0000-0000-000000000001', 'admin', 'System administrator with full access', false),
('60000000-0000-0000-0000-000000000002', 'user', 'Standard user role', false),
('60000000-0000-0000-0000-000000000003', 'manager', 'Manager role with additional permissions', false),
('60000000-0000-0000-0000-000000000004', 'auditor', 'Audit and compliance role', false),
('60000000-0000-0000-0000-000000000005', 'developer', 'Software developer role', false)
ON CONFLICT (id) DO NOTHING;

-- Insert sample users
INSERT INTO users (id, username, email, first_name, last_name, enabled, email_verified) VALUES
('00000000-0000-0000-0000-000000000002', 'jsmith', 'john.smith@example.com', 'John', 'Smith', true, true),
('00000000-0000-0000-0000-000000000003', 'jdoe', 'jane.doe@example.com', 'Jane', 'Doe', true, true),
('00000000-0000-0000-0000-000000000004', 'bwilson', 'bob.wilson@example.com', 'Bob', 'Wilson', true, false),
('00000000-0000-0000-0000-000000000005', 'amartin', 'alice.martin@example.com', 'Alice', 'Martin', false, true)
ON CONFLICT (id) DO NOTHING;

-- Insert sample groups
INSERT INTO groups (id, name, description, parent_id) VALUES
('10000000-0000-0000-0000-000000000001', 'Administrators', 'System administrators with full access', NULL),
('10000000-0000-0000-0000-000000000002', 'Developers', 'Software development team', NULL),
('10000000-0000-0000-0000-000000000003', 'DevOps', 'DevOps engineering team', '10000000-0000-0000-0000-000000000002'),
('10000000-0000-0000-0000-000000000004', 'QA Team', 'Quality assurance team', '10000000-0000-0000-0000-000000000002'),
('10000000-0000-0000-0000-000000000005', 'Finance', 'Finance department', NULL),
('10000000-0000-0000-0000-000000000006', 'HR', 'Human resources department', NULL)
ON CONFLICT (id) DO NOTHING;

-- Insert group memberships
INSERT INTO group_memberships (user_id, group_id) VALUES
('00000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000001'),
('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000002'),
('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000003'),
('00000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000002'),
('00000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000004'),
('00000000-0000-0000-0000-000000000004', '10000000-0000-0000-0000-000000000005'),
('00000000-0000-0000-0000-000000000005', '10000000-0000-0000-0000-000000000006')
ON CONFLICT DO NOTHING;

-- Insert sample applications
    UNIQUE(application_id)
);

INSERT INTO applications (id, client_id, name, description, type, protocol, base_url, enabled) VALUES
('20000000-0000-0000-0000-000000000001', 'admin-console', 'Admin Console', 'OpenIDX Administration Console', 'web', 'openid-connect', 'http://localhost:3000', true),
('20000000-0000-0000-0000-000000000002', 'hr-portal', 'HR Portal', 'Human Resources Management Portal', 'web', 'openid-connect', 'http://hr.example.com', true),
('20000000-0000-0000-0000-000000000003', 'finance-app', 'Finance Application', 'Financial reporting and management', 'web', 'openid-connect', 'http://finance.example.com', true),
('20000000-0000-0000-0000-000000000004', 'mobile-app', 'Mobile Application', 'Company mobile application', 'native', 'openid-connect', NULL, true),
('20000000-0000-0000-0000-000000000005', 'legacy-erp', 'Legacy ERP', 'Legacy ERP system integration', 'service', 'saml', 'http://erp.example.com', false)
ON CONFLICT (id) DO NOTHING;

-- Insert demo OAuth client
INSERT INTO oauth_clients (
    id, client_id, client_secret, name, description, type,
    redirect_uris, grant_types, response_types, scopes,
    pkce_required, allow_refresh_token
) VALUES (
    '00000000-0000-0000-0000-000000000020',
    'demo-client',
    '$2a$10$N9qo8uLOickgx2ZMRZoMye1234567890abcdefghijk',
    'Demo Application',
    'Demo OAuth 2.0 client for testing',
    'web',
    '["http://localhost:3000/callback", "http://localhost:8080/callback"]'::jsonb,
    '["authorization_code", "refresh_token"]'::jsonb,
    '["code"]'::jsonb,
    '["openid", "profile", "email", "offline_access"]'::jsonb,
    true,
    true
) ON CONFLICT (client_id) DO NOTHING;

-- Insert sample access reviews
INSERT INTO access_reviews (id, name, description, type, status, reviewer_id, start_date, end_date) VALUES
('30000000-0000-0000-0000-000000000001', 'Q1 2026 Access Review', 'Quarterly access review for all users', 'user_access', 'in_progress', '00000000-0000-0000-0000-000000000001', '2026-01-01', '2026-01-31'),
('30000000-0000-0000-0000-000000000002', 'Admin Role Review', 'Review of administrative role assignments', 'role_assignment', 'pending', '00000000-0000-0000-0000-000000000001', '2026-02-01', '2026-02-28'),
('30000000-0000-0000-0000-000000000003', 'Finance App Access', 'Review access to finance application', 'application_access', 'completed', '00000000-0000-0000-0000-000000000001', '2025-12-01', '2025-12-31')
ON CONFLICT (id) DO NOTHING;

-- Insert sample review items
INSERT INTO review_items (id, review_id, user_id, resource_type, resource_id, resource_name, decision) VALUES
('31000000-0000-0000-0000-000000000001', '30000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'application', '20000000-0000-0000-0000-000000000002', 'HR Portal', 'pending'),
('31000000-0000-0000-0000-000000000002', '30000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000003', 'application', '20000000-0000-0000-0000-000000000003', 'Finance Application', 'approved'),
('31000000-0000-0000-0000-000000000003', '30000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000004', 'group', '10000000-0000-0000-0000-000000000005', 'Finance', 'pending')
ON CONFLICT (id) DO NOTHING;

-- Insert sample MFA policies
INSERT INTO mfa_policies (id, name, description, enabled, priority, conditions, required_methods, grace_period_hours) VALUES
('50000000-0000-0000-0000-000000000001', 'Admin MFA Required', 'Require MFA for all administrators', true, 100,
 '{"groups": ["Administrators"]}'::jsonb, '["totp", "backup_code"]'::jsonb, 24),
('50000000-0000-0000-0000-000000000002', 'Finance Department MFA', 'Require MFA for finance department during business hours', true, 80,
 '{"groups": ["Finance"], "time_windows": [{"days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"], "start_hour": 9, "end_hour": 17}]}'::jsonb, '["totp"]'::jsonb, 48),
('50000000-0000-0000-0000-000000000003', 'External Access MFA', 'Require MFA for access from external IP ranges', true, 60,
 '{"ip_ranges": ["192.168.0.0/16", "10.0.0.0/8"]}'::jsonb, '["totp", "backup_code"]'::jsonb, 0)
ON CONFLICT (id) DO NOTHING;

-- Insert sample audit events
INSERT INTO audit_events (id, timestamp, event_type, category, action, outcome, actor_id, actor_type, actor_ip, target_id, target_type, details) VALUES
('40000000-0000-0000-0000-000000000001', NOW() - INTERVAL '1 hour', 'authentication', 'security', 'user.login', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.100', '00000000-0000-0000-0000-000000000001', 'user', '{"method": "password", "client": "admin-console"}'::jsonb),
('40000000-0000-0000-0000-000000000002', NOW() - INTERVAL '2 hours', 'authentication', 'security', 'user.login', 'failure', NULL, 'anonymous', '192.168.1.101', NULL, NULL, '{"reason": "invalid_credentials", "username": "unknown"}'::jsonb),
('40000000-0000-0000-0000-000000000003', NOW() - INTERVAL '3 hours', 'user_management', 'operational', 'user.create', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.100', '00000000-0000-0000-0000-000000000002', 'user', '{"username": "jsmith"}'::jsonb),
('40000000-0000-0000-0000-000000000004', NOW() - INTERVAL '4 hours', 'authorization', 'security', 'permission.granted', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.100', '00000000-0000-0000-0000-000000000002', 'user', '{"permission": "view_reports", "resource": "finance-app"}'::jsonb),
('40000000-0000-0000-0000-000000000005', NOW() - INTERVAL '5 hours', 'group_management', 'operational', 'group.member_added', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.100', '10000000-0000-0000-0000-000000000002', 'group', '{"user_id": "00000000-0000-0000-0000-000000000003", "group": "Developers"}'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- SUCCESS MESSAGE
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '✅ OpenIDX Database Schema Created Successfully (Merged)';
    RAISE NOTICE '📊 Tables: users, groups, roles, oauth_clients, scim_users, applications, access_reviews, policies, audit_events, MFA, and more';
    RAISE NOTICE '👤 Default admin user: admin@openidx.local';
    RAISE NOTICE '🔐 Demo OAuth client: demo-client';
    RAISE NOTICE '🎭 Sample roles: admin, user, manager, auditor, developer';
END $$;
