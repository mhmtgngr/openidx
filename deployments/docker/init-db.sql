-- ============================================================================
-- OpenIDX Database Schema - Complete
-- ============================================================================
-- This file creates all tables and seed data for OpenIDX
-- Run automatically by PostgreSQL on container initialization
-- ============================================================================

-- ============================================================================
-- USERS AND GROUPS TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
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

-- Composite roles (role hierarchy)
CREATE TABLE IF NOT EXISTS composite_roles (
    parent_role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    child_role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (parent_role_id, child_role_id)
);

-- User roles (many-to-many relationship)
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id),
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

-- ============================================================================
-- OAUTH 2.0 / OIDC TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret VARCHAR(255),  -- NULL for public clients
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,  -- 'public' or 'confidential'
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
-- APPLICATIONS
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

-- Application SSO settings
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

CREATE TABLE IF NOT EXISTS compliance_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL,
    framework VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    start_date TIMESTAMP WITH TIME ZONE NOT NULL,
    end_date TIMESTAMP WITH TIME ZONE NOT NULL,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    generated_by UUID REFERENCES users(id),
    summary JSONB DEFAULT '{}',
    findings JSONB DEFAULT '[]',
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
CREATE INDEX IF NOT EXISTS idx_audit_events_outcome ON audit_events(outcome);

-- Compliance Reports
CREATE INDEX IF NOT EXISTS idx_compliance_reports_type ON compliance_reports(type);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_status ON compliance_reports(status);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_generated_at ON compliance_reports(generated_at);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_framework ON compliance_reports(framework);

-- ============================================================================
-- SEED DATA - Admin User and Sample Data
-- ============================================================================

-- Insert default admin user (password: Admin@123)
-- bcrypt hash generated with cost 12 for "Admin@123"
INSERT INTO users (id, username, email, password_hash, first_name, last_name, enabled, email_verified)
VALUES ('00000000-0000-0000-0000-000000000001', 'admin', 'admin@openidx.local', '$2b$12$oX..0F6dHbNip8vASE5VdOgXiBfyqRZ768PU5vArjeOMxG5MGEEdq', 'System', 'Admin', true, true)
ON CONFLICT (id) DO NOTHING;

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
INSERT INTO applications (id, client_id, name, description, type, protocol, base_url, redirect_uris, enabled) VALUES
('40000000-0000-0000-0000-000000000001', 'admin-console', 'Admin Console', 'OpenIDX Administration Console', 'web', 'openid-connect', 'http://localhost:3000', ARRAY['http://localhost:3000/callback'], true),
('40000000-0000-0000-0000-000000000002', 'sample-spa', 'Sample SPA', 'Sample Single Page Application', 'spa', 'openid-connect', 'http://localhost:4000', ARRAY['http://localhost:4000/callback'], true),
('40000000-0000-0000-0000-000000000003', 'api-service', 'API Service', 'Backend API Service', 'service', 'openid-connect', NULL, NULL, true)
ON CONFLICT (id) DO NOTHING;

-- Insert OAuth clients (public and confidential)
INSERT INTO oauth_clients (id, client_id, client_secret, name, description, type, redirect_uris, grant_types, response_types, scopes, pkce_required, allow_refresh_token, access_token_lifetime, refresh_token_lifetime) VALUES
-- Admin Console - public client (no secret, PKCE required)
('80000000-0000-0000-0000-000000000001', 'admin-console', NULL, 'Admin Console', 'OpenIDX Administration Console', 'public',
 '["http://localhost:3000/login", "http://localhost:3000/callback"]'::jsonb,
 '["authorization_code", "refresh_token"]'::jsonb,
 '["code"]'::jsonb,
 '["openid", "profile", "email", "offline_access"]'::jsonb,
 true, true, 3600, 86400),
-- API Service - confidential client
('80000000-0000-0000-0000-000000000002', 'api-service', 'api-service-secret', 'API Service', 'Backend API Service', 'confidential',
 '[]'::jsonb,
 '["client_credentials"]'::jsonb,
 '[]'::jsonb,
 '["openid", "api"]'::jsonb,
 false, false, 3600, 0)
ON CONFLICT (id) DO NOTHING;

-- Add test client for debugging
INSERT INTO oauth_clients (id, client_id, client_secret, name, description, type, redirect_uris, grant_types, response_types, scopes, pkce_required, allow_refresh_token, access_token_lifetime, refresh_token_lifetime) VALUES
('80000000-0000-0000-0000-000000000003', 'test-client', 'test-secret', 'Test Client', 'Client for testing authentication flow', 'confidential',
 '[]'::jsonb,
 '["authorization_code", "refresh_token", "client_credentials"]'::jsonb,
 '["code"]'::jsonb,
 '["openid", "profile", "email"]'::jsonb,
 false, true, 3600, 86400)
ON CONFLICT (id) DO NOTHING;

-- Insert sample application SSO settings
INSERT INTO application_sso_settings (id, application_id, enabled, use_refresh_tokens, access_token_lifetime, refresh_token_lifetime, require_consent) VALUES
('50000000-0000-0000-0000-000000000001', '40000000-0000-0000-0000-000000000001', true, true, 3600, 86400, false),
('50000000-0000-0000-0000-000000000002', '40000000-0000-0000-0000-000000000002', true, true, 1800, 43200, true),
('50000000-0000-0000-0000-000000000003', '40000000-0000-0000-0000-000000000003', true, false, 3600, 0, false)
ON CONFLICT (id) DO NOTHING;

-- Assign admin role to admin user
INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES
('00000000-0000-0000-0000-000000000001', '60000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001')
ON CONFLICT DO NOTHING;

-- Insert sample access review
INSERT INTO access_reviews (id, name, description, type, status, reviewer_id, start_date, end_date) VALUES
('70000000-0000-0000-0000-000000000001', 'Q1 2026 Access Review', 'Quarterly access review for all users', 'user-access', 'pending', '00000000-0000-0000-0000-000000000001', '2026-01-01', '2026-03-31')
ON CONFLICT (id) DO NOTHING;

-- OpenIDX Database Schema Migration
-- Version: 004
-- Description: Adds support for external identity providers (OIDC/SAML) for SSO.

-- ============================================================================
-- IDENTITY PROVIDERS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS identity_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    provider_type VARCHAR(50) NOT NULL, -- 'oidc' or 'saml'
    issuer_url VARCHAR(255) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255) NOT NULL, -- TODO: Encrypt this value at rest
    scopes JSONB,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_identity_providers_name ON identity_providers(name);
CREATE INDEX IF NOT EXISTS idx_identity_providers_provider_type ON identity_providers(provider_type);
CREATE INDEX IF NOT EXISTS idx_identity_providers_issuer_url ON identity_providers(issuer_url);

-- ============================================================================
-- COMMENTS FOR DOCUMENTATION
-- ============================================================================

COMMENT ON TABLE identity_providers IS 'Configuration for external OIDC/SAML identity providers for SSO';
COMMENT ON COLUMN identity_providers.provider_type IS 'Type of the identity provider (e.g., ''oidc'', ''saml'')';
COMMENT ON COLUMN identity_providers.issuer_url IS 'The base URL of the external identity provider';
COMMENT ON COLUMN identity_providers.client_secret IS 'Client secret for the external provider. This should be encrypted.';

-- ============================================================================
-- FOREIGN KEY (Optional, but recommended)
-- Link JIT-provisioned users to the IdP that created them.
-- ============================================================================

ALTER TABLE users
ADD COLUMN IF NOT EXISTS idp_id UUID REFERENCES identity_providers(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS external_user_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_users_idp_id ON users(idp_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id_idp_id ON users(idp_id, external_user_id) WHERE idp_id IS NOT NULL;

COMMENT ON COLUMN users.idp_id IS 'Foreign key to the identity provider that provisioned this user.';
COMMENT ON COLUMN users.external_user_id IS 'The user''s unique ID from the external identity provider.';

-- ============================================================================
-- PROVISIONING RULES TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS provisioning_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    trigger VARCHAR(50) NOT NULL,
    conditions JSONB DEFAULT '[]',
    actions JSONB DEFAULT '[]',
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_provisioning_rules_trigger ON provisioning_rules(trigger);
CREATE INDEX IF NOT EXISTS idx_provisioning_rules_enabled ON provisioning_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_provisioning_rules_priority ON provisioning_rules(priority);

-- ============================================================================
-- PASSWORD RESET TOKENS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);

-- ============================================================================
-- PERMISSIONS TABLES
-- ============================================================================

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
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
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

-- ============================================================================
-- SYSTEM SETTINGS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by UUID
);

-- Seed default system settings
INSERT INTO system_settings (key, value) VALUES
('system', '{
    "general": {
        "organization_name": "OpenIDX",
        "support_email": "support@openidx.io",
        "default_language": "en",
        "default_timezone": "UTC"
    },
    "security": {
        "password_policy": {
            "min_length": 12,
            "require_uppercase": true,
            "require_lowercase": true,
            "require_numbers": true,
            "require_special": true,
            "max_age": 90,
            "history": 5
        },
        "session_timeout": 30,
        "max_failed_logins": 5,
        "lockout_duration": 15,
        "require_mfa": false,
        "blocked_countries": []
    },
    "authentication": {
        "allow_registration": true,
        "require_email_verify": true,
        "mfa_methods": ["totp", "webauthn", "sms"]
    },
    "branding": {
        "primary_color": "#2563eb",
        "secondary_color": "#1e40af",
        "login_page_title": "Welcome to OpenIDX"
    }
}'::jsonb),
('mfa_methods', '["totp", "webauthn", "sms"]'::jsonb),
('browzer_domain_config', '{
    "domain": "browzer.localtest.me",
    "cert_type": "self_signed",
    "cert_subject": "",
    "cert_issuer": "",
    "cert_not_before": "",
    "cert_not_after": "",
    "cert_fingerprint": "",
    "cert_san": [],
    "custom_cert_uploaded_at": null,
    "previous_domain": null,
    "domain_changed_at": null
}'::jsonb)
ON CONFLICT (key) DO NOTHING;

-- ============================================================================
-- DIRECTORY INTEGRATIONS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS directory_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- ldap, azure_ad, google
    config JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    sync_status VARCHAR(50) DEFAULT 'never',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_directory_integrations_type ON directory_integrations(type);

-- ============================================================================
-- ZERO TRUST ACCESS PROXY TABLES
-- ============================================================================

-- Proxy route configurations
CREATE TABLE IF NOT EXISTS proxy_routes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    from_url VARCHAR(500) NOT NULL,
    to_url VARCHAR(500) NOT NULL,
    preserve_host BOOLEAN DEFAULT false,
    require_auth BOOLEAN DEFAULT true,
    allowed_roles JSONB,
    allowed_groups JSONB,
    policy_ids JSONB,
    idle_timeout INTEGER DEFAULT 900,
    absolute_timeout INTEGER DEFAULT 43200,
    cors_allowed_origins JSONB,
    custom_headers JSONB,
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_proxy_routes_from_url ON proxy_routes(from_url);
CREATE INDEX IF NOT EXISTS idx_proxy_routes_enabled ON proxy_routes(enabled);

-- Proxy sessions
CREATE TABLE IF NOT EXISTS proxy_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    route_id UUID REFERENCES proxy_routes(id),
    session_token VARCHAR(500) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_active_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_proxy_sessions_user ON proxy_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_proxy_sessions_token ON proxy_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_proxy_sessions_expires ON proxy_sessions(expires_at);

-- ============================================================================
-- OPENZITI INTEGRATION TABLES
-- ============================================================================

-- Add Ziti columns to proxy_routes
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS ziti_enabled BOOLEAN DEFAULT false;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS ziti_service_name VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_proxy_routes_ziti_enabled ON proxy_routes(ziti_enabled);

-- Ziti services managed by OpenIDX
CREATE TABLE IF NOT EXISTS ziti_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    protocol VARCHAR(20) DEFAULT 'tcp',
    host VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    route_id UUID REFERENCES proxy_routes(id) ON DELETE SET NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ziti_services_name ON ziti_services(name);
CREATE INDEX IF NOT EXISTS idx_ziti_services_route_id ON ziti_services(route_id);

-- Ziti identities for tunneler enrollment
CREATE TABLE IF NOT EXISTS ziti_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) UNIQUE NOT NULL,
    identity_type VARCHAR(50) DEFAULT 'Device',
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    enrollment_jwt TEXT,
    enrolled BOOLEAN DEFAULT false,
    attributes JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ziti_identities_user_id ON ziti_identities(user_id);
CREATE INDEX IF NOT EXISTS idx_ziti_identities_name ON ziti_identities(name);

-- Ziti service policies (Bind/Dial)
CREATE TABLE IF NOT EXISTS ziti_service_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    policy_type VARCHAR(10) NOT NULL,
    service_roles JSONB DEFAULT '[]',
    identity_roles JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Seed: Register access-proxy as an OAuth client
INSERT INTO oauth_clients (client_id, client_secret, name, type, redirect_uris, grant_types, response_types, scopes, pkce_required)
VALUES (
    'access-proxy',
    '',
    'Zero Trust Access Proxy',
    'public',
    '["http://localhost:8007/access/.auth/callback", "http://localhost:8088/access/.auth/callback", "http://demo.localtest.me:8088/access/.auth/callback"]'::jsonb,
    '["authorization_code", "refresh_token"]'::jsonb,
    '["code"]'::jsonb,
    '["openid", "profile", "email"]'::jsonb,
    true
) ON CONFLICT (client_id) DO NOTHING;

-- Seed audit events for demo/testing
INSERT INTO audit_events (id, timestamp, event_type, category, action, outcome, actor_id, actor_type, actor_ip, target_id, target_type, resource_id, details)
VALUES
  (gen_random_uuid(), NOW() - INTERVAL '6 days 14 hours', 'system', 'operational', 'system_startup', 'success',
   'system', 'system', '127.0.0.1', '', 'system', '', '{"message": "OpenIDX platform initialized"}'),

  (gen_random_uuid(), NOW() - INTERVAL '6 days 13 hours', 'configuration', 'operational', 'settings_updated', 'success',
   '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '00000000-0000-0000-0000-000000000001', 'settings', '', '{"section": "security", "change": "password policy updated"}'),

  (gen_random_uuid(), NOW() - INTERVAL '5 days 10 hours', 'authentication', 'security', 'login', 'success',
   '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}'),

  (gen_random_uuid(), NOW() - INTERVAL '5 days 8 hours', 'user_management', 'operational', 'user_created', 'success',
   '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '00000000-0000-0000-0000-000000000002', 'user', '00000000-0000-0000-0000-000000000002', '{"username": "john.doe", "email": "john@openidx.local"}'),

  (gen_random_uuid(), NOW() - INTERVAL '4 days 16 hours', 'authentication', 'security', 'login_failed', 'failure',
   'unknown_user', 'user', '10.0.0.55', '', 'user', '', '{"reason": "invalid credentials", "username": "unknown_user"}'),

  (gen_random_uuid(), NOW() - INTERVAL '3 days 12 hours', 'authentication', 'security', 'login', 'success',
   '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}'),

  (gen_random_uuid(), NOW() - INTERVAL '3 days 6 hours', 'user_management', 'operational', 'user_updated', 'success',
   '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '00000000-0000-0000-0000-000000000002', 'user', '00000000-0000-0000-0000-000000000002', '{"changes": ["email", "display_name"]}'),

  (gen_random_uuid(), NOW() - INTERVAL '2 days 9 hours', 'authentication', 'security', 'login_failed', 'failure',
   'admin', 'user', '10.0.0.99', '', 'user', '', '{"reason": "invalid password", "username": "admin"}'),

  (gen_random_uuid(), NOW() - INTERVAL '1 day 15 hours', 'authentication', 'security', 'login', 'success',
   '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}'),

  (gen_random_uuid(), NOW() - INTERVAL '1 day 4 hours', 'group_management', 'operational', 'group_created', 'success',
   '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '', 'group', '', '{"group_name": "Engineering", "description": "Engineering team"}'),

  (gen_random_uuid(), NOW() - INTERVAL '12 hours', 'configuration', 'operational', 'application_created', 'success',
   '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '', 'application', '', '{"app_name": "Internal Dashboard", "protocol": "oidc"}'),

  (gen_random_uuid(), NOW() - INTERVAL '6 hours', 'authentication', 'security', 'login', 'success',
   '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.20', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}');

-- ============================================================================
-- DIRECTORY SYNC TABLES (Phase 3)
-- ============================================================================

-- Add directory sync columns to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'local';
ALTER TABLE users ADD COLUMN IF NOT EXISTS directory_id UUID REFERENCES directory_integrations(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS ldap_dn VARCHAR(1024);

CREATE INDEX IF NOT EXISTS idx_users_directory_id ON users(directory_id);
CREATE INDEX IF NOT EXISTS idx_users_source ON users(source);

-- Add directory sync columns to groups
ALTER TABLE groups ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'local';
ALTER TABLE groups ADD COLUMN IF NOT EXISTS directory_id UUID REFERENCES directory_integrations(id) ON DELETE SET NULL;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS ldap_dn VARCHAR(1024);
ALTER TABLE groups ADD COLUMN IF NOT EXISTS external_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_groups_directory_id ON groups(directory_id);

-- Sync state per directory (for incremental sync)
CREATE TABLE IF NOT EXISTS directory_sync_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id UUID NOT NULL REFERENCES directory_integrations(id) ON DELETE CASCADE,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    last_usn_changed BIGINT,
    last_modify_timestamp VARCHAR(255),
    users_synced INTEGER DEFAULT 0,
    groups_synced INTEGER DEFAULT 0,
    errors_count INTEGER DEFAULT 0,
    sync_duration_ms INTEGER,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(directory_id)
);

-- Sync log history
CREATE TABLE IF NOT EXISTS directory_sync_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id UUID NOT NULL REFERENCES directory_integrations(id) ON DELETE CASCADE,
    sync_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    users_added INTEGER DEFAULT 0,
    users_updated INTEGER DEFAULT 0,
    users_disabled INTEGER DEFAULT 0,
    groups_added INTEGER DEFAULT 0,
    groups_updated INTEGER DEFAULT 0,
    groups_deleted INTEGER DEFAULT 0,
    error_message TEXT,
    details JSONB
);

CREATE INDEX IF NOT EXISTS idx_sync_logs_directory ON directory_sync_logs(directory_id);
CREATE INDEX IF NOT EXISTS idx_sync_logs_started ON directory_sync_logs(started_at DESC);

-- ============================================================================
-- CONDITIONAL ACCESS / RISK ENGINE
-- ============================================================================

-- Known/trusted devices per user
CREATE TABLE IF NOT EXISTS known_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint VARCHAR(128) NOT NULL,
    name VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    location VARCHAR(255),
    trusted BOOLEAN DEFAULT false,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_known_devices_user ON known_devices(user_id);

-- Login history for risk analysis
CREATE TABLE IF NOT EXISTS login_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    location VARCHAR(255),
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    device_fingerprint VARCHAR(128),
    risk_score INTEGER DEFAULT 0,
    success BOOLEAN NOT NULL,
    auth_methods TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id, created_at DESC);

-- Step-up MFA challenges (mid-session re-auth)
CREATE TABLE IF NOT EXISTS stepup_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id VARCHAR(255) NOT NULL,
    reason VARCHAR(255),
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_stepup_user ON stepup_challenges(user_id, status);

-- Enhance proxy_sessions with risk context
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS device_fingerprint VARCHAR(128);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS auth_methods TEXT[];
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS location VARCHAR(255);

-- ============================================================================
-- PHASE 5: API KEYS, WEBHOOKS, EMAIL VERIFICATION, INVITATIONS
-- ============================================================================

-- Service accounts (non-human identities for programmatic access)
CREATE TABLE IF NOT EXISTS service_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    owner_id UUID REFERENCES users(id),
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- API keys (for both users and service accounts)
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(12) NOT NULL,
    key_hash VARCHAR(128) NOT NULL UNIQUE,
    user_id UUID REFERENCES users(id),
    service_account_id UUID REFERENCES service_accounts(id),
    scopes TEXT[],
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CHECK (user_id IS NOT NULL OR service_account_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_sa ON api_keys(service_account_id);

-- Webhook subscriptions
CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    secret VARCHAR(255) NOT NULL,
    events TEXT[] NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Webhook delivery log
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id UUID NOT NULL REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    response_status INTEGER,
    response_body TEXT,
    attempt INTEGER DEFAULT 1,
    status VARCHAR(50) DEFAULT 'pending',
    next_retry_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    delivered_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_sub ON webhook_deliveries(subscription_id);

-- Email verification tokens
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User invitations
CREATE TABLE IF NOT EXISTS user_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    invited_by UUID NOT NULL REFERENCES users(id),
    roles TEXT[],
    groups TEXT[],
    token VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(50) DEFAULT 'pending',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    accepted_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invitations_token ON user_invitations(token);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON user_invitations(email);

-- Add lifecycle columns to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_completed BOOLEAN DEFAULT false;

-- ============================================================================
-- PHASE 6: REQUEST/APPROVAL WORKFLOWS
-- ============================================================================

CREATE TABLE IF NOT EXISTS access_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID NOT NULL,
    resource_name VARCHAR(255),
    justification TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    priority VARCHAR(20) DEFAULT 'normal',
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS access_request_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
    approver_id UUID NOT NULL REFERENCES users(id),
    step_order INTEGER DEFAULT 1,
    decision VARCHAR(50) DEFAULT 'pending',
    comments TEXT,
    decided_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS approval_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    approval_steps JSONB NOT NULL DEFAULT '[]',
    auto_approve_conditions JSONB,
    max_wait_hours INTEGER DEFAULT 72,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_access_requests_requester ON access_requests(requester_id);
CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status);
CREATE INDEX IF NOT EXISTS idx_request_approvals_request ON access_request_approvals(request_id);
CREATE INDEX IF NOT EXISTS idx_request_approvals_approver ON access_request_approvals(approver_id, decision);
CREATE INDEX IF NOT EXISTS idx_approval_policies_resource ON approval_policies(resource_type, resource_id);

-- ============================================================================
-- PHASE 6: ANOMALY DETECTION & THREAT RESPONSE
-- ============================================================================

CREATE TABLE IF NOT EXISTS security_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) DEFAULT 'open',
    title VARCHAR(500) NOT NULL,
    description TEXT,
    details JSONB,
    source_ip VARCHAR(45),
    remediation_actions JSONB DEFAULT '[]',
    resolved_by UUID REFERENCES users(id),
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ip_threat_list (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    threat_type VARCHAR(50) NOT NULL,
    reason TEXT,
    blocked_until TIMESTAMP WITH TIME ZONE,
    permanent BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_alerts_user ON security_alerts(user_id);
CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_security_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_security_alerts_created ON security_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ip_threat_list_ip ON ip_threat_list(ip_address);

-- ============================================================================
-- PHASE 6: PASSWORD/CREDENTIAL MANAGEMENT
-- ============================================================================

CREATE TABLE IF NOT EXISTS password_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS credential_rotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_account_id UUID NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    old_key_id UUID,
    new_key_id UUID,
    rotation_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'completed',
    rotated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    rotated_by UUID REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_credential_rotations_sa ON credential_rotations(service_account_id);

-- ============================================================================
-- PHASE 6: SESSION MANAGEMENT ENHANCEMENTS
-- ============================================================================

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_name VARCHAR(255);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS location VARCHAR(255);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_type VARCHAR(50);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked BOOLEAN DEFAULT false;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked_by UUID REFERENCES users(id);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoke_reason VARCHAR(255);

-- ============================================================================
-- PHASE 7: MULTI-TENANCY
-- ============================================================================

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
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    invited_by UUID REFERENCES users(id),
    UNIQUE(organization_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);
CREATE INDEX IF NOT EXISTS idx_organizations_domain ON organizations(domain);
CREATE INDEX IF NOT EXISTS idx_org_members_org ON organization_members(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);

-- Add org_id to key tables
ALTER TABLE users ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
ALTER TABLE groups ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
ALTER TABLE roles ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
ALTER TABLE applications ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
ALTER TABLE policies ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
ALTER TABLE access_reviews ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
ALTER TABLE service_accounts ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
ALTER TABLE webhook_subscriptions ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);

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

-- ============================================================================
-- PHASE 7: ADVANCED REPORTING
-- ============================================================================

CREATE TABLE IF NOT EXISTS scheduled_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    report_type VARCHAR(50) NOT NULL,
    framework VARCHAR(100),
    parameters JSONB DEFAULT '{}',
    schedule VARCHAR(100) NOT NULL,
    format VARCHAR(10) DEFAULT 'csv',
    enabled BOOLEAN DEFAULT true,
    recipients TEXT[],
    last_run_at TIMESTAMP WITH TIME ZONE,
    next_run_at TIMESTAMP WITH TIME ZONE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS report_exports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    scheduled_report_id UUID REFERENCES scheduled_reports(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    framework VARCHAR(100),
    format VARCHAR(10) NOT NULL,
    status VARCHAR(50) DEFAULT 'generating',
    file_path VARCHAR(500),
    file_size BIGINT,
    row_count INTEGER,
    error_message TEXT,
    generated_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_report_exports_org ON report_exports(org_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_reports_org ON scheduled_reports(org_id);

-- ============================================================================
-- PHASE 7: SELF-SERVICE PORTAL
-- ============================================================================

CREATE TABLE IF NOT EXISTS group_join_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    justification TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    reviewed_by UUID REFERENCES users(id),
    reviewed_at TIMESTAMP WITH TIME ZONE,
    review_comments TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, group_id)
);

CREATE TABLE IF NOT EXISTS user_application_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, application_id)
);

ALTER TABLE groups ADD COLUMN IF NOT EXISTS allow_self_join BOOLEAN DEFAULT false;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS require_approval BOOLEAN DEFAULT true;

CREATE INDEX IF NOT EXISTS idx_group_requests_user ON group_join_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_group_requests_status ON group_join_requests(status);
CREATE INDEX IF NOT EXISTS idx_user_app_assignments_user ON user_application_assignments(user_id);

-- ============================================================================
-- PHASE 7: NOTIFICATION SYSTEM
-- ============================================================================

CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID REFERENCES organizations(id),
    channel VARCHAR(50) NOT NULL,
    type VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    link VARCHAR(500),
    read BOOLEAN DEFAULT false,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notification_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel VARCHAR(50) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, channel, event_type)
);

CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, read, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_prefs_user ON notification_preferences(user_id);


-- ============================================================================
-- PHASE: OPENZITI ENHANCED - POSTURE CHECKS, POLICY SYNC, CERTIFICATES
-- ============================================================================

-- Device posture check types
CREATE TABLE IF NOT EXISTS posture_check_types (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    category VARCHAR(100) NOT NULL,
    parameters JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Posture checks linked to Ziti
CREATE TABLE IF NOT EXISTS posture_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE,
    name VARCHAR(255) NOT NULL,
    check_type VARCHAR(100) NOT NULL,
    parameters JSONB DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    severity VARCHAR(50) DEFAULT 'medium',
    remediation_hint TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Device posture results
CREATE TABLE IF NOT EXISTS device_posture_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID REFERENCES ziti_identities(id) ON DELETE CASCADE,
    check_id UUID REFERENCES posture_checks(id) ON DELETE CASCADE,
    passed BOOLEAN NOT NULL,
    details JSONB DEFAULT '{}',
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_posture_results_identity ON device_posture_results(identity_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_posture_results_check ON device_posture_results(check_id);

-- Policy sync state between governance and Ziti
CREATE TABLE IF NOT EXISTS policy_sync_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    governance_policy_id UUID NOT NULL,
    ziti_policy_id VARCHAR(255),
    sync_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    last_synced_at TIMESTAMP WITH TIME ZONE,
    last_error TEXT,
    config JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_sync_governance ON policy_sync_state(governance_policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_sync_status ON policy_sync_state(status);

-- Ziti certificate management
CREATE TABLE IF NOT EXISTS ziti_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    cert_type VARCHAR(50) NOT NULL,
    subject VARCHAR(500),
    issuer VARCHAR(500),
    serial_number VARCHAR(255),
    fingerprint VARCHAR(255) UNIQUE,
    not_before TIMESTAMP WITH TIME ZONE,
    not_after TIMESTAMP WITH TIME ZONE,
    auto_renew BOOLEAN DEFAULT false,
    renewal_threshold_days INTEGER DEFAULT 30,
    pem_data TEXT,
    status VARCHAR(50) DEFAULT 'active',
    associated_identity_id UUID REFERENCES ziti_identities(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ziti_certs_expiry ON ziti_certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_ziti_certs_status ON ziti_certificates(status);

-- Ziti edge routers tracking
CREATE TABLE IF NOT EXISTS ziti_edge_routers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    hostname VARCHAR(255),
    is_online BOOLEAN DEFAULT false,
    is_verified BOOLEAN DEFAULT false,
    role_attributes JSONB DEFAULT '[]',
    os VARCHAR(100),
    arch VARCHAR(100),
    version VARCHAR(100),
    last_seen_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Ziti network metrics snapshots
CREATE TABLE IF NOT EXISTS ziti_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_type VARCHAR(100) NOT NULL,
    source VARCHAR(255) NOT NULL,
    value DOUBLE PRECISION NOT NULL,
    labels JSONB DEFAULT '{}',
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ziti_metrics_type ON ziti_metrics(metric_type, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_ziti_metrics_source ON ziti_metrics(source);

-- Seed default posture check types
INSERT INTO posture_check_types (id, name, description, category, parameters) VALUES
('a0000000-0000-0000-0000-000000000001', 'os_check', 'Operating System Version Check', 'device', '{"os_types": ["Windows", "macOS", "Linux"], "min_versions": {}}'),
('a0000000-0000-0000-0000-000000000002', 'domain_check', 'Windows Domain Membership Check', 'device', '{"domains": []}'),
('a0000000-0000-0000-0000-000000000003', 'mac_address_check', 'MAC Address Allowlist Check', 'network', '{"mac_addresses": []}'),
('a0000000-0000-0000-0000-000000000004', 'mfa_check', 'Multi-Factor Authentication Check', 'authentication', '{"timeout_seconds": 300}'),
('a0000000-0000-0000-0000-000000000005', 'process_check', 'Running Process Check', 'endpoint', '{"os_type": "", "path": "", "hashes": []}')
ON CONFLICT (id) DO NOTHING;

-- Add posture_check_ids to ziti_service_policies
ALTER TABLE ziti_service_policies ADD COLUMN IF NOT EXISTS posture_check_roles JSONB DEFAULT '[]';

-- Track whether a service policy was auto-created by the system
ALTER TABLE ziti_service_policies ADD COLUMN IF NOT EXISTS is_system BOOLEAN DEFAULT false;

-- Add description column to ziti_services
ALTER TABLE ziti_services ADD COLUMN IF NOT EXISTS description TEXT;

-- Track when group attributes were last synced per identity
ALTER TABLE ziti_identities ADD COLUMN IF NOT EXISTS group_attrs_synced_at TIMESTAMP WITH TIME ZONE;

-- Ziti user sync state (singleton row)
CREATE TABLE IF NOT EXISTS ziti_user_sync (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    last_full_sync_at TIMESTAMP WITH TIME ZONE,
    last_auto_sync_at TIMESTAMP WITH TIME ZONE,
    users_synced INTEGER DEFAULT 0,
    users_failed INTEGER DEFAULT 0,
    groups_synced INTEGER DEFAULT 0,
    status VARCHAR(50) DEFAULT 'idle',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
INSERT INTO ziti_user_sync (status) VALUES ('idle') ON CONFLICT DO NOTHING;

-- ============================================================================
-- POMERIUM-LIKE ZERO-TRUST ACCESS PROXY ENHANCEMENTS
-- ============================================================================

-- Add context-aware access columns to proxy_routes
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS idp_id UUID REFERENCES identity_providers(id);
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS route_type VARCHAR(20) DEFAULT 'http';
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS remote_host VARCHAR(255);
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS remote_port INTEGER;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS reverify_interval INTEGER DEFAULT 0;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS posture_check_ids JSONB;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS inline_policy TEXT;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS require_device_trust BOOLEAN DEFAULT false;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS allowed_countries JSONB;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS max_risk_score INTEGER DEFAULT 100;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS guacamole_connection_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_proxy_routes_route_type ON proxy_routes(route_type);
CREATE INDEX IF NOT EXISTS idx_proxy_routes_idp_id ON proxy_routes(idp_id);

-- Add continuous verification columns to proxy_sessions
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS verification_failures INTEGER DEFAULT 0;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS geo_country VARCHAR(10);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS geo_city VARCHAR(255);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS idp_id UUID;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS device_trusted BOOLEAN DEFAULT false;

-- Add is_active column to ip_threat_list if not exists
ALTER TABLE ip_threat_list ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true;

-- IP geolocation cache
CREATE TABLE IF NOT EXISTS ip_geolocation_cache (
    ip_address VARCHAR(45) PRIMARY KEY,
    country_code VARCHAR(10),
    city VARCHAR(255),
    latitude FLOAT,
    longitude FLOAT,
    cached_at TIMESTAMPTZ DEFAULT NOW()
);

-- Guacamole connection tracking
CREATE TABLE IF NOT EXISTS guacamole_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    route_id UUID REFERENCES proxy_routes(id) ON DELETE CASCADE,
    guacamole_connection_id VARCHAR(255) NOT NULL,
    protocol VARCHAR(20) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    parameters JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(route_id)
);

CREATE INDEX IF NOT EXISTS idx_guacamole_connections_route ON guacamole_connections(route_id);

-- ============================================================================
-- BROWZER CONFIGURATION
-- ============================================================================

-- BrowZer config state (single-row table)
CREATE TABLE IF NOT EXISTS ziti_browzer_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_jwt_signer_id VARCHAR(255),
    auth_policy_id VARCHAR(255),
    dial_policy_id VARCHAR(255),
    oidc_issuer VARCHAR(500),
    oidc_client_id VARCHAR(255),
    enabled BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- BrowZer-enabled flag on proxy routes
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS browzer_enabled BOOLEAN DEFAULT false;

-- BrowZer OAuth client for browser-native Ziti access
INSERT INTO oauth_clients (client_id, client_secret, name, type, redirect_uris, grant_types, response_types, scopes, pkce_required)
VALUES (
    'browzer-client', '', 'BrowZer Zero Trust Browser Client', 'public',
    '["https://browzer.localtest.me/"]'::jsonb,
    '["authorization_code","refresh_token"]'::jsonb,
    '["code"]'::jsonb,
    '["openid","profile","email"]'::jsonb,
    true
) ON CONFLICT (client_id) DO NOTHING;

-- ============================================================================
-- UNIFIED SERVICE MANAGEMENT - PHASE 1
-- ============================================================================

-- Service features tracking (toggleable features per route)
CREATE TABLE IF NOT EXISTS service_features (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    route_id UUID NOT NULL REFERENCES proxy_routes(id) ON DELETE CASCADE,
    feature_name VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT false,
    config JSONB DEFAULT '{}',
    resource_ids JSONB DEFAULT '{}',
    status VARCHAR(50) DEFAULT 'disabled',
    error_message TEXT,
    last_health_check TIMESTAMPTZ,
    health_status VARCHAR(20) DEFAULT 'unknown',
    enabled_at TIMESTAMPTZ,
    enabled_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(route_id, feature_name)
);

CREATE INDEX IF NOT EXISTS idx_service_features_route ON service_features(route_id);
CREATE INDEX IF NOT EXISTS idx_service_features_feature ON service_features(feature_name);
CREATE INDEX IF NOT EXISTS idx_service_features_enabled ON service_features(enabled);
CREATE INDEX IF NOT EXISTS idx_service_features_health ON service_features(health_status);

-- Connection test results
CREATE TABLE IF NOT EXISTS connection_tests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    route_id UUID NOT NULL REFERENCES proxy_routes(id) ON DELETE CASCADE,
    test_type VARCHAR(50) NOT NULL,
    success BOOLEAN NOT NULL,
    latency_ms INTEGER,
    error_message TEXT,
    details JSONB DEFAULT '{}',
    tested_at TIMESTAMPTZ DEFAULT NOW(),
    tested_by UUID REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_connection_tests_route ON connection_tests(route_id);
CREATE INDEX IF NOT EXISTS idx_connection_tests_type ON connection_tests(test_type);
CREATE INDEX IF NOT EXISTS idx_connection_tests_tested_at ON connection_tests(tested_at DESC);

-- Unified audit events (aggregates from OpenIDX, Ziti, Guacamole)
CREATE TABLE IF NOT EXISTS unified_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source VARCHAR(50) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    route_id UUID REFERENCES proxy_routes(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_ip VARCHAR(45),
    details JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_unified_audit_source ON unified_audit_events(source, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_unified_audit_route ON unified_audit_events(route_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_unified_audit_user ON unified_audit_events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_unified_audit_event_type ON unified_audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_unified_audit_created ON unified_audit_events(created_at DESC);

-- Guacamole connection pool tracking
CREATE TABLE IF NOT EXISTS guacamole_connection_pool (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id VARCHAR(255) NOT NULL,
    token VARCHAR(500) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ DEFAULT NOW(),
    use_count INTEGER DEFAULT 1,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_guac_pool_connection ON guacamole_connection_pool(connection_id);
CREATE INDEX IF NOT EXISTS idx_guac_pool_user ON guacamole_connection_pool(user_id);
CREATE INDEX IF NOT EXISTS idx_guac_pool_expires ON guacamole_connection_pool(expires_at);

-- External audit sync state (tracks last sync from Ziti/Guacamole)
CREATE TABLE IF NOT EXISTS external_audit_sync_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source VARCHAR(50) UNIQUE NOT NULL,
    last_sync_at TIMESTAMPTZ,
    last_event_id VARCHAR(255),
    sync_cursor JSONB DEFAULT '{}',
    error_message TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO external_audit_sync_state (source, last_sync_at) VALUES
    ('ziti', NULL),
    ('guacamole', NULL)
ON CONFLICT (source) DO NOTHING;

-- ============================================================================
-- MIGRATION 004: SMS/Email OTP, Risk Policies, Trusted Browsers
-- ============================================================================

-- SMS MFA enrollment
CREATE TABLE IF NOT EXISTS mfa_sms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    phone_number VARCHAR(20) NOT NULL,
    country_code VARCHAR(5) NOT NULL DEFAULT '+1',
    verified BOOLEAN DEFAULT false,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    verified_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id)
);

CREATE INDEX IF NOT EXISTS idx_mfa_sms_user_id ON mfa_sms(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_sms_phone ON mfa_sms(phone_number);

-- Email OTP enrollment
CREATE TABLE IF NOT EXISTS mfa_email_otp (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email_address VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id)
);

CREATE INDEX IF NOT EXISTS idx_mfa_email_otp_user_id ON mfa_email_otp(user_id);

-- OTP challenges (shared for both SMS and Email)
CREATE TABLE IF NOT EXISTS mfa_otp_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method VARCHAR(20) NOT NULL,
    recipient VARCHAR(255) NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    status VARCHAR(20) DEFAULT 'pending',
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_mfa_otp_challenges_user_id ON mfa_otp_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_otp_challenges_status ON mfa_otp_challenges(status, expires_at);

-- Risk-based MFA policies
CREATE TABLE IF NOT EXISTS risk_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 100,
    conditions JSONB NOT NULL DEFAULT '{}',
    actions JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_policies_enabled ON risk_policies(enabled, priority);

-- Trusted browsers (remember this device)
CREATE TABLE IF NOT EXISTS trusted_browsers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    browser_hash VARCHAR(128) NOT NULL,
    name VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    trusted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE,
    revoked BOOLEAN DEFAULT false,
    UNIQUE(user_id, browser_hash)
);

CREATE INDEX IF NOT EXISTS idx_trusted_browsers_user_id ON trusted_browsers(user_id);
CREATE INDEX IF NOT EXISTS idx_trusted_browsers_hash ON trusted_browsers(browser_hash);
CREATE INDEX IF NOT EXISTS idx_trusted_browsers_active ON trusted_browsers(user_id, revoked, expires_at);

-- Insert default risk policies
INSERT INTO risk_policies (name, description, priority, conditions, actions) VALUES
(
    'New Device MFA',
    'Require MFA when logging in from a new device',
    100,
    '{"new_device": true}',
    '{"require_mfa": true, "mfa_methods": ["any"]}'
),
(
    'New Location MFA',
    'Require MFA when logging in from a new location',
    90,
    '{"new_location": true}',
    '{"require_mfa": true, "mfa_methods": ["any"]}'
),
(
    'High Risk Score',
    'Require strong MFA for high-risk logins',
    80,
    '{"risk_score_min": 50}',
    '{"require_mfa": true, "mfa_methods": ["webauthn", "push"], "step_up": true}'
),
(
    'Impossible Travel',
    'Block or require step-up auth for impossible travel',
    70,
    '{"impossible_travel": true}',
    '{"require_mfa": true, "mfa_methods": ["webauthn", "push"], "step_up": true, "notify_admin": true}'
),
(
    'Blocked IP',
    'Deny access from blocked IP addresses',
    60,
    '{"ip_blocked": true}',
    '{"deny": true, "notify_admin": true}'
)
ON CONFLICT DO NOTHING;

-- MFA methods view
CREATE OR REPLACE VIEW user_mfa_methods AS
SELECT
    u.id AS user_id,
    u.username,
    COALESCE(t.enabled, false) AS totp_enabled,
    COALESCE(s.enabled AND s.verified, false) AS sms_enabled,
    COALESCE(e.enabled, false) AS email_otp_enabled,
    EXISTS(SELECT 1 FROM mfa_push_devices p WHERE p.user_id = u.id AND p.enabled) AS push_enabled,
    EXISTS(SELECT 1 FROM mfa_webauthn w WHERE w.user_id = u.id) AS webauthn_enabled,
    (SELECT COUNT(*) FROM mfa_backup_codes b WHERE b.user_id = u.id AND NOT b.used) AS backup_codes_remaining
FROM users u
LEFT JOIN mfa_totp t ON t.user_id = u.id
LEFT JOIN mfa_sms s ON s.user_id = u.id
LEFT JOIN mfa_email_otp e ON e.user_id = u.id;

-- ============================================================================
-- MIGRATION 005: Advanced MFA Features
-- ============================================================================

-- Hardware Tokens
CREATE TABLE IF NOT EXISTS hardware_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial_number VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255),
    token_type VARCHAR(50) NOT NULL DEFAULT 'yubikey',
    secret_key VARCHAR(255) NOT NULL,
    counter BIGINT DEFAULT 0,
    manufacturer VARCHAR(100),
    model VARCHAR(100),
    firmware_version VARCHAR(50),
    status VARCHAR(20) DEFAULT 'available',
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMP WITH TIME ZONE,
    assigned_by UUID REFERENCES users(id),
    last_used_at TIMESTAMP WITH TIME ZONE,
    use_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_hardware_tokens_serial ON hardware_tokens(serial_number);
CREATE INDEX IF NOT EXISTS idx_hardware_tokens_assigned ON hardware_tokens(assigned_to);
CREATE INDEX IF NOT EXISTS idx_hardware_tokens_status ON hardware_tokens(status);

-- Token usage audit log
CREATE TABLE IF NOT EXISTS hardware_token_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id UUID REFERENCES hardware_tokens(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_token_events_token ON hardware_token_events(token_id);
CREATE INDEX IF NOT EXISTS idx_token_events_user ON hardware_token_events(user_id);

-- Biometric preferences
CREATE TABLE IF NOT EXISTS biometric_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    platform_authenticator_preferred BOOLEAN DEFAULT true,
    allow_cross_platform BOOLEAN DEFAULT true,
    require_user_verification BOOLEAN DEFAULT true,
    biometric_only_enabled BOOLEAN DEFAULT false,
    resident_key_required BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Biometric policies
CREATE TABLE IF NOT EXISTS biometric_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    applies_to_groups UUID[],
    applies_to_roles VARCHAR(100)[],
    require_platform_authenticator BOOLEAN DEFAULT false,
    allowed_authenticator_types VARCHAR(50)[] DEFAULT ARRAY['platform', 'cross-platform'],
    min_authenticator_level VARCHAR(50) DEFAULT 'any',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Phone Call Verification
CREATE TABLE IF NOT EXISTS mfa_phone_call (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    phone_number VARCHAR(20) NOT NULL,
    country_code VARCHAR(5) NOT NULL,
    verified BOOLEAN DEFAULT false,
    enabled BOOLEAN DEFAULT true,
    voice_language VARCHAR(10) DEFAULT 'en-US',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id)
);

CREATE TABLE IF NOT EXISTS phone_call_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    phone_number VARCHAR(25) NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    call_type VARCHAR(20) DEFAULT 'outbound',
    call_sid VARCHAR(100),
    status VARCHAR(20) DEFAULT 'pending',
    attempts INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_phone_challenges_user ON phone_call_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_phone_challenges_status ON phone_call_challenges(status);

-- Device Trust Approval
CREATE TABLE IF NOT EXISTS device_trust_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    device_fingerprint VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(50),
    ip_address VARCHAR(45),
    user_agent TEXT,
    justification TEXT,
    status VARCHAR(20) DEFAULT 'pending',
    reviewed_by UUID REFERENCES users(id),
    reviewed_at TIMESTAMP WITH TIME ZONE,
    review_notes TEXT,
    auto_expire_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trust_requests_user ON device_trust_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_trust_requests_status ON device_trust_requests(status);
CREATE INDEX IF NOT EXISTS idx_trust_requests_pending ON device_trust_requests(status) WHERE status = 'pending';

-- Device trust settings
CREATE TABLE IF NOT EXISTS device_trust_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID,
    require_approval BOOLEAN DEFAULT false,
    auto_approve_known_ips BOOLEAN DEFAULT false,
    auto_approve_corporate_devices BOOLEAN DEFAULT false,
    request_expiry_hours INTEGER DEFAULT 72,
    notify_admins BOOLEAN DEFAULT true,
    notify_user_on_decision BOOLEAN DEFAULT true,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

INSERT INTO device_trust_settings (id, require_approval, auto_approve_known_ips, request_expiry_hours)
VALUES (gen_random_uuid(), false, false, 72)
ON CONFLICT DO NOTHING;

-- MFA Bypass Codes
CREATE TABLE IF NOT EXISTS mfa_bypass_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    reason TEXT NOT NULL,
    generated_by UUID REFERENCES users(id) NOT NULL,
    valid_from TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
    max_uses INTEGER DEFAULT 1,
    use_count INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'active',
    used_at TIMESTAMP WITH TIME ZONE,
    used_from_ip VARCHAR(45),
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bypass_codes_user ON mfa_bypass_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_bypass_codes_status ON mfa_bypass_codes(status);

-- Bypass code audit log
CREATE TABLE IF NOT EXISTS mfa_bypass_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bypass_code_id UUID REFERENCES mfa_bypass_codes(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    performed_by UUID REFERENCES users(id),
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bypass_audit_user ON mfa_bypass_audit(user_id);

-- Magic link tokens
CREATE TABLE IF NOT EXISTS magic_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    purpose VARCHAR(50) DEFAULT 'login',
    redirect_url TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_magic_links_token ON magic_links(token_hash);
CREATE INDEX IF NOT EXISTS idx_magic_links_user ON magic_links(user_id);
CREATE INDEX IF NOT EXISTS idx_magic_links_email ON magic_links(email);

-- QR code login sessions
CREATE TABLE IF NOT EXISTS qr_login_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_token VARCHAR(255) NOT NULL UNIQUE,
    qr_code_data TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    user_id UUID REFERENCES users(id),
    browser_info JSONB,
    mobile_info JSONB,
    ip_address VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    scanned_at TIMESTAMP WITH TIME ZONE,
    approved_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_qr_sessions_token ON qr_login_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_qr_sessions_status ON qr_login_sessions(status);

-- Passwordless user preferences
CREATE TABLE IF NOT EXISTS passwordless_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    webauthn_only BOOLEAN DEFAULT false,
    magic_link_enabled BOOLEAN DEFAULT true,
    qr_login_enabled BOOLEAN DEFAULT true,
    preferred_method VARCHAR(50) DEFAULT 'webauthn',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- MIGRATION 006: Add missing columns
-- ============================================================================

ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_trusted BOOLEAN DEFAULT false;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS auth_methods TEXT[];
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_name VARCHAR(255);
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_type VARCHAR(50);
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS location VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_user_sessions_device_trusted ON user_sessions(device_trusted);
CREATE INDEX IF NOT EXISTS idx_user_sessions_risk_score ON user_sessions(risk_score);

-- ============================================================================
-- MIGRATION 007: Temporary Access Links
-- ============================================================================

CREATE TABLE IF NOT EXISTS temp_access_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    protocol VARCHAR(20) NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc')),
    target_host VARCHAR(255) NOT NULL,
    target_port INTEGER NOT NULL CHECK (target_port > 0 AND target_port <= 65535),
    username VARCHAR(255),
    created_by UUID NOT NULL,
    created_by_email VARCHAR(255),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    max_uses INTEGER DEFAULT 0,
    current_uses INTEGER DEFAULT 0,
    allowed_ips TEXT[],
    require_mfa BOOLEAN DEFAULT FALSE,
    notify_on_use BOOLEAN DEFAULT FALSE,
    notify_email VARCHAR(255),
    route_id UUID REFERENCES proxy_routes(id) ON DELETE SET NULL,
    guacamole_connection_id VARCHAR(255),
    access_url TEXT,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked', 'used')),
    last_used_at TIMESTAMP WITH TIME ZONE,
    last_used_ip VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_temp_access_token ON temp_access_links(token);
CREATE INDEX IF NOT EXISTS idx_temp_access_status ON temp_access_links(status);
CREATE INDEX IF NOT EXISTS idx_temp_access_expires ON temp_access_links(expires_at);
CREATE INDEX IF NOT EXISTS idx_temp_access_created_by ON temp_access_links(created_by);

CREATE TABLE IF NOT EXISTS temp_access_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    link_id UUID NOT NULL REFERENCES temp_access_links(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    connected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    disconnected_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_temp_access_usage_link ON temp_access_usage(link_id);
CREATE INDEX IF NOT EXISTS idx_temp_access_usage_time ON temp_access_usage(connected_at);

CREATE OR REPLACE FUNCTION expire_temp_access_links()
RETURNS void AS $$
BEGIN
    UPDATE temp_access_links
    SET status = 'expired', updated_at = CURRENT_TIMESTAMP
    WHERE status = 'active' AND expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- DEMO APP - Proxy route for forward-auth standalone and BrowZer access
-- ============================================================================

INSERT INTO proxy_routes (id, name, description, from_url, to_url, require_auth, enabled, priority, ziti_enabled, ziti_service_name, browzer_enabled)
VALUES (
    'a0000000-0000-0000-0000-000000000100',
    'demo-app',
    'OpenIDX Demo App - demonstrates authenticated user identity via forward-auth and BrowZer zero-trust access',
    'http://browzer.localtest.me/demo',
    'http://demo-app:8090',
    true,
    true,
    10,
    true,
    'demo-app-zt',
    true
) ON CONFLICT (id) DO NOTHING;

-- GUACAMOLE - BrowZer route for path-based Guacamole access
INSERT INTO proxy_routes (id, name, description, from_url, to_url, require_auth, enabled, priority, ziti_enabled, ziti_service_name, browzer_enabled)
VALUES (
    'a0000000-0000-0000-0000-000000000101',
    'guacamole',
    'Apache Guacamole remote desktop via BrowZer zero-trust access',
    'http://browzer.localtest.me/guacamole',
    'http://guacamole:8080',
    true,
    true,
    10,
    true,
    'guacamole-zt',
    true
) ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- APP PUBLISHING - Auto-discover and publish web app paths as proxy routes
-- ============================================================================

CREATE TABLE IF NOT EXISTS published_apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    target_url VARCHAR(500) NOT NULL,
    spec_url VARCHAR(500),
    status VARCHAR(50) DEFAULT 'pending',
    discovery_started_at TIMESTAMPTZ,
    discovery_completed_at TIMESTAMPTZ,
    discovery_error TEXT,
    discovery_strategies JSONB DEFAULT '[]',
    total_paths_discovered INTEGER DEFAULT 0,
    total_paths_published INTEGER DEFAULT 0,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_published_apps_status ON published_apps(status);

CREATE TABLE IF NOT EXISTS discovered_paths (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES published_apps(id) ON DELETE CASCADE,
    path VARCHAR(500) NOT NULL,
    http_methods JSONB DEFAULT '["GET"]',
    classification VARCHAR(50) NOT NULL,
    classification_source VARCHAR(50) DEFAULT 'auto',
    discovery_strategy VARCHAR(50),
    suggested_policy TEXT,
    require_auth BOOLEAN DEFAULT true,
    allowed_roles JSONB DEFAULT '[]',
    require_device_trust BOOLEAN DEFAULT false,
    published BOOLEAN DEFAULT false,
    route_id UUID REFERENCES proxy_routes(id) ON DELETE SET NULL,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(app_id, path)
);

CREATE INDEX IF NOT EXISTS idx_discovered_paths_app ON discovered_paths(app_id);
CREATE INDEX IF NOT EXISTS idx_discovered_paths_classification ON discovered_paths(classification);

-- ============================================================================
-- Certification Campaigns (Governance)
-- ============================================================================

CREATE TABLE IF NOT EXISTS certification_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    schedule VARCHAR(50) NOT NULL,
    reviewer_strategy VARCHAR(50) NOT NULL,
    reviewer_id UUID,
    reviewer_role VARCHAR(100),
    auto_revoke BOOLEAN DEFAULT false,
    grace_period_days INTEGER DEFAULT 7,
    duration_days INTEGER DEFAULT 30,
    status VARCHAR(50) DEFAULT 'active',
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_certification_campaigns_status ON certification_campaigns(status);
CREATE INDEX IF NOT EXISTS idx_certification_campaigns_next_run ON certification_campaigns(next_run_at);

CREATE TABLE IF NOT EXISTS campaign_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id UUID NOT NULL REFERENCES certification_campaigns(id) ON DELETE CASCADE,
    review_id UUID REFERENCES access_reviews(id),
    status VARCHAR(50) DEFAULT 'in_progress',
    started_at TIMESTAMPTZ DEFAULT NOW(),
    deadline TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    total_items INTEGER DEFAULT 0,
    reviewed_items INTEGER DEFAULT 0,
    auto_revoked_items INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_campaign_runs_campaign ON campaign_runs(campaign_id);
CREATE INDEX IF NOT EXISTS idx_campaign_runs_status ON campaign_runs(status);

-- ============================================================================
-- User Lifecycle Workflows (Identity + Provisioning)
-- ============================================================================

CREATE TABLE IF NOT EXISTS lifecycle_workflows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    event_type VARCHAR(50) NOT NULL,
    trigger_type VARCHAR(50) DEFAULT 'manual',
    actions JSONB NOT NULL DEFAULT '[]',
    conditions JSONB DEFAULT '{}',
    require_approval BOOLEAN DEFAULT false,
    approval_policy_id UUID,
    enabled BOOLEAN DEFAULT true,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lifecycle_workflows_event_type ON lifecycle_workflows(event_type);
CREATE INDEX IF NOT EXISTS idx_lifecycle_workflows_enabled ON lifecycle_workflows(enabled);

CREATE TABLE IF NOT EXISTS lifecycle_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL REFERENCES lifecycle_workflows(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    triggered_by UUID,
    trigger_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    actions_completed JSONB DEFAULT '[]',
    actions_failed JSONB DEFAULT '[]',
    error TEXT,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lifecycle_executions_workflow ON lifecycle_executions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_lifecycle_executions_user ON lifecycle_executions(user_id);
CREATE INDEX IF NOT EXISTS idx_lifecycle_executions_status ON lifecycle_executions(status);

-- ============================================================================
-- Entitlement Metadata (Catalog)
-- ============================================================================

CREATE TABLE IF NOT EXISTS entitlement_metadata (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entitlement_type VARCHAR(50) NOT NULL,
    entitlement_id UUID NOT NULL,
    risk_level VARCHAR(20) DEFAULT 'low',
    owner_id UUID,
    description TEXT,
    tags JSONB DEFAULT '[]',
    review_required BOOLEAN DEFAULT false,
    last_reviewed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(entitlement_type, entitlement_id)
);

CREATE INDEX IF NOT EXISTS idx_entitlement_metadata_type ON entitlement_metadata(entitlement_type);
CREATE INDEX IF NOT EXISTS idx_entitlement_metadata_risk ON entitlement_metadata(risk_level);

-- ============================================================================
-- Phase 8: Advanced RBAC & Delegation
-- ============================================================================

-- Additional permissions for fine-grained access control
INSERT INTO permissions (id, name, description, resource, action) VALUES
('a0000000-0000-0000-0000-000000000010', 'Read Groups', 'View groups', 'groups', 'read'),
('a0000000-0000-0000-0000-000000000011', 'Write Groups', 'Create and edit groups', 'groups', 'write'),
('a0000000-0000-0000-0000-000000000012', 'Delete Groups', 'Delete groups', 'groups', 'delete'),
('a0000000-0000-0000-0000-000000000013', 'Read Policies', 'View governance policies', 'policies', 'read'),
('a0000000-0000-0000-0000-000000000014', 'Write Policies', 'Create and edit governance policies', 'policies', 'write'),
('a0000000-0000-0000-0000-000000000015', 'Read Directories', 'View directory integrations', 'directories', 'read'),
('a0000000-0000-0000-0000-000000000016', 'Write Directories', 'Manage directory integrations', 'directories', 'write'),
('a0000000-0000-0000-0000-000000000017', 'Read Sessions', 'View active sessions', 'sessions', 'read'),
('a0000000-0000-0000-0000-000000000018', 'Write Sessions', 'Terminate sessions', 'sessions', 'write'),
('a0000000-0000-0000-0000-000000000019', 'Delete Roles', 'Delete roles', 'roles', 'delete'),
('a0000000-0000-0000-0000-000000000020', 'Read Settings', 'View system settings', 'settings', 'read'),
('a0000000-0000-0000-0000-000000000021', 'Manage Delegations', 'Create and manage admin delegations', 'delegations', 'write')
ON CONFLICT (resource, action) DO NOTHING;

-- Seed role_permissions for built-in roles
-- Admin gets ALL permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT '60000000-0000-0000-0000-000000000001', id FROM permissions
ON CONFLICT DO NOTHING;

-- Manager: read/write users, read/write groups, read roles, read applications, read audit, read sessions
INSERT INTO role_permissions (role_id, permission_id) VALUES
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000001'),
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000002'),
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000004'),
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000006'),
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000008'),
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000010'),
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000011'),
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000017')
ON CONFLICT DO NOTHING;

-- Auditor: read users, read roles, read applications, read audit, read policies, read sessions, read settings
INSERT INTO role_permissions (role_id, permission_id) VALUES
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000001'),
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000004'),
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000006'),
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000008'),
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000010'),
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000013'),
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000017'),
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000020')
ON CONFLICT DO NOTHING;

-- User: read users, read roles, read applications, read groups
INSERT INTO role_permissions (role_id, permission_id) VALUES
('60000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001'),
('60000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000004'),
('60000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000006'),
('60000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000010')
ON CONFLICT DO NOTHING;

-- Developer: read users, read roles, read applications, read groups, read directories
INSERT INTO role_permissions (role_id, permission_id) VALUES
('60000000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000001'),
('60000000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000004'),
('60000000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000006'),
('60000000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000010'),
('60000000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000015')
ON CONFLICT DO NOTHING;

-- Time-bound role assignments
ALTER TABLE user_roles ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE user_roles ADD COLUMN IF NOT EXISTS expiry_notified BOOLEAN DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_user_roles_expires ON user_roles(expires_at) WHERE expires_at IS NOT NULL;

-- Admin Delegations
CREATE TABLE IF NOT EXISTS admin_delegations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    delegate_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    delegated_by UUID NOT NULL REFERENCES users(id),
    scope_type VARCHAR(50) NOT NULL,
    scope_id UUID NOT NULL,
    permissions JSONB NOT NULL DEFAULT '[]',
    enabled BOOLEAN DEFAULT true,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_delegations_delegate ON admin_delegations(delegate_id);
CREATE INDEX IF NOT EXISTS idx_admin_delegations_scope ON admin_delegations(scope_type, scope_id);
CREATE INDEX IF NOT EXISTS idx_admin_delegations_expires ON admin_delegations(expires_at);

-- ABAC Policies
CREATE TABLE IF NOT EXISTS abac_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID,
    conditions JSONB NOT NULL DEFAULT '[]',
    effect VARCHAR(10) NOT NULL DEFAULT 'deny',
    priority INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_abac_policies_resource ON abac_policies(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_abac_policies_enabled ON abac_policies(enabled);

-- ============================================================================
-- PHASE 9: SESSION MANAGEMENT & SSO
-- ============================================================================

-- Link refresh tokens to sessions for revocation propagation
ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS session_id UUID REFERENCES sessions(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_session_id ON oauth_refresh_tokens(session_id);

-- Partial index for fast active session counts per user
CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON sessions(user_id) WHERE (revoked IS NULL OR revoked = false) AND expires_at > NOW();

-- Session policy fields on per-application SSO settings
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS idle_timeout INTEGER DEFAULT 1800;
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS absolute_timeout INTEGER DEFAULT 86400;
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS remember_me_duration INTEGER DEFAULT 2592000;
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS reauth_interval INTEGER DEFAULT 0;
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS bind_ip BOOLEAN DEFAULT false;
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS force_logout_on_password_change BOOLEAN DEFAULT true;
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS max_concurrent_sessions INTEGER DEFAULT 0;
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS concurrent_session_strategy VARCHAR(20) DEFAULT 'deny_new';

-- Back-channel and front-channel logout URIs for federated logout
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS back_channel_logout_uri VARCHAR(500);
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS front_channel_logout_uri VARCHAR(500);

-- Phase 10: Self-Service Portal & Passwordless UX
-- Indexes for consent management queries (refresh tokens by user+client)
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_user_client ON oauth_refresh_tokens(user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_user_client ON oauth_access_tokens(user_id, client_id);

-- ============================================================================
-- Phase 11: Enterprise Integrations
-- ============================================================================

-- SAML Service Provider registrations (for IdP role)
CREATE TABLE IF NOT EXISTS saml_service_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    entity_id VARCHAR(500) UNIQUE NOT NULL,
    acs_url VARCHAR(500) NOT NULL,
    slo_url VARCHAR(500),
    certificate TEXT,
    name_id_format VARCHAR(255) DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    attribute_mappings JSONB DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_saml_sp_entity_id ON saml_service_providers(entity_id);

-- Social login account links
CREATE TABLE IF NOT EXISTS social_account_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    provider_id UUID REFERENCES identity_providers(id) ON DELETE CASCADE,
    external_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    profile_data JSONB,
    linked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(provider_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_social_links_user ON social_account_links(user_id);
CREATE INDEX IF NOT EXISTS idx_social_links_provider ON social_account_links(provider_id, external_id);

-- Webhook delivery statistics cache
CREATE TABLE IF NOT EXISTS webhook_delivery_stats (
    subscription_id VARCHAR(255) PRIMARY KEY,
    total_deliveries INT DEFAULT 0,
    successful_deliveries INT DEFAULT 0,
    failed_deliveries INT DEFAULT 0,
    avg_response_time_ms INT DEFAULT 0,
    last_delivery_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Phase 12: Analytics & Insights
-- ============================================================================

-- User risk baselines
CREATE TABLE IF NOT EXISTS user_risk_baselines (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    typical_login_hours JSONB DEFAULT '[]',
    typical_countries JSONB DEFAULT '[]',
    typical_ips JSONB DEFAULT '[]',
    avg_risk_score FLOAT DEFAULT 0,
    login_count INT DEFAULT 0,
    last_updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- API usage metrics
CREATE TABLE IF NOT EXISTS api_usage_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    service VARCHAR(100) NOT NULL,
    status_code INT,
    count INT DEFAULT 1,
    avg_latency_ms FLOAT DEFAULT 0,
    hour TIMESTAMP WITH TIME ZONE NOT NULL,
    UNIQUE(endpoint, method, service, status_code, hour)
);

CREATE INDEX IF NOT EXISTS idx_api_metrics_hour ON api_usage_metrics(hour);
CREATE INDEX IF NOT EXISTS idx_api_metrics_endpoint ON api_usage_metrics(endpoint, hour);

-- Feature adoption tracking
CREATE TABLE IF NOT EXISTS feature_adoption (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feature_name VARCHAR(100) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    first_used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    usage_count INT DEFAULT 1,
    UNIQUE(feature_name, user_id)
);

CREATE INDEX IF NOT EXISTS idx_feature_adoption_feature ON feature_adoption(feature_name);

-- ============================================================================
-- Phase 13: Developer Experience
-- ============================================================================

-- Developer settings
CREATE TABLE IF NOT EXISTS developer_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value JSONB NOT NULL,
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- OAuth playground sessions
CREATE TABLE IF NOT EXISTS oauth_playground_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    state VARCHAR(255),
    code_verifier VARCHAR(255),
    code_challenge VARCHAR(255),
    redirect_uri VARCHAR(500),
    scopes TEXT[],
    status VARCHAR(50) DEFAULT 'initiated',
    authorization_code VARCHAR(255),
    access_token TEXT,
    id_token TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() + INTERVAL '30 minutes'
);

CREATE INDEX IF NOT EXISTS idx_playground_user ON oauth_playground_sessions(user_id);

-- ============================================================================
-- Phase 14: Operational Excellence
-- ============================================================================

-- Admin operation audit trail
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID REFERENCES users(id),
    actor_email VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(100) NOT NULL,
    target_id VARCHAR(255),
    target_name VARCHAR(255),
    before_state JSONB,
    after_state JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    request_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_actor ON admin_audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_action ON admin_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_admin_audit_target ON admin_audit_log(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_time ON admin_audit_log(created_at DESC);

-- Health check history
CREATE TABLE IF NOT EXISTS health_check_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name VARCHAR(100) NOT NULL,
    dependency_name VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL,
    latency_ms INT,
    details JSONB,
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_health_history_service ON health_check_history(service_name, checked_at DESC);

-- Error catalog
CREATE TABLE IF NOT EXISTS error_catalog (
    code VARCHAR(100) PRIMARY KEY,
    http_status INT NOT NULL,
    category VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    resolution_hint TEXT,
    documentation_url VARCHAR(500),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Phase 15: AI & Intelligence
-- ============================================================================

-- AI Agent Identity Management
CREATE TABLE IF NOT EXISTS ai_agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    agent_type VARCHAR(50) NOT NULL DEFAULT 'assistant',
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    capabilities JSONB DEFAULT '[]',
    trust_level VARCHAR(20) NOT NULL DEFAULT 'low',
    rate_limits JSONB DEFAULT '{"requests_per_minute": 60, "requests_per_hour": 1000}',
    allowed_scopes TEXT[] DEFAULT '{}',
    ip_allowlist TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    last_active_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_agents_status ON ai_agents(status);
CREATE INDEX IF NOT EXISTS idx_ai_agents_owner ON ai_agents(owner_id);
CREATE INDEX IF NOT EXISTS idx_ai_agents_type ON ai_agents(agent_type);

CREATE TABLE IF NOT EXISTS ai_agent_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    credential_type VARCHAR(50) NOT NULL DEFAULT 'api_key',
    key_prefix VARCHAR(12),
    key_hash VARCHAR(128) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    rotated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_agent_creds_agent ON ai_agent_credentials(agent_id);
CREATE INDEX IF NOT EXISTS idx_ai_agent_creds_hash ON ai_agent_credentials(key_hash);

CREATE TABLE IF NOT EXISTS ai_agent_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255),
    actions TEXT[] NOT NULL DEFAULT '{}',
    conditions JSONB DEFAULT '{}',
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_agent_perms_agent ON ai_agent_permissions(agent_id);
CREATE INDEX IF NOT EXISTS idx_ai_agent_perms_resource ON ai_agent_permissions(resource_type, resource_id);

CREATE TABLE IF NOT EXISTS ai_agent_activity (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    action VARCHAR(255) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    outcome VARCHAR(50) NOT NULL DEFAULT 'success',
    details JSONB DEFAULT '{}',
    ip_address VARCHAR(45),
    duration_ms INT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_agent_activity_agent ON ai_agent_activity(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_agent_activity_time ON ai_agent_activity(created_at DESC);

-- Identity Security Posture Management (ISPM)
CREATE TABLE IF NOT EXISTS ispm_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,
    check_type VARCHAR(100) NOT NULL UNIQUE,
    enabled BOOLEAN DEFAULT true,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    thresholds JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ispm_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID REFERENCES ispm_rules(id) ON DELETE SET NULL,
    check_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    category VARCHAR(50) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    affected_entity_type VARCHAR(100),
    affected_entity_id VARCHAR(255),
    affected_entity_name VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    remediation_action VARCHAR(100),
    remediation_details JSONB DEFAULT '{}',
    dismissed_by UUID REFERENCES users(id),
    dismissed_reason TEXT,
    remediated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ispm_findings_status ON ispm_findings(status);
CREATE INDEX IF NOT EXISTS idx_ispm_findings_severity ON ispm_findings(severity);
CREATE INDEX IF NOT EXISTS idx_ispm_findings_category ON ispm_findings(category);
CREATE INDEX IF NOT EXISTS idx_ispm_findings_entity ON ispm_findings(affected_entity_type, affected_entity_id);
CREATE INDEX IF NOT EXISTS idx_ispm_findings_created ON ispm_findings(created_at DESC);

CREATE TABLE IF NOT EXISTS ispm_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    overall_score INT NOT NULL,
    category_scores JSONB NOT NULL DEFAULT '{}',
    total_findings INT DEFAULT 0,
    critical_findings INT DEFAULT 0,
    high_findings INT DEFAULT 0,
    medium_findings INT DEFAULT 0,
    low_findings INT DEFAULT 0,
    snapshot_date DATE NOT NULL DEFAULT CURRENT_DATE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ispm_scores_date ON ispm_scores(snapshot_date);

-- AI-Powered Access Recommendations
CREATE TABLE IF NOT EXISTS ai_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recommendation_type VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    impact VARCHAR(20) NOT NULL DEFAULT 'medium',
    effort VARCHAR(20) NOT NULL DEFAULT 'medium',
    affected_entities JSONB DEFAULT '[]',
    suggested_action JSONB DEFAULT '{}',
    supporting_data JSONB DEFAULT '{}',
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    dismissed_reason TEXT,
    applied_at TIMESTAMP WITH TIME ZONE,
    applied_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_recommendations_status ON ai_recommendations(status);
CREATE INDEX IF NOT EXISTS idx_ai_recommendations_category ON ai_recommendations(category);
CREATE INDEX IF NOT EXISTS idx_ai_recommendations_impact ON ai_recommendations(impact);
CREATE INDEX IF NOT EXISTS idx_ai_recommendations_created ON ai_recommendations(created_at DESC);

CREATE TABLE IF NOT EXISTS recommendation_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recommendation_id UUID NOT NULL REFERENCES ai_recommendations(id) ON DELETE CASCADE,
    previous_status VARCHAR(50),
    new_status VARCHAR(50) NOT NULL,
    changed_by UUID REFERENCES users(id),
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_recommendation_history_rec ON recommendation_history(recommendation_id, created_at DESC);

-- Seed data: ISPM rules
INSERT INTO ispm_rules (id, name, description, category, check_type, severity, thresholds) VALUES
('a0000000-0000-0000-0000-000000000001', 'MFA Adoption Check', 'Detects users without MFA enabled', 'authentication', 'mfa_adoption', 'high', '{"min_adoption_pct": 90}'),
('a0000000-0000-0000-0000-000000000002', 'Stale Account Detection', 'Finds users not logged in for extended period', 'accounts', 'stale_accounts', 'medium', '{"inactive_days": 90}'),
('a0000000-0000-0000-0000-000000000003', 'Over-Privileged Users', 'Detects admin users who rarely use admin features', 'authorization', 'over_privileged', 'high', '{"unused_days": 30}'),
('a0000000-0000-0000-0000-000000000004', 'Weak Password Detection', 'Finds accounts with passwords older than policy', 'authentication', 'weak_passwords', 'medium', '{"max_age_days": 90}'),
('a0000000-0000-0000-0000-000000000005', 'Orphaned Permissions', 'Permissions for disabled users or deleted groups', 'authorization', 'orphaned_permissions', 'medium', '{}'),
('a0000000-0000-0000-0000-000000000006', 'Shadow Admin Detection', 'Users with admin-equivalent access without admin role', 'authorization', 'shadow_admin', 'critical', '{}'),
('a0000000-0000-0000-0000-000000000007', 'Shared Account Detection', 'Accounts with concurrent sessions from different IPs', 'accounts', 'shared_accounts', 'high', '{"max_concurrent_ips": 2}'),
('a0000000-0000-0000-0000-000000000008', 'Dormant Permissions', 'Granted permissions unused for extended period', 'authorization', 'dormant_permissions', 'low', '{"unused_days": 30}'),
('a0000000-0000-0000-0000-000000000009', 'Policy Gap Detection', 'Applications without conditional access policies', 'compliance', 'policy_gaps', 'medium', '{}'),
('a0000000-0000-0000-0000-00000000000a', 'MFA Bypass Risk', 'Users with only weak MFA methods (SMS/email)', 'authentication', 'mfa_bypass_risk', 'high', '{}')
ON CONFLICT DO NOTHING;

-- Seed data: Sample AI agents
INSERT INTO ai_agents (id, name, description, agent_type, status, capabilities, trust_level, allowed_scopes) VALUES
('b0000000-0000-0000-0000-000000000001', 'CI/CD Pipeline Bot', 'Automated deployment and testing agent', 'workflow', 'active', '["deploy", "test", "scan"]'::jsonb, 'medium', '{"read:users", "read:applications", "write:deployments"}'),
('b0000000-0000-0000-0000-000000000002', 'Analytics Assistant', 'Data analysis and reporting agent', 'assistant', 'active', '["query", "report", "alert"]'::jsonb, 'low', '{"read:analytics", "read:audit-logs"}'),
('b0000000-0000-0000-0000-000000000003', 'Provisioning Workflow', 'Automated user provisioning agent', 'autonomous', 'active', '["provision", "deprovision", "sync"]'::jsonb, 'high', '{"read:users", "write:users", "read:groups", "write:groups"}')
ON CONFLICT (id) DO NOTHING;
