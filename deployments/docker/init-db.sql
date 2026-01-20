-- ============================================================================
-- OpenIDX Database Schema - Complete
-- ============================================================================
-- This file creates all tables and seed data for OpenIDX
-- Run automatically by PostgreSQL on container initialization
-- ============================================================================

-- Create separate database for Keycloak
CREATE DATABASE keycloak;
GRANT ALL PRIVILEGES ON DATABASE keycloak TO openidx;

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

-- Insert default admin user (password: admin123)
-- bcrypt hash generated with cost 10 for "admin123"
INSERT INTO users (id, username, email, password_hash, first_name, last_name, enabled, email_verified)
VALUES ('00000000-0000-0000-0000-000000000001', 'admin', 'admin@openidx.local', '$2a$10$u1/0j1YwyqSHvwkb3m/lVexQyAh4oKFb47ojAhSk.BGk/LBt53Lfq', 'System', 'Admin', true, true)
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

