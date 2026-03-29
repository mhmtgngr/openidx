//go:build !dev

package migrations

// SQL content for migrations - embedded as strings
// This file is auto-generated from the migrations directory

const (
	// Migration 001: Initial Schema
	initialSchemaUp = `-- Migration 001: Initial Schema
-- Description: Core tables for users, groups, and roles

-- Users table
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

-- Groups table
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

-- Group memberships
CREATE TABLE IF NOT EXISTS group_memberships (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, group_id)
);

-- Roles table
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
);`

	initialSchemaDown = `-- Rollback 001: Initial Schema
DROP TABLE IF EXISTS user_roles CASCADE;
DROP TABLE IF EXISTS composite_roles CASCADE;
DROP TABLE IF EXISTS roles CASCADE;
DROP TABLE IF EXISTS group_memberships CASCADE;
DROP TABLE IF EXISTS groups CASCADE;
DROP TABLE IF EXISTS users CASCADE;`

	// Migration 002: OAuth 2.0 / OIDC
	oauthOIDCUp = `-- Migration 002: OAuth 2.0 / OIDC Tables
CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret VARCHAR(255),
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
);`

	oauthOIDCDown = `-- Rollback 002: OAuth 2.0 / OIDC Tables
DROP TABLE IF EXISTS oauth_refresh_tokens CASCADE;
DROP TABLE IF EXISTS oauth_access_tokens CASCADE;
DROP TABLE IF EXISTS oauth_authorization_codes CASCADE;
DROP TABLE IF EXISTS oauth_clients CASCADE;`

	// Migration 003: SCIM
	scimUp = `-- Migration 003: SCIM 2.0 Provisioning Tables
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
);`

	scimDown = `-- Rollback 003: SCIM 2.0 Provisioning Tables
DROP TABLE IF EXISTS scim_groups CASCADE;
DROP TABLE IF EXISTS scim_users CASCADE;`

	// Migration 004: Governance
	governanceUp = `-- Migration 004: Governance Tables (Access Reviews & Policies)
CREATE TABLE IF NOT EXISTS access_reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    reviewer_id UUID,
    start_date TIMESTAMP WITH TIME ZONE NOT NULL,
    end_date TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS review_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID REFERENCES access_reviews(id) ON DELETE CASCADE,
    user_id UUID,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    resource_name VARCHAR(255),
    decision VARCHAR(50) DEFAULT 'pending',
    decided_by UUID,
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
);`

	governanceDown = `-- Rollback 004: Governance Tables
DROP TABLE IF EXISTS policy_rules CASCADE;
DROP TABLE IF EXISTS policies CASCADE;
DROP TABLE IF EXISTS review_items CASCADE;
DROP TABLE IF EXISTS access_reviews CASCADE;`

	// Migration 005: MFA
	mfaUp = `-- Migration 005: Multi-Factor Authentication Tables
CREATE TABLE IF NOT EXISTS mfa_totp (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    secret VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT false,
    enrolled_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    used BOOLEAN DEFAULT false,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

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
    user_id UUID NOT NULL,
    policy_id UUID NOT NULL,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, policy_id)
);

CREATE TABLE IF NOT EXISTS mfa_webauthn (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
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

CREATE TABLE IF NOT EXISTS mfa_push_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
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
    user_id UUID NOT NULL,
    device_id UUID NOT NULL,
    challenge_code VARCHAR(10) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    session_info JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    responded_at TIMESTAMP WITH TIME ZONE,
    ip_address VARCHAR(45),
    user_agent TEXT,
    location VARCHAR(255)
);`

	mfaDown = `-- Rollback 005: Multi-Factor Authentication Tables
DROP TABLE IF EXISTS mfa_push_challenges CASCADE;
DROP TABLE IF EXISTS mfa_push_devices CASCADE;
DROP TABLE IF EXISTS mfa_webauthn CASCADE;
DROP TABLE IF EXISTS user_mfa_policies CASCADE;
DROP TABLE IF EXISTS mfa_policies CASCADE;
DROP TABLE IF EXISTS mfa_backup_codes CASCADE;
DROP TABLE IF EXISTS mfa_totp CASCADE;`

	// Migration 006: Sessions
	sessionsUp = `-- Migration 006: Session Management Tables
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    session_token VARCHAR(500) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);`

	sessionsDown = `-- Rollback 006: Session Management Tables
DROP TABLE IF EXISTS user_sessions CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;`

	// Migration 007: Applications
	applicationsUp = `-- Migration 007: Application Management Tables
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

CREATE TABLE IF NOT EXISTS application_sso_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    enabled BOOLEAN DEFAULT true,
    use_refresh_tokens BOOLEAN DEFAULT true,
    access_token_lifetime INTEGER DEFAULT 3600,
    refresh_token_lifetime INTEGER DEFAULT 86400,
    require_consent BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(application_id)
);`

	applicationsDown = `-- Rollback 007: Application Management Tables
DROP TABLE IF EXISTS application_sso_settings CASCADE;
DROP TABLE IF EXISTS applications CASCADE;`

	// Migration 008: Audit and Compliance
	auditComplianceUp = `-- Migration 008: Audit and Compliance Tables
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
    generated_by UUID,
    summary JSONB DEFAULT '{}',
    findings JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);`

	auditComplianceDown = `-- Rollback 008: Audit and Compliance Tables
DROP TABLE IF EXISTS compliance_reports CASCADE;
DROP TABLE IF EXISTS audit_events CASCADE;`

	// Migration 009: Indexes
	indexesUp = `-- Migration 009: Performance Indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_groups_name ON groups(name);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_client_id ON oauth_authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_user_id ON oauth_authorization_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_client_id ON oauth_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_user_id ON oauth_access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_client_id ON oauth_refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_scim_users_external_id ON scim_users(external_id);
CREATE INDEX IF NOT EXISTS idx_scim_groups_external_id ON scim_groups(external_id);
CREATE INDEX IF NOT EXISTS idx_access_reviews_status ON access_reviews(status);
CREATE INDEX IF NOT EXISTS idx_review_items_review_id ON review_items(review_id);
CREATE INDEX IF NOT EXISTS idx_review_items_user_id ON review_items(user_id);
CREATE INDEX IF NOT EXISTS idx_policies_type ON policies(type);
CREATE INDEX IF NOT EXISTS idx_webauthn_user_id ON mfa_webauthn(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credential_id ON mfa_webauthn(credential_id);
CREATE INDEX IF NOT EXISTS idx_push_devices_user_id ON mfa_push_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_push_devices_token ON mfa_push_devices(device_token);
CREATE INDEX IF NOT EXISTS idx_push_challenges_user_id ON mfa_push_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_push_challenges_status ON mfa_push_challenges(status);
CREATE INDEX IF NOT EXISTS idx_push_challenges_expires_at ON mfa_push_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_applications_client_id ON applications(client_id);
CREATE INDEX IF NOT EXISTS idx_application_sso_settings_application_id ON application_sso_settings(application_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_category ON audit_events(category);
CREATE INDEX IF NOT EXISTS idx_audit_events_outcome ON audit_events(outcome);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_type ON compliance_reports(type);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_status ON compliance_reports(status);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_generated_at ON compliance_reports(generated_at);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_framework ON compliance_reports(framework);`

	indexesDown = `-- Rollback 009: Performance Indexes
DROP INDEX IF EXISTS idx_compliance_reports_framework;
DROP INDEX IF EXISTS idx_compliance_reports_generated_at;
DROP INDEX IF EXISTS idx_compliance_reports_status;
DROP INDEX IF EXISTS idx_compliance_reports_type;
DROP INDEX IF EXISTS idx_audit_events_outcome;
DROP INDEX IF EXISTS idx_audit_events_category;
DROP INDEX IF EXISTS idx_audit_events_type;
DROP INDEX IF EXISTS idx_audit_events_actor;
DROP INDEX IF EXISTS idx_audit_events_timestamp;
DROP INDEX IF EXISTS idx_application_sso_settings_application_id;
DROP INDEX IF EXISTS idx_applications_client_id;
DROP INDEX IF EXISTS idx_user_sessions_token;
DROP INDEX IF EXISTS idx_user_sessions_user_id;
DROP INDEX IF EXISTS idx_sessions_expires_at;
DROP INDEX IF EXISTS idx_sessions_user_id;
DROP INDEX IF EXISTS idx_push_challenges_expires_at;
DROP INDEX IF EXISTS idx_push_challenges_status;
DROP INDEX IF EXISTS idx_push_challenges_user_id;
DROP INDEX IF EXISTS idx_push_devices_token;
DROP INDEX IF EXISTS idx_push_devices_user_id;
DROP INDEX IF EXISTS idx_webauthn_credential_id;
DROP INDEX IF EXISTS idx_webauthn_user_id;
DROP INDEX IF EXISTS idx_policies_type;
DROP INDEX IF EXISTS idx_review_items_user_id;
DROP INDEX IF EXISTS idx_review_items_review_id;
DROP INDEX IF EXISTS idx_access_reviews_status;
DROP INDEX IF EXISTS idx_scim_groups_external_id;
DROP INDEX IF EXISTS idx_scim_users_external_id;
DROP INDEX IF EXISTS idx_oauth_refresh_tokens_client_id;
DROP INDEX IF EXISTS idx_oauth_access_tokens_user_id;
DROP INDEX IF EXISTS idx_oauth_access_tokens_client_id;
DROP INDEX IF EXISTS idx_oauth_authorization_codes_user_id;
DROP INDEX IF EXISTS idx_oauth_authorization_codes_client_id;
DROP INDEX IF EXISTS idx_oauth_clients_client_id;
DROP INDEX IF EXISTS idx_user_roles_role_id;
DROP INDEX IF EXISTS idx_user_roles_user_id;
DROP INDEX IF EXISTS idx_groups_name;
DROP INDEX IF EXISTS idx_users_username;
DROP INDEX IF EXISTS idx_users_email;`

	// Migration 010: Seed Data
	seedDataUp = `-- Migration 010: Initial Seed Data
INSERT INTO users (id, username, email, password_hash, first_name, last_name, enabled, email_verified)
VALUES ('00000000-0000-0000-0000-000000000001', 'admin', 'admin@openidx.local', '$2b$12$oX..0F6dHbNip8vASE5VdOgXiBfyqRZ768PU5vArjeOMxG5MGEEdq', 'System', 'Admin', true, true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO roles (id, name, description, is_composite) VALUES
('60000000-0000-0000-0000-000000000001', 'admin', 'System administrator with full access', false),
('60000000-0000-0000-0000-000000000002', 'user', 'Standard user role', false),
('60000000-0000-0000-0000-000000000003', 'manager', 'Manager role with additional permissions', false),
('60000000-0000-0000-0000-000000000004', 'auditor', 'Audit and compliance role', false),
('60000000-0000-0000-0000-000000000005', 'developer', 'Software developer role', false)
ON CONFLICT (id) DO NOTHING;

INSERT INTO users (id, username, email, first_name, last_name, enabled, email_verified) VALUES
('00000000-0000-0000-0000-000000000002', 'jsmith', 'john.smith@example.com', 'John', 'Smith', true, true),
('00000000-0000-0000-0000-000000000003', 'jdoe', 'jane.doe@example.com', 'Jane', 'Doe', true, true),
('00000000-0000-0000-0000-000000000004', 'bwilson', 'bob.wilson@example.com', 'Bob', 'Wilson', true, false),
('00000000-0000-0000-0000-000000000005', 'amartin', 'alice.martin@example.com', 'Alice', 'Martin', false, true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO groups (id, name, description, parent_id) VALUES
('10000000-0000-0000-0000-000000000001', 'Administrators', 'System administrators with full access', NULL),
('10000000-0000-0000-0000-000000000002', 'Developers', 'Software development team', NULL),
('10000000-0000-0000-0000-000000000003', 'DevOps', 'DevOps engineering team', '10000000-0000-0000-0000-000000000002'),
('10000000-0000-0000-0000-000000000004', 'QA Team', 'Quality assurance team', '10000000-0000-0000-0000-000000000002'),
('10000000-0000-0000-0000-000000000005', 'Finance', 'Finance department', NULL),
('10000000-0000-0000-0000-000000000006', 'HR', 'Human resources department', NULL)
ON CONFLICT (id) DO NOTHING;

INSERT INTO group_memberships (user_id, group_id) VALUES
('00000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000001'),
('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000002'),
('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000003'),
('00000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000002'),
('00000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000004'),
('00000000-0000-0000-0000-000000000004', '10000000-0000-0000-0000-000000000005'),
('00000000-0000-0000-0000-000000000005', '10000000-0000-0000-0000-000000000006')
ON CONFLICT DO NOTHING;

INSERT INTO applications (id, client_id, name, description, type, protocol, base_url, redirect_uris, enabled) VALUES
('40000000-0000-0000-0000-000000000001', 'admin-console', 'Admin Console', 'OpenIDX Administration Console', 'web', 'openid-connect', 'http://localhost:3000', ARRAY['http://localhost:3000/callback'], true),
('40000000-0000-0000-0000-000000000002', 'sample-spa', 'Sample SPA', 'Sample Single Page Application', 'spa', 'openid-connect', 'http://localhost:4000', ARRAY['http://localhost:4000/callback'], true),
('40000000-0000-0000-0000-000000000003', 'api-service', 'API Service', 'Backend API Service', 'service', 'openid-connect', NULL, NULL, true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_clients (id, client_id, client_secret, name, description, type, redirect_uris, grant_types, response_types, scopes, pkce_required, allow_refresh_token, access_token_lifetime, refresh_token_lifetime) VALUES
('80000000-0000-0000-0000-000000000001', 'admin-console', NULL, 'Admin Console', 'OpenIDX Administration Console', 'public',
 '["http://localhost:3000/login", "http://localhost:3000/callback"]'::jsonb,
 '["authorization_code", "refresh_token"]'::jsonb,
 '["code"]'::jsonb,
 '["openid", "profile", "email", "offline_access"]'::jsonb,
 true, true, 3600, 86400),
('80000000-0000-0000-0000-000000000002', 'api-service', 'api-service-secret', 'API Service', 'Backend API Service', 'confidential',
 '[]'::jsonb,
 '["client_credentials"]'::jsonb,
 '[]'::jsonb,
 '["openid", "api"]'::jsonb,
 false, false, 3600, 0)
ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_clients (id, client_id, client_secret, name, description, type, redirect_uris, grant_types, response_types, scopes, pkce_required, allow_refresh_token, access_token_lifetime, refresh_token_lifetime) VALUES
('80000000-0000-0000-0000-000000000003', 'test-client', 'test-secret', 'Test Client', 'Client for testing authentication flow', 'confidential',
 '[]'::jsonb,
 '["authorization_code", "refresh_token", "client_credentials"]'::jsonb,
 '["code"]'::jsonb,
 '["openid", "profile", "email"]'::jsonb,
 false, true, 3600, 86400)
ON CONFLICT (id) DO NOTHING;

INSERT INTO application_sso_settings (id, application_id, enabled, use_refresh_tokens, access_token_lifetime, refresh_token_lifetime, require_consent) VALUES
('50000000-0000-0000-0000-000000000001', '40000000-0000-0000-0000-000000000001', true, true, 3600, 86400, false),
('50000000-0000-0000-0000-000000000002', '40000000-0000-0000-0000-000000000002', true, true, 1800, 43200, true),
('50000000-0000-0000-0000-000000000003', '40000000-0000-0000-0000-000000000003', true, false, 3600, 0, false)
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES
('00000000-0000-0000-0000-000000000001', '60000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001')
ON CONFLICT DO NOTHING;

INSERT INTO access_reviews (id, name, description, type, status, reviewer_id, start_date, end_date) VALUES
('70000000-0000-0000-0000-000000000001', 'Q1 2026 Access Review', 'Quarterly access review for all users', 'user-access', 'pending', '00000000-0000-0000-0000-000000000001', '2026-01-01', '2026-03-31')
ON CONFLICT (id) DO NOTHING;`

	seedDataDown = `-- Rollback 010: Initial Seed Data
DELETE FROM user_roles WHERE user_id = '00000000-0000-0000-0000-000000000001' AND role_id = '60000000-0000-0000-0000-000000000001';
DELETE FROM access_reviews WHERE id = '70000000-0000-0000-0000-000000000001';
DELETE FROM application_sso_settings WHERE id LIKE '50000000-0000-0000-0000-000000000%';
DELETE FROM oauth_clients WHERE id LIKE '80000000-0000-0000-0000-000000000%';
DELETE FROM applications WHERE id LIKE '40000000-0000-0000-0000-000000000%';
DELETE FROM group_memberships WHERE user_id LIKE '00000000-0000-0000-0000-000000000%';
DELETE FROM groups WHERE id LIKE '10000000-0000-0000-0000-000000000%';
DELETE FROM roles WHERE id LIKE '60000000-0000-0000-0000-000000000%';
DELETE FROM users WHERE id LIKE '00000000-0000-0000-0000-000000000%';`

	// Migration 011-029 would be similarly defined...
	// For brevity, I'm including a placeholder for the rest
	// In production, these would be auto-generated from the migration files

	identityProvidersUp = `-- Migration 011: External Identity Providers
CREATE TABLE IF NOT EXISTS identity_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    issuer_url VARCHAR(255) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    scopes JSONB,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_identity_providers_name ON identity_providers(name);
CREATE INDEX IF NOT EXISTS idx_identity_providers_provider_type ON identity_providers(provider_type);
CREATE INDEX IF NOT EXISTS idx_identity_providers_issuer_url ON identity_providers(issuer_url);
ALTER TABLE users ADD COLUMN IF NOT EXISTS idp_id UUID;
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_user_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_users_idp_id ON users(idp_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id_idp_id ON users(idp_id, external_user_id) WHERE idp_id IS NOT NULL;`

	identityProvidersDown = `DROP INDEX IF EXISTS idx_users_external_id_idp_id;
DROP INDEX IF EXISTS idx_users_idp_id;
ALTER TABLE users DROP COLUMN IF EXISTS external_user_id;
ALTER TABLE users DROP COLUMN IF EXISTS idp_id;
DROP INDEX IF EXISTS idx_identity_providers_issuer_url;
DROP INDEX IF EXISTS idx_identity_providers_provider_type;
DROP INDEX IF EXISTS idx_identity_providers_name;
DROP TABLE IF EXISTS identity_providers;`

	provisioningRulesUp = `-- Migration 012: Provisioning Rules
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
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_provisioning_rules_trigger ON provisioning_rules(trigger);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);`

	provisioningRulesDown = `DROP INDEX IF EXISTS idx_password_reset_tokens_token;
DROP TABLE IF EXISTS password_reset_tokens;
DROP INDEX IF EXISTS idx_provisioning_rules_trigger;
DROP TABLE IF EXISTS provisioning_rules;`

	permissionsUp = `-- Migration 013: Permissions
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
ON CONFLICT (resource, action) DO NOTHING;`

	permissionsDown = `DELETE FROM permissions WHERE id LIKE 'a0000000-0000-0000-0000-000000000%';
DROP INDEX IF EXISTS idx_role_permissions_role_id;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;`

	systemSettingsUp = `-- Migration 014: System Settings
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by UUID
);
INSERT INTO system_settings (key, value) VALUES
('system', '{"general": {"organization_name": "OpenIDX", "support_email": "support@openidx.io", "default_language": "en", "default_timezone": "UTC"}, "security": {"password_policy": {"min_length": 12, "require_uppercase": true, "require_lowercase": true, "require_numbers": true, "require_special": true, "max_age": 90, "history": 5}, "session_timeout": 30, "max_failed_logins": 5, "lockout_duration": 15, "require_mfa": false, "blocked_countries": []}, "authentication": {"allow_registration": true, "require_email_verify": true, "mfa_methods": ["totp", "webauthn", "sms"]}, "branding": {"primary_color": "#2563eb", "secondary_color": "#1e40af", "login_page_title": "Welcome to OpenIDX"}}'::jsonb),
('mfa_methods', '["totp", "webauthn", "sms"]'::jsonb)
ON CONFLICT (key) DO NOTHING;`

	systemSettingsDown = `DELETE FROM system_settings WHERE key IN ('system', 'mfa_methods');
DROP TABLE IF EXISTS system_settings;`

	directoryIntegrationsUp = `-- Migration 015: Directory Integrations
CREATE TABLE IF NOT EXISTS directory_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    sync_status VARCHAR(50) DEFAULT 'never',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_directory_integrations_type ON directory_integrations(type);`

	directoryIntegrationsDown = `DROP INDEX IF EXISTS idx_directory_integrations_type;
DROP TABLE IF EXISTS directory_integrations;`

	proxyRoutesUp = `-- Migration 016: Proxy Routes
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
CREATE TABLE IF NOT EXISTS proxy_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    route_id UUID,
    session_token VARCHAR(500) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_active_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_proxy_routes_from_url ON proxy_routes(from_url);
CREATE INDEX IF NOT EXISTS idx_proxy_routes_enabled ON proxy_routes(enabled);
CREATE INDEX IF NOT EXISTS idx_proxy_sessions_user ON proxy_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_proxy_sessions_token ON proxy_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_proxy_sessions_expires ON proxy_sessions(expires_at);`

	proxyRoutesDown = `DROP INDEX IF EXISTS idx_proxy_sessions_expires;
DROP INDEX IF EXISTS idx_proxy_sessions_token;
DROP INDEX IF EXISTS idx_proxy_sessions_user;
DROP INDEX IF EXISTS idx_proxy_routes_enabled;
DROP INDEX IF EXISTS idx_proxy_routes_from_url;
DROP TABLE IF EXISTS proxy_sessions;
DROP TABLE IF EXISTS proxy_routes;`

	openzitiUp = `-- Migration 017: OpenZiti Integration
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS ziti_enabled BOOLEAN DEFAULT false;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS ziti_service_name VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_proxy_routes_ziti_enabled ON proxy_routes(ziti_enabled);
CREATE TABLE IF NOT EXISTS ziti_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    protocol VARCHAR(20) DEFAULT 'tcp',
    host VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    route_id UUID,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS ziti_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) UNIQUE NOT NULL,
    identity_type VARCHAR(50) DEFAULT 'Device',
    user_id UUID,
    enrollment_jwt TEXT,
    enrolled BOOLEAN DEFAULT false,
    attributes JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS ziti_service_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    policy_type VARCHAR(10) NOT NULL,
    service_roles JSONB DEFAULT '[]',
    identity_roles JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ziti_services_name ON ziti_services(name);
CREATE INDEX IF NOT EXISTS idx_ziti_identities_user_id ON ziti_identities(user_id);
INSERT INTO oauth_clients (client_id, client_secret, name, type, redirect_uris, grant_types, response_types, scopes, pkce_required)
VALUES ('access-proxy', '', 'Zero Trust Access Proxy', 'public', '["http://localhost:8007/access/.auth/callback", "http://localhost:8088/access/.auth/callback", "http://demo.localtest.me:8088/access/.auth/callback"]'::jsonb, '["authorization_code", "refresh_token"]'::jsonb, '["code"]'::jsonb, '["openid", "profile", "email"]'::jsonb, true)
ON CONFLICT (client_id) DO NOTHING;`

	openzitiDown = `DELETE FROM oauth_clients WHERE client_id = 'access-proxy';
DROP INDEX IF EXISTS idx_ziti_identities_user_id;
DROP INDEX IF EXISTS idx_ziti_services_name;
DROP TABLE IF EXISTS ziti_service_policies;
DROP TABLE IF EXISTS ziti_identities;
DROP TABLE IF EXISTS ziti_services;
DROP INDEX IF EXISTS idx_proxy_routes_ziti_enabled;
ALTER TABLE proxy_routes DROP COLUMN IF EXISTS ziti_service_name;
ALTER TABLE proxy_routes DROP COLUMN IF EXISTS ziti_enabled;`

	directorySyncUp = `-- Migration 018: Directory Sync
ALTER TABLE users ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'local';
ALTER TABLE users ADD COLUMN IF NOT EXISTS directory_id UUID;
ALTER TABLE users ADD COLUMN IF NOT EXISTS ldap_dn VARCHAR(1024);
CREATE INDEX IF NOT EXISTS idx_users_directory_id ON users(directory_id);
CREATE INDEX IF NOT EXISTS idx_users_source ON users(source);
ALTER TABLE groups ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'local';
ALTER TABLE groups ADD COLUMN IF NOT EXISTS directory_id UUID;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS ldap_dn VARCHAR(1024);
ALTER TABLE groups ADD COLUMN IF NOT EXISTS external_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_groups_directory_id ON groups(directory_id);
CREATE TABLE IF NOT EXISTS directory_sync_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id UUID NOT NULL,
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
CREATE TABLE IF NOT EXISTS directory_sync_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id UUID NOT NULL,
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
CREATE INDEX IF NOT EXISTS idx_sync_logs_started ON directory_sync_logs(started_at DESC);`

	directorySyncDown = `DROP INDEX IF EXISTS idx_sync_logs_started;
DROP INDEX IF EXISTS idx_sync_logs_directory;
DROP TABLE IF EXISTS directory_sync_logs;
DROP TABLE IF EXISTS directory_sync_state;
DROP INDEX IF EXISTS idx_groups_directory_id;
ALTER TABLE groups DROP COLUMN IF EXISTS external_id;
ALTER TABLE groups DROP COLUMN IF EXISTS ldap_dn;
ALTER TABLE groups DROP COLUMN IF EXISTS directory_id;
ALTER TABLE groups DROP COLUMN IF EXISTS source;
DROP INDEX IF EXISTS idx_users_source;
DROP INDEX IF EXISTS idx_users_directory_id;
ALTER TABLE users DROP COLUMN IF EXISTS ldap_dn;
ALTER TABLE users DROP COLUMN IF EXISTS directory_id;
ALTER TABLE users DROP COLUMN IF EXISTS source;`

	conditionalAccessUp = `-- Migration 019: Conditional Access
CREATE TABLE IF NOT EXISTS known_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
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
CREATE TABLE IF NOT EXISTS login_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
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
CREATE TABLE IF NOT EXISTS stepup_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    session_id VARCHAR(255) NOT NULL,
    reason VARCHAR(255),
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_stepup_user ON stepup_challenges(user_id, status);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS device_fingerprint VARCHAR(128);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS auth_methods TEXT[];
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS location VARCHAR(255);`

	conditionalAccessDown = `ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS location;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS auth_methods;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS risk_score;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS device_fingerprint;
DROP INDEX IF EXISTS idx_stepup_user;
DROP TABLE IF EXISTS stepup_challenges;
DROP INDEX IF EXISTS idx_login_history_user;
DROP TABLE IF EXISTS login_history;
DROP INDEX IF EXISTS idx_known_devices_user;
DROP TABLE IF EXISTS known_devices;`

	apiKeysWebhooksUp = `-- Migration 020: API Keys, Webhooks, Email Verification, Invitations
CREATE TABLE IF NOT EXISTS service_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    owner_id UUID,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(12) NOT NULL,
    key_hash VARCHAR(128) NOT NULL UNIQUE,
    user_id UUID,
    service_account_id UUID,
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
CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    secret VARCHAR(255) NOT NULL,
    events TEXT[] NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id UUID NOT NULL,
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
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS user_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    invited_by UUID NOT NULL,
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
ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_completed BOOLEAN DEFAULT false;`

	apiKeysWebhooksDown = `ALTER TABLE users DROP COLUMN IF EXISTS onboarding_completed;
DROP INDEX IF EXISTS idx_invitations_email;
DROP INDEX IF EXISTS idx_invitations_token;
DROP TABLE IF EXISTS user_invitations;
DROP TABLE IF EXISTS email_verification_tokens;
DROP INDEX IF EXISTS idx_webhook_deliveries_sub;
DROP INDEX IF EXISTS idx_webhook_deliveries_status;
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS webhook_subscriptions;
DROP INDEX IF EXISTS idx_api_keys_sa;
DROP INDEX IF EXISTS idx_api_keys_user;
DROP INDEX IF EXISTS idx_api_keys_hash;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS service_accounts;`

	accessRequestsUp = `-- Migration 021: Access Requests
CREATE TABLE IF NOT EXISTS access_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_id UUID NOT NULL,
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
    request_id UUID NOT NULL,
    approver_id UUID NOT NULL,
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
CREATE INDEX IF NOT EXISTS idx_approval_policies_resource ON approval_policies(resource_type, resource_id);`

	accessRequestsDown = `DROP INDEX IF EXISTS idx_approval_policies_resource;
DROP INDEX IF EXISTS idx_request_approvals_approver;
DROP INDEX IF EXISTS idx_request_approvals_request;
DROP INDEX IF EXISTS idx_access_requests_status;
DROP INDEX IF EXISTS idx_access_requests_requester;
DROP TABLE IF EXISTS approval_policies;
DROP TABLE IF EXISTS access_request_approvals;
DROP TABLE IF EXISTS access_requests;`

	securityAlertsUp = `-- Migration 022: Security Alerts
CREATE TABLE IF NOT EXISTS security_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID,
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) DEFAULT 'open',
    title VARCHAR(500) NOT NULL,
    description TEXT,
    details JSONB,
    source_ip VARCHAR(45),
    remediation_actions JSONB DEFAULT '[]',
    resolved_by UUID,
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
INSERT INTO audit_events (id, timestamp, event_type, category, action, outcome, actor_id, actor_type, actor_ip, target_id, target_type, resource_id, details)
VALUES
  (gen_random_uuid(), NOW() - INTERVAL '6 days 14 hours', 'system', 'operational', 'system_startup', 'success', 'system', 'system', '127.0.0.1', '', 'system', '', '{"message": "OpenIDX platform initialized"}'),
  (gen_random_uuid(), NOW() - INTERVAL '5 days 10 hours', 'authentication', 'security', 'login', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}'),
  (gen_random_uuid(), NOW() - INTERVAL '3 days 12 hours', 'authentication', 'security', 'login', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}'),
  (gen_random_uuid(), NOW() - INTERVAL '1 day 15 hours', 'authentication', 'security', 'login', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}'),
  (gen_random_uuid(), NOW() - INTERVAL '6 hours', 'authentication', 'security', 'login', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.20', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}');`

	securityAlertsDown = `DELETE FROM audit_events WHERE details->>'username' = 'admin';
DROP INDEX IF EXISTS idx_ip_threat_list_ip;
DROP INDEX IF EXISTS idx_security_alerts_created;
DROP INDEX IF EXISTS idx_security_alerts_severity;
DROP INDEX IF EXISTS idx_security_alerts_status;
DROP INDEX IF EXISTS idx_security_alerts_user;
DROP TABLE IF EXISTS ip_threat_list;
DROP TABLE IF EXISTS security_alerts;`

	passwordManagementUp = `-- Migration 023: Password Management
CREATE TABLE IF NOT EXISTS password_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS credential_rotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_account_id UUID NOT NULL,
    old_key_id UUID,
    new_key_id UUID,
    rotation_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'completed',
    rotated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    rotated_by UUID
);
CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_credential_rotations_sa ON credential_rotations(service_account_id);`

	passwordManagementDown = `DROP INDEX IF EXISTS idx_credential_rotations_sa;
DROP TABLE IF EXISTS credential_rotations;
DROP INDEX IF NOT EXISTS idx_password_history_user;
DROP TABLE IF NOT EXISTS password_history;`

	sessionEnhancementsUp = `-- Migration 024: Session Enhancements
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_name VARCHAR(255);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS location VARCHAR(255);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_type VARCHAR(50);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked BOOLEAN DEFAULT false;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked_by UUID;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoke_reason VARCHAR(255);`

	sessionEnhancementsDown = `ALTER TABLE sessions DROP COLUMN IF EXISTS revoke_reason;
ALTER TABLE sessions DROP COLUMN IF EXISTS revoked_by;
ALTER TABLE sessions DROP COLUMN IF EXISTS revoked_at;
ALTER TABLE sessions DROP COLUMN IF EXISTS revoked;
ALTER TABLE sessions DROP COLUMN IF EXISTS device_type;
ALTER TABLE sessions DROP COLUMN IF EXISTS location;
ALTER TABLE sessions DROP COLUMN IF EXISTS device_name;`

	multitenancyUp = `-- Migration 025: Multi-Tenancy
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
INSERT INTO organizations (id, name, slug, domain, plan, status, max_users, max_applications)
VALUES ('00000000-0000-0000-0000-000000000010', 'Default Organization', 'default', NULL, 'enterprise', 'active', 999999, 999999)
ON CONFLICT (id) DO NOTHING;
UPDATE users SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE groups SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE roles SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE applications SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
INSERT INTO organization_members (organization_id, user_id, role)
VALUES ('00000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-000000000001', 'owner')
ON CONFLICT DO NOTHING;`

	multitenancyDown = `DELETE FROM organization_members WHERE organization_id = '00000000-0000-0000-0000-000000000010';
UPDATE users SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE groups SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE roles SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE applications SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
DELETE FROM organizations WHERE id = '00000000-0000-0000-0000-000000000010';
DROP INDEX IF EXISTS idx_applications_org_id;
DROP INDEX IF EXISTS idx_roles_org_id;
DROP INDEX IF EXISTS idx_groups_org_id;
DROP INDEX IF EXISTS idx_users_org_id;
ALTER TABLE security_alerts DROP COLUMN IF EXISTS org_id;
ALTER TABLE access_requests DROP COLUMN IF EXISTS org_id;
ALTER TABLE webhook_subscriptions DROP COLUMN IF EXISTS org_id;
ALTER TABLE service_accounts DROP COLUMN IF EXISTS org_id;
ALTER TABLE access_reviews DROP COLUMN IF EXISTS org_id;
ALTER TABLE policies DROP COLUMN IF EXISTS org_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS org_id;
ALTER TABLE audit_events DROP COLUMN IF EXISTS org_id;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS org_id;
ALTER TABLE applications DROP COLUMN IF EXISTS org_id;
ALTER TABLE roles DROP COLUMN IF EXISTS org_id;
ALTER TABLE groups DROP COLUMN IF EXISTS org_id;
ALTER TABLE users DROP COLUMN IF EXISTS org_id;
DROP INDEX IF EXISTS idx_org_members_user;
DROP INDEX IF EXISTS idx_org_members_org;
DROP INDEX IF EXISTS idx_organizations_domain;
DROP INDEX IF EXISTS idx_organizations_slug;
DROP TABLE IF EXISTS organization_members;
DROP TABLE IF EXISTS organizations;`

	reportingUp = `-- Migration 026: Advanced Reporting
CREATE TABLE IF NOT EXISTS scheduled_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID,
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
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS report_exports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID,
    scheduled_report_id UUID,
    name VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    framework VARCHAR(100),
    format VARCHAR(10) NOT NULL,
    status VARCHAR(50) DEFAULT 'generating',
    file_path VARCHAR(500),
    file_size BIGINT,
    row_count INTEGER,
    error_message TEXT,
    generated_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_report_exports_org ON report_exports(org_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_reports_org ON scheduled_reports(org_id);`

	reportingDown = `DROP INDEX IF EXISTS idx_scheduled_reports_org;
DROP INDEX IF EXISTS idx_report_exports_org;
DROP TABLE IF EXISTS report_exports;
DROP TABLE IF EXISTS scheduled_reports;`

	selfServiceUp = `-- Migration 027: Self-Service Portal
CREATE TABLE IF NOT EXISTS group_join_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    group_id UUID NOT NULL,
    justification TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    reviewed_by UUID,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    review_comments TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, group_id)
);
CREATE TABLE IF NOT EXISTS user_application_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    application_id UUID NOT NULL,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, application_id)
);
CREATE INDEX IF NOT EXISTS idx_group_requests_user ON group_join_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_group_requests_status ON group_join_requests(status);
CREATE INDEX IF NOT EXISTS idx_user_app_assignments_user ON user_application_assignments(user_id);`

	selfServiceDown = `DROP INDEX IF EXISTS idx_user_app_assignments_user;
DROP TABLE IF EXISTS user_application_assignments;
DROP INDEX IF EXISTS idx_group_requests_status;
DROP INDEX IF EXISTS idx_group_requests_user;
DROP TABLE IF EXISTS group_join_requests;`

	notificationsUp = `-- Migration 028: Notifications
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    org_id UUID,
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
    user_id UUID NOT NULL,
    channel VARCHAR(50) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, channel, event_type)
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, read, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_prefs_user ON notification_preferences(user_id);`

	notificationsDown = `DROP INDEX IF EXISTS idx_notification_prefs_user;
DROP INDEX IF EXISTS idx_notifications_user;
DROP TABLE IF NOT EXISTS notification_preferences;
DROP TABLE IF NOT EXISTS notifications;`

	zitiEnhancedUp = `-- Migration 029: OpenZiti Enhanced
CREATE TABLE IF NOT EXISTS posture_check_types (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    category VARCHAR(100) NOT NULL,
    parameters JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
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
CREATE TABLE IF NOT EXISTS device_posture_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID,
    check_id UUID,
    passed BOOLEAN NOT NULL,
    details JSONB DEFAULT '{}',
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_posture_results_identity ON device_posture_results(identity_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_posture_results_check ON device_posture_results(check_id);
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
CREATE TABLE IF NOT EXISTS ziti_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    cert_data TEXT NOT NULL,
    private_key_encrypted TEXT,
    ca_chain TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    identity_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ziti_certificates_identity ON ziti_certificates(identity_id);
CREATE INDEX IF NOT EXISTS idx_ziti_certificates_expires ON ziti_certificates(expires_at);`

	zitiEnhancedDown = `DROP INDEX IF EXISTS idx_ziti_certificates_expires;
DROP INDEX IF EXISTS idx_ziti_certificates_identity;
DROP TABLE IF EXISTS ziti_certificates;
DROP INDEX IF EXISTS idx_policy_sync_status;
DROP INDEX IF EXISTS idx_policy_sync_governance;
DROP TABLE IF EXISTS policy_sync_state;
DROP INDEX IF EXISTS idx_posture_results_check;
DROP INDEX IF EXISTS idx_posture_results_identity;
DROP TABLE IF EXISTS device_posture_results;
DROP TABLE IF EXISTS posture_checks;
DROP TABLE IF NOT EXISTS posture_check_types;`
)
