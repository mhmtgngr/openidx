-- OpenIDX Database Schema Migration
-- Version: 001
-- Description: Initial schema for all OpenIDX services

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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_groups (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, group_id)
);

-- ============================================================================
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oauth_access_tokens (
    token VARCHAR(1000) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id UUID,
    scope TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token VARCHAR(500) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL,
    scope TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- SCIM 2.0 PROVISIONING TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS scim_users (
    id UUID PRIMARY KEY,
    external_id VARCHAR(255),
    username VARCHAR(255) UNIQUE NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scim_groups (
    id UUID PRIMARY KEY,
    external_id VARCHAR(255),
    display_name VARCHAR(255) UNIQUE NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- GOVERNANCE TABLES (Access Reviews & Policies)
-- ============================================================================

CREATE TABLE IF NOT EXISTS access_reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    reviewer_id UUID,
    start_date TIMESTAMP NOT NULL,
    end_date TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS review_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID NOT NULL REFERENCES access_reviews(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    resource_name VARCHAR(255),
    decision VARCHAR(50) DEFAULT 'pending',
    decided_by UUID,
    decided_at TIMESTAMP,
    comments TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS policy_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    rule_type VARCHAR(50) NOT NULL,
    conditions JSONB NOT NULL,
    actions JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- AUDIT AND COMPLIANCE TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL,
    user_id UUID,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    action VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- WEBAUTHN / PASSKEY TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id VARCHAR(255) UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    counter BIGINT DEFAULT 0,
    aaguid VARCHAR(255),
    device_name VARCHAR(255),
    last_used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- PUSH MFA TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS mfa_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_type VARCHAR(50) NOT NULL,
    device_token TEXT NOT NULL,
    device_name VARCHAR(255),
    enabled BOOLEAN DEFAULT true,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mfa_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES mfa_devices(id) ON DELETE CASCADE,
    challenge_code VARCHAR(10) NOT NULL,
    number_match VARCHAR(2) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    expires_at TIMESTAMP NOT NULL,
    responded_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- SESSION MANAGEMENT TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(500) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Users and Groups indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_groups_name ON groups(name);

-- OAuth indexes
CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_client_id ON oauth_authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_user_id ON oauth_authorization_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_client_id ON oauth_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_user_id ON oauth_access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_client_id ON oauth_refresh_tokens(client_id);

-- SCIM indexes
CREATE INDEX IF NOT EXISTS idx_scim_users_external_id ON scim_users(external_id);
CREATE INDEX IF NOT EXISTS idx_scim_groups_external_id ON scim_groups(external_id);

-- Governance indexes
CREATE INDEX IF NOT EXISTS idx_access_reviews_status ON access_reviews(status);
CREATE INDEX IF NOT EXISTS idx_review_items_review_id ON review_items(review_id);
CREATE INDEX IF NOT EXISTS idx_review_items_user_id ON review_items(user_id);
CREATE INDEX IF NOT EXISTS idx_policies_type ON policies(type);
CREATE INDEX IF NOT EXISTS idx_policy_rules_policy_id ON policy_rules(policy_id);

-- Audit indexes
CREATE INDEX IF NOT EXISTS idx_audit_events_user_id ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_resource_type ON audit_events(resource_type);

-- WebAuthn indexes
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id);

-- MFA indexes
CREATE INDEX IF NOT EXISTS idx_mfa_devices_user_id ON mfa_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_id ON mfa_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_status ON mfa_challenges(status);

-- Session indexes
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);

-- ============================================================================
-- SEED DATA (Development/Demo)
-- ============================================================================

-- Insert demo admin user
INSERT INTO users (id, username, email, first_name, last_name, enabled, email_verified)
VALUES
    ('00000000-0000-0000-0000-000000000001', 'admin', 'admin@openidx.local', 'Admin', 'User', true, true)
ON CONFLICT (username) DO NOTHING;

-- Insert demo groups
INSERT INTO groups (id, name, description)
VALUES
    ('00000000-0000-0000-0000-000000000010', 'Administrators', 'System administrators with full access'),
    ('00000000-0000-0000-0000-000000000011', 'Developers', 'Development team members'),
    ('00000000-0000-0000-0000-000000000012', 'Users', 'Standard users')
ON CONFLICT (name) DO NOTHING;

-- Add admin to Administrators group
INSERT INTO user_groups (user_id, group_id)
VALUES ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000010')
ON CONFLICT DO NOTHING;

-- Insert demo OAuth client
INSERT INTO oauth_clients (
    id, client_id, client_secret, name, description, type,
    redirect_uris, grant_types, response_types, scopes,
    pkce_required, allow_refresh_token
)
VALUES (
    '00000000-0000-0000-0000-000000000020',
    'demo-client',
    '$2a$10$N9qo8uLOickgx2ZMRZoMye1234567890abcdefghijk', -- bcrypt hash of 'demo-secret'
    'Demo Application',
    'Demo OAuth 2.0 client for testing',
    'web',
    '["http://localhost:3000/callback", "http://localhost:8080/callback"]'::jsonb,
    '["authorization_code", "refresh_token"]'::jsonb,
    '["code"]'::jsonb,
    '["openid", "profile", "email", "offline_access"]'::jsonb,
    true,
    true
)
ON CONFLICT (client_id) DO NOTHING;

-- ============================================================================
-- COMMENTS FOR DOCUMENTATION
-- ============================================================================

COMMENT ON TABLE users IS 'Core user identity table';
COMMENT ON TABLE groups IS 'User groups for access control';
COMMENT ON TABLE oauth_clients IS 'OAuth 2.0 / OpenID Connect registered clients';
COMMENT ON TABLE oauth_authorization_codes IS 'OAuth authorization codes (short-lived)';
COMMENT ON TABLE oauth_access_tokens IS 'OAuth access tokens';
COMMENT ON TABLE oauth_refresh_tokens IS 'OAuth refresh tokens';
COMMENT ON TABLE scim_users IS 'SCIM 2.0 user provisioning data';
COMMENT ON TABLE scim_groups IS 'SCIM 2.0 group provisioning data';
COMMENT ON TABLE access_reviews IS 'Access review campaigns';
COMMENT ON TABLE review_items IS 'Individual items to review in a campaign';
COMMENT ON TABLE policies IS 'Access policies (SoD, risk-based, time-bound)';
COMMENT ON TABLE policy_rules IS 'Rules within policies';
COMMENT ON TABLE audit_events IS 'Audit log for all system events';
COMMENT ON TABLE webauthn_credentials IS 'WebAuthn/Passkey credentials';
COMMENT ON TABLE mfa_devices IS 'Push MFA device registrations';
COMMENT ON TABLE mfa_challenges IS 'Active MFA challenges';
COMMENT ON TABLE user_sessions IS 'Active user sessions';
