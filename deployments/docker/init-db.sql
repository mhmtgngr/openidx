-- OpenIDX Database Schema

-- Users table (extended from Keycloak)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
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

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Groups table
CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    parent_id UUID REFERENCES groups(id),
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
    id UUID PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    is_composite BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Access reviews
CREATE TABLE IF NOT EXISTS access_reviews (
    id UUID PRIMARY KEY,
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

-- Review items
CREATE TABLE IF NOT EXISTS review_items (
    id UUID PRIMARY KEY,
    review_id UUID REFERENCES access_reviews(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID NOT NULL,
    resource_name VARCHAR(255),
    decision VARCHAR(50) DEFAULT 'pending',
    decided_by UUID REFERENCES users(id),
    decided_at TIMESTAMP WITH TIME ZONE,
    comments TEXT
);

-- Policies
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    rules JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- SCIM users
CREATE TABLE IF NOT EXISTS scim_users (
    id UUID PRIMARY KEY,
    external_id VARCHAR(255),
    username VARCHAR(255) NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- MFA (TOTP) settings
CREATE TABLE IF NOT EXISTS mfa_totp (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    secret VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT false,
    enrolled_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Backup codes for MFA
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    used BOOLEAN DEFAULT false,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- MFA enforcement policies
CREATE TABLE IF NOT EXISTS mfa_policies (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    conditions JSONB, -- e.g., {"groups": ["admin"], "ip_ranges": ["192.168.1.0/24"]}
    required_methods JSONB, -- e.g., ["totp", "backup_code"]
    grace_period_hours INTEGER DEFAULT 24,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User MFA policy assignments
CREATE TABLE IF NOT EXISTS user_mfa_policies (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES mfa_policies(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, policy_id)
);

-- WebAuthn (FIDO2/Passkey) credentials
CREATE TABLE IF NOT EXISTS mfa_webauthn (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT UNIQUE NOT NULL, -- Base64URL encoded
    public_key TEXT NOT NULL, -- COSE encoded public key
    sign_count BIGINT DEFAULT 0, -- Counter to prevent replay attacks
    aaguid VARCHAR(36), -- Authenticator attestation GUID
    transports TEXT[], -- usb, nfc, ble, internal
    name VARCHAR(255), -- User-friendly name (e.g., "YubiKey 5", "Touch ID")
    backup_eligible BOOLEAN DEFAULT false, -- Can credential be backed up (passkey)
    backup_state BOOLEAN DEFAULT false, -- Is credential currently backed up
    attestation_format VARCHAR(50), -- packed, fido-u2f, none, etc.
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, credential_id)
);

-- Push notification MFA devices
CREATE TABLE IF NOT EXISTS mfa_push_devices (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_token TEXT UNIQUE NOT NULL, -- FCM/APNS token
    platform VARCHAR(20) NOT NULL, -- ios, android, web
    device_name VARCHAR(255), -- User-friendly name (e.g., "iPhone 13", "Pixel 6")
    device_model VARCHAR(100), -- Phone model
    os_version VARCHAR(50), -- OS version
    app_version VARCHAR(50), -- App version
    enabled BOOLEAN DEFAULT true,
    trusted BOOLEAN DEFAULT false, -- Device trust status
    last_ip VARCHAR(45), -- Last IP address
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE -- Token expiry
);

-- Push MFA challenges
CREATE TABLE IF NOT EXISTS mfa_push_challenges (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES mfa_push_devices(id) ON DELETE CASCADE,
    challenge_code VARCHAR(10) NOT NULL, -- Number matching code (e.g., "73")
    status VARCHAR(20) DEFAULT 'pending', -- pending, approved, denied, expired
    session_info JSONB, -- IP, location, browser, etc.
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    responded_at TIMESTAMP WITH TIME ZONE,
    ip_address VARCHAR(45), -- IP of login attempt
    user_agent TEXT, -- Browser/client info
    location VARCHAR(255) -- Geolocation (city, country)
);

-- Indexes for WebAuthn
CREATE INDEX IF NOT EXISTS idx_webauthn_user_id ON mfa_webauthn(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credential_id ON mfa_webauthn(credential_id);

-- Indexes for Push MFA
CREATE INDEX IF NOT EXISTS idx_push_devices_user_id ON mfa_push_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_push_devices_token ON mfa_push_devices(device_token);
CREATE INDEX IF NOT EXISTS idx_push_challenges_user_id ON mfa_push_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_push_challenges_status ON mfa_push_challenges(status);
CREATE INDEX IF NOT EXISTS idx_push_challenges_expires_at ON mfa_push_challenges(expires_at);

-- Audit events
CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
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
    request_id VARCHAR(255)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);

-- Insert default admin user
INSERT INTO users (id, username, email, first_name, last_name, enabled, email_verified)
VALUES ('00000000-0000-0000-0000-000000000001', 'admin', 'admin@openidx.local', 'System', 'Admin', true, true)
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
CREATE TABLE IF NOT EXISTS applications (
    id UUID PRIMARY KEY,
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

INSERT INTO applications (id, client_id, name, description, type, protocol, base_url, enabled) VALUES
('20000000-0000-0000-0000-000000000001', 'admin-console', 'Admin Console', 'OpenIDX Administration Console', 'web', 'openid-connect', 'http://localhost:3000', true),
('20000000-0000-0000-0000-000000000002', 'hr-portal', 'HR Portal', 'Human Resources Management Portal', 'web', 'openid-connect', 'http://hr.example.com', true),
('20000000-0000-0000-0000-000000000003', 'finance-app', 'Finance Application', 'Financial reporting and management', 'web', 'openid-connect', 'http://finance.example.com', true),
('20000000-0000-0000-0000-000000000004', 'mobile-app', 'Mobile Application', 'Company mobile application', 'native', 'openid-connect', NULL, true),
('20000000-0000-0000-0000-000000000005', 'legacy-erp', 'Legacy ERP', 'Legacy ERP system integration', 'service', 'saml', 'http://erp.example.com', false)
ON CONFLICT (id) DO NOTHING;

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
 '{"groups": ["Administrators"]}', '["totp", "backup_code"]', 24),
('50000000-0000-0000-0000-000000000002', 'Finance Department MFA', 'Require MFA for finance department during business hours', true, 80,
 '{"groups": ["Finance"], "time_windows": [{"days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"], "start_hour": 9, "end_hour": 17}]}', '["totp"]', 48),
('50000000-0000-0000-0000-000000000003', 'External Access MFA', 'Require MFA for access from external IP ranges', true, 60,
 '{"ip_ranges": ["192.168.0.0/16", "10.0.0.0/8"]}', '["totp", "backup_code"]', 0),
('50000000-0000-0000-0000-000000000004', 'Verified Users Only', 'Require MFA for users with verified email', true, 40,
 '{"attributes": {"email_verified": true}}', '["totp"]', 168),
('50000000-0000-0000-0000-000000000005', 'Weekend Access MFA', 'Require MFA during weekends', true, 50,
 '{"time_windows": [{"days": ["Saturday", "Sunday"], "start_hour": 0, "end_hour": 23}]}', '["totp", "backup_code"]', 24)
ON CONFLICT (id) DO NOTHING;

-- Insert sample audit events
INSERT INTO audit_events (id, timestamp, event_type, category, action, outcome, actor_id, actor_type, actor_ip, target_id, target_type, details) VALUES
('40000000-0000-0000-0000-000000000001', NOW() - INTERVAL '1 hour', 'authentication', 'security', 'user.login', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.100', '00000000-0000-0000-0000-000000000001', 'user', '{"method": "password", "client": "admin-console"}'),
('40000000-0000-0000-0000-000000000002', NOW() - INTERVAL '2 hours', 'authentication', 'security', 'user.login', 'failure', NULL, 'anonymous', '192.168.1.101', NULL, NULL, '{"reason": "invalid_credentials", "username": "unknown"}'),
('40000000-0000-0000-0000-000000000003', NOW() - INTERVAL '3 hours', 'user_management', 'operational', 'user.create', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.100', '00000000-0000-0000-0000-000000000002', 'user', '{"username": "jsmith"}'),
('40000000-0000-0000-0000-000000000004', NOW() - INTERVAL '4 hours', 'authorization', 'security', 'permission.granted', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.100', '00000000-0000-0000-0000-000000000002', 'user', '{"permission": "view_reports", "resource": "finance-app"}'),
('40000000-0000-0000-0000-000000000005', NOW() - INTERVAL '5 hours', 'group_management', 'operational', 'group.member_added', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.100', '10000000-0000-0000-0000-000000000002', 'group', '{"user_id": "00000000-0000-0000-0000-000000000003", "group": "Developers"}'),
('40000000-0000-0000-0000-000000000006', NOW() - INTERVAL '1 day', 'authentication', 'security', 'user.logout', 'success', '00000000-0000-0000-0000-000000000003', 'user', '192.168.1.102', '00000000-0000-0000-0000-000000000003', 'user', '{}'),
('40000000-0000-0000-0000-000000000007', NOW() - INTERVAL '2 days', 'configuration', 'operational', 'settings.updated', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.100', NULL, 'system', '{"setting": "password_policy", "old_value": "length:8", "new_value": "length:12"}')
ON CONFLICT (id) DO NOTHING;
