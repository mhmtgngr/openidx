-- OpenIDX Production Settings Migration
-- Version: 014
-- Description: Production system settings, feature flags, and compliance configuration

-- ============================================================================
-- FEATURE FLAGS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS feature_flags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT false,
    rollout_percentage INTEGER DEFAULT 0 CHECK (rollout_percentage >= 0 AND rollout_percentage <= 100),
    constraints JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default feature flags
INSERT INTO feature_flags (name, description, enabled, rollout_percentage)
VALUES
    ('mfa_required', 'Require multi-factor authentication for all users', false, 0),
    ('password_less_auth', 'Enable passwordless authentication options', false, 0),
    ('biometric_auth', 'Enable WebAuthn biometric authentication', true, 100),
    ('continuous_verification', 'Enable continuous verification for sensitive actions', false, 0),
    ('risk_based_auth', 'Enable risk-based authentication challenges', false, 0),
    ('self_service_password_reset', 'Allow users to reset their own passwords', true, 100),
    ('self_service_mfa', 'Allow users to manage their own MFA devices', true, 100),
    ('api_rate_limiting', 'Enable API rate limiting', true, 100),
    ('audit_log_export', 'Enable audit log export functionality', true, 100),
    ('compliance_reports', 'Enable compliance report generation', true, 100)
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- COMPLIANCE SETTINGS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS compliance_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    jurisdiction VARCHAR(100) NOT NULL, -- GDPR, HIPAA, SOX, etc.
    data_retention_days INTEGER NOT NULL,
    audit_retention_days INTEGER NOT NULL,
    session_timeout_minutes INTEGER NOT NULL,
    require_mfa BOOLEAN DEFAULT false,
    require_consent BOOLEAN DEFAULT false,
    consent_text TEXT,
    privacy_policy_url VARCHAR(500),
    data_deletion_enabled BOOLEAN DEFAULT true,
    data_portability_enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(jurisdiction)
);

-- Insert default compliance settings
INSERT INTO compliance_settings (jurisdiction, data_retention_days, audit_retention_days, session_timeout_minutes, require_mfa, require_consent)
VALUES
    ('GDPR', 2555, 3650, 480, false, true),  -- 7 years data, 10 years audit
    ('HIPAA', 2190, 3650, 480, true, false), -- 6 years data, 10 years audit
    ('SOX', 2555, 4380, 480, true, false),   -- 7 years data, 12 years audit
    ('default', 365, 365, 480, false, false) -- 1 year default
ON CONFLICT (jurisdiction) DO NOTHING;

-- ============================================================================
-- SECURITY POLICIES TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS security_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,

    -- Password policy
    password_min_length INTEGER DEFAULT 12,
    password_max_length INTEGER DEFAULT 128,
    password_require_uppercase BOOLEAN DEFAULT true,
    password_require_lowercase BOOLEAN DEFAULT true,
    password_require_number BOOLEAN DEFAULT true,
    password_require_special BOOLEAN DEFAULT true,
    password_expiration_days INTEGER,
    password_history_count INTEGER DEFAULT 5,
    password Prevent_reuse BOOLEAN DEFAULT true,

    -- Session policy
    session_timeout_minutes INTEGER DEFAULT 480,
    max_concurrent_sessions INTEGER DEFAULT 10,
    max_concurrent_sessions_per_type INTEGER DEFAULT 5,

    -- Lockout policy
    max_failed_attempts INTEGER DEFAULT 5,
    lockout_duration_minutes INTEGER DEFAULT 30,
    permanent_lock_after_attempts INTEGER,

    -- IP restrictions
    allowed_ip_ranges JSONB DEFAULT '[]'::jsonb,
    denied_ip_ranges JSONB DEFAULT '[]'::jsonb,

    -- Geo restrictions
    allowed_countries JSONB DEFAULT '[]'::jsonb,
    denied_countries JSONB DEFAULT '[]'::jsonb,

    -- Time restrictions
    allowed_time_ranges JSONB DEFAULT '[]'::jsonb,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default security policy
INSERT INTO security_policies (
    name,
    description,
    password_min_length,
    password_require_uppercase,
    password_require_lowercase,
    password_require_number,
    password_require_special,
    max_failed_attempts,
    lockout_duration_minutes
)
VALUES (
    'default-policy',
    'Default security policy for all users',
    12,
    true,
    true,
    true,
    true,
    5,
    30
)
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- USER POLICY ASSIGNMENTS
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_policy_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES security_policies(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID REFERENCES users(id),
    UNIQUE(user_id, policy_id)
);

-- ============================================================================
-- GROUP POLICY ASSIGNMENTS
-- ============================================================================

CREATE TABLE IF NOT EXISTS group_policy_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES security_policies(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID REFERENCES users(id),
    UNIQUE(group_id, policy_id)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_feature_flags_enabled ON feature_flags(enabled);
CREATE INDEX IF NOT EXISTS idx_feature_flags_name ON feature_flags(name);

CREATE INDEX IF NOT EXISTS idx_compliance_jurisdiction ON compliance_settings(jurisdiction);

CREATE INDEX IF NOT EXISTS idx_security_policies_enabled ON security_policies(enabled);
CREATE INDEX IF NOT EXISTS idx_security_policies_priority ON security_policies(priority DESC);

CREATE INDEX IF NOT EXISTS idx_user_policy_assignments_user ON user_policy_assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_user_policy_assignments_policy ON user_policy_assignments(policy_id);

CREATE INDEX IF NOT EXISTS idx_group_policy_assignments_group ON group_policy_assignments(group_id);
CREATE INDEX IF NOT EXISTS idx_group_policy_assignments_policy ON group_policy_assignments(policy_id);

-- ============================================================================
-- FUNCTIONS
-- ============================================================================

-- Function to check if a feature is enabled for a user
CREATE OR REPLACE FUNCTION is_feature_enabled(
    feature_name VARCHAR,
    user_id UUID DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    feature_enabled BOOLEAN;
    rollout_pct INTEGER;
BEGIN
    SELECT enabled, rollout_percentage
    INTO feature_enabled, rollout_pct
    FROM feature_flags
    WHERE name = feature_name;

    -- Feature not found or disabled
    IF feature_enabled IS NULL OR NOT feature_enabled THEN
        RETURN false;
    END IF;

    -- 100% rollout means enabled for all
    IF rollout_pct >= 100 THEN
        RETURN true;
    END IF;

    -- 0% rollout means disabled
    IF rollout_pct <= 0 THEN
        RETURN false;
    END IF;

    -- For partial rollouts, use user ID hash for consistent selection
    IF user_id IS NOT NULL THEN
        RETURN (hashtext(user_id::text) % 100) < rollout_pct;
    END IF;

    -- No user provided, default to false for partial rollouts
    RETURN false;
END;
$$ LANGUAGE plpgsql;

-- Function to get applicable security policy for a user
CREATE OR REPLACE FUNCTION get_user_security_policy(target_user_id UUID)
RETURNS security_policies AS $$
DECLARE
    user_policy security_policies;
    group_policy security_policies;
BEGIN
    -- First check for direct user policy assignment
    SELECT sp.* INTO user_policy
    FROM security_policies sp
    INNER JOIN user_policy_assignments upa ON sp.id = upa.policy_id
    WHERE upa.user_id = target_user_id AND sp.enabled = true
    ORDER BY sp.priority DESC
    LIMIT 1;

    IF user_policy IS NOT NULL THEN
        RETURN user_policy;
    END IF;

    -- Check for group policy assignments
    SELECT sp.* INTO group_policy
    FROM security_policies sp
    INNER JOIN group_policy_assignments gpa ON sp.id = gpa.policy_id
    INNER JOIN user_groups ug ON gpa.group_id = ug.group_id
    WHERE ug.user_id = target_user_id AND sp.enabled = true
    ORDER BY sp.priority DESC
    LIMIT 1;

    IF group_policy IS NOT NULL THEN
        RETURN group_policy;
    END IF;

    -- Return default policy
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE feature_flags IS 'Feature flags for gradual rollout';
COMMENT ON TABLE compliance_settings IS 'Compliance settings by jurisdiction';
COMMENT ON TABLE security_policies IS 'Security policies for passwords, sessions, and access';
COMMENT ON TABLE user_policy_assignments IS 'Direct policy assignments to users';
COMMENT ON TABLE group_policy_assignments IS 'Policy assignments to groups';

COMMENT ON FUNCTION is_feature_enabled IS 'Check if a feature is enabled for a given user';
COMMENT ON FUNCTION get_user_security_policy IS 'Get the applicable security policy for a user';
