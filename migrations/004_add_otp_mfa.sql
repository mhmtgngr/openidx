-- Migration: Add SMS and Email OTP MFA support
-- Description: Creates tables for SMS OTP, Email OTP enrollment and OTP challenges

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
    method VARCHAR(20) NOT NULL, -- 'sms' or 'email'
    recipient VARCHAR(255) NOT NULL, -- phone number or email address
    code_hash VARCHAR(255) NOT NULL, -- SHA256 hash of the OTP code
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    status VARCHAR(20) DEFAULT 'pending', -- pending, verified, expired, failed
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

-- Add user_mfa_methods view for easy querying of enrolled MFA methods
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

COMMENT ON TABLE mfa_sms IS 'SMS-based OTP MFA enrollment';
COMMENT ON TABLE mfa_email_otp IS 'Email-based OTP MFA enrollment';
COMMENT ON TABLE mfa_otp_challenges IS 'Active OTP challenges for SMS and Email MFA';
COMMENT ON TABLE risk_policies IS 'Risk-based MFA policies for adaptive authentication';
COMMENT ON TABLE trusted_browsers IS 'Trusted browsers that can skip MFA';
