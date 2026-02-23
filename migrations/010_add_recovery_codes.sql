-- Migration: Add Recovery Codes MFA support
-- Description: Creates table for recovery codes (backup codes) for MFA

-- Recovery codes (backup codes) for MFA
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL, -- bcrypt hash of the recovery code
    used BOOLEAN DEFAULT false,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_user_id ON mfa_backup_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_used ON mfa_backup_codes(used);

-- Comments for documentation
COMMENT ON TABLE mfa_backup_codes IS 'Recovery codes (backup codes) for MFA - single-use codes for account recovery';
COMMENT ON COLUMN mfa_backup_codes.code_hash IS 'bcrypt hash of the recovery code (8 alphanumeric characters)';
COMMENT ON COLUMN mfa_backup_codes.used IS 'True if the recovery code has been used (single-use)';
COMMENT ON COLUMN mfa_backup_codes.used_at IS 'Timestamp when the recovery code was used';

-- Update the user_mfa_methods view if it exists
DROP VIEW IF EXISTS user_mfa_methods;

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
