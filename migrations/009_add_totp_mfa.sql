-- Migration: Add TOTP MFA support
-- Description: Creates table for TOTP (Time-based One-Time Password) MFA enrollment

-- TOTP MFA enrollment
CREATE TABLE IF NOT EXISTS mfa_totp (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    secret VARCHAR(255) NOT NULL, -- Encrypted TOTP secret
    account_name VARCHAR(255) NOT NULL, -- Account name for TOTP (typically email or username)
    verified BOOLEAN DEFAULT false, -- Whether the user has verified the TOTP setup
    enabled BOOLEAN DEFAULT false, -- Whether TOTP is enabled for this user
    backup_codes TEXT[], -- Backup recovery codes (encrypted)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    verified_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_mfa_totp_user_id ON mfa_totp(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_totp_enabled ON mfa_totp(enabled);

-- Comments for documentation
COMMENT ON TABLE mfa_totp IS 'TOTP (Time-based One-Time Password) MFA enrollment';
COMMENT ON COLUMN mfa_totp.secret IS 'Encrypted TOTP secret (AES-256-GCM)';
COMMENT ON COLUMN mfa_totp.account_name IS 'Account name displayed in authenticator app';
COMMENT ON COLUMN mfa_totp.verified IS 'True if user has successfully verified their TOTP setup';
COMMENT ON COLUMN mfa_totp.enabled IS 'True if TOTP is active and required for authentication';
COMMENT ON COLUMN mfa_totp.backup_codes IS 'Encrypted backup recovery codes for account recovery';

-- Update the user_mfa_methods view to include TOTP status
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
