-- OpenIDX Production Schema Migration
-- Version: 013
-- Description: Production enhancements for user tracking, analytics, and settings
--
-- This migration adds:
-- - Last login tracking for users
-- - Login count for analytics
-- - Performance indexes for common queries
-- - Production settings table

-- ============================================================================
-- USERS TABLE - Production Enhancements
-- ============================================================================

-- Add last login tracking
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP;

-- Add login count for analytics
ALTER TABLE users ADD COLUMN IF NOT EXISTS login_count INTEGER DEFAULT 0;

-- Add failed login attempt tracking
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_count INTEGER DEFAULT 0;

-- Add account locked status for security
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP;

-- Add password last changed timestamp
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Add TOTP secret for two-factor authentication
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(255);

-- Add TOTP enabled flag
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN DEFAULT false;

-- Add backup codes for MFA recovery
ALTER TABLE users ADD COLUMN IF NOT EXISTS backup_codes JSONB;

-- Add user preferences (notifications, theme, etc.)
ALTER TABLE users ADD COLUMN IF NOT EXISTS preferences JSONB DEFAULT '{}'::jsonb;

-- Add profile image URL
ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_image_url VARCHAR(500);

-- Add phone number for MFA
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number VARCHAR(50);

-- Add phone verified flag
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN DEFAULT false;

-- Add timezone setting
ALTER TABLE users ADD COLUMN IF NOT EXISTS timezone VARCHAR(50) DEFAULT 'UTC';

-- Add locale setting
ALTER TABLE users ADD COLUMN IF NOT EXISTS locale VARCHAR(10) DEFAULT 'en';

-- ============================================================================
-- SESSIONS TABLE - Production Enhancements
-- ============================================================================

-- Add session type (web, api, mobile)
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS session_type VARCHAR(20) DEFAULT 'web';

-- Add device information
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_type VARCHAR(50);
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_name VARCHAR(255);
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_id VARCHAR(255);

-- Add location tracking (IP-based geolocation)
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS country_code VARCHAR(2);
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS city VARCHAR(100);

-- Add session metadata
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;

-- ============================================================================
-- AUDIT EVENTS TABLE - Production Enhancements
-- ============================================================================

-- Add correlation ID for request tracing
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS correlation_id UUID;

-- Add session ID for user activity tracking
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS session_id UUID REFERENCES user_sessions(id) ON DELETE SET NULL;

-- Add severity level (info, warning, error, critical)
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS severity VARCHAR(20) DEFAULT 'info';

-- Add source IP (behind proxy)
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS x_forwarded_for VARCHAR(100);

-- ============================================================================
-- PERFORMANCE INDEXES
-- ============================================================================

-- Users indexes for common queries
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login_at DESC);
CREATE INDEX IF NOT EXISTS idx_users_enabled ON users(enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_users_email_verified ON users(email_verified) WHERE email_verified = true;
CREATE INDEX IF NOT EXISTS idx_users_locked ON users(locked_until) WHERE locked_until IS NOT NULL;

-- Sessions indexes for performance
CREATE INDEX IF NOT EXISTS idx_sessions_user_id_created ON user_sessions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON user_sessions(expires_at) WHERE expires_at > CURRENT_TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_sessions_type ON user_sessions(session_type);
CREATE INDEX IF NOT EXISTS idx_sessions_device_id ON user_sessions(device_id);

-- Audit events indexes for reporting
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp_desc ON audit_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_user_timestamp ON audit_events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_type_timestamp ON audit_events(event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_severity ON audit_events(severity);
CREATE INDEX IF NOT EXISTS idx_audit_events_resource ON audit_events(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_correlation ON audit_events(correlation_id);

-- OAuth tokens cleanup indexes
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_expires ON oauth_access_tokens(expires_at) WHERE expires_at < CURRENT_TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_expires ON oauth_refresh_tokens(expires_at) WHERE expires_at < CURRENT_TIMESTAMP;

-- Authorization codes cleanup index
CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_expires ON oauth_authorization_codes(expires_at) WHERE expires_at < CURRENT_TIMESTAMP;

-- ============================================================================
-- FUNCTIONS FOR AUTOMATIC CLEANUP
-- ============================================================================

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM user_sessions
    WHERE expires_at < CURRENT_TIMESTAMP;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up expired OAuth tokens
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS INTEGER AS $$
DECLARE
    deleted_access INTEGER;
    deleted_refresh INTEGER;
    deleted_codes INTEGER;
BEGIN
    -- Clean up expired access tokens
    DELETE FROM oauth_access_tokens
    WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS deleted_access = ROW_COUNT;

    -- Clean up expired refresh tokens
    DELETE FROM oauth_refresh_tokens
    WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS deleted_refresh = ROW_COUNT;

    -- Clean up expired authorization codes
    DELETE FROM oauth_authorization_codes
    WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS deleted_codes = ROW_COUNT;

    RETURN deleted_access + deleted_refresh + deleted_codes;
END;
$$ LANGUAGE plpgsql;

-- Function to update user login statistics
CREATE OR REPLACE FUNCTION update_login_stats(user_uuid UUID)
RETURNS VOID AS $$
BEGIN
    UPDATE users
    SET
        last_login_at = CURRENT_TIMESTAMP,
        login_count = COALESCE(login_count, 0) + 1,
        failed_login_count = 0
    WHERE id = user_uuid;
END;
$$ LANGUAGE plpgsql;

-- Function to record failed login attempt
CREATE OR REPLACE FUNCTION record_failed_login(user_uuid UUID)
RETURNS VOID AS $$
BEGIN
    UPDATE users
    SET
        failed_login_count = COALESCE(failed_login_count, 0) + 1
    WHERE id = user_uuid;

    -- Lock account after 5 failed attempts (30 minute lock)
    UPDATE users
    SET
        locked_until = CURRENT_TIMESTAMP + INTERVAL '30 minutes'
    WHERE id = user_uuid
      AND failed_login_count >= 5;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- PRODUCTION SETTINGS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS production_settings (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    value_type VARCHAR(20) NOT NULL DEFAULT 'string', -- string, json, boolean, number
    description TEXT,
    is_public BOOLEAN DEFAULT false,
    is_encrypted BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default production settings
INSERT INTO production_settings (key, value, value_type, description, is_public)
VALUES
    ('maintenance_mode', 'false', 'boolean', 'Enable maintenance mode', true),
    ('registration_enabled', 'true', 'boolean', 'Allow new user registrations', true),
    ('max_sessions_per_user', '10', 'number', 'Maximum concurrent sessions per user', false),
    ('session_timeout_minutes', '480', 'number', 'Default session timeout in minutes', false),
    ('password_min_length', '12', 'number', 'Minimum password length', false),
    ('password_require_uppercase', 'true', 'boolean', 'Require uppercase in password', false),
    ('password_require_lowercase', 'true', 'boolean', 'Require lowercase in password', false),
    ('password_require_number', 'true', 'boolean', 'Require number in password', false),
    ('password_require_special', 'true', 'boolean', 'Require special character in password', false),
    ('mfa_enabled', 'false', 'boolean', 'Enable multi-factor authentication requirement', false),
    ('login_rate_limit', '5', 'number', 'Max login attempts per minute per IP', false)
ON CONFLICT (key) DO NOTHING;

-- Index for settings lookups
CREATE INDEX IF NOT EXISTS idx_production_settings_public ON production_settings(is_public) WHERE is_public = true;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE production_settings IS 'Production configuration settings';
COMMENT ON COLUMN users.last_login_at IS 'Timestamp of last successful login';
COMMENT ON COLUMN users.login_count IS 'Total number of successful logins';
COMMENT ON COLUMN users.failed_login_count IS 'Current count of consecutive failed login attempts';
COMMENT ON COLUMN users.locked_until IS 'Account locked until this time after failed logins';
COMMENT ON COLUMN users.totp_secret IS 'TOTP secret for two-factor authentication';
COMMENT ON COLUMN users.preferences IS 'User preferences stored as JSON';
COMMENT ON COLUMN user_sessions.session_type IS 'Type of session: web, api, mobile';
COMMENT ON COLUMN audit_events.severity IS 'Event severity: info, warning, error, critical';
COMMENT ON COLUMN audit_events.correlation_id IS 'Request correlation ID for distributed tracing';
