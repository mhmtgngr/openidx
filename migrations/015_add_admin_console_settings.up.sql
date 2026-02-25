-- OpenIDX Admin Console Settings Migration
-- Version: 015
-- Description: Admin console specific settings for frontend configuration

-- ============================================================================
-- ADMIN CONSOLE SETTINGS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS admin_console_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(255) UNIQUE NOT NULL,
    value JSONB NOT NULL,
    description TEXT,
    category VARCHAR(100) DEFAULT 'general',
    sensitive BOOLEAN DEFAULT false,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL
);

-- Insert default admin console settings
INSERT INTO admin_console_settings (key, value, description, category)
VALUES
    ('general', '{
        "organization_name": "OpenIDX",
        "support_email": "support@openidx.io",
        "default_language": "en",
        "default_timezone": "UTC",
        "session_timeout": 3600
    }'::jsonb, 'General system settings', 'general'),

    ('security', '{
        "password_policy": {
            "min_length": 12,
            "require_uppercase": true,
            "require_lowercase": true,
            "require_numbers": true,
            "require_special": true,
            "forbidden_words": ["password", "123456", "qwerty"],
            "max_age": 90,
            "history_count": 5
        },
        "mfa": {
            "enabled": false,
            "required": false,
            "allowed_methods": ["totp", "sms", "webauthn"]
        },
        "session": {
            "idle_timeout_minutes": 30,
            "absolute_timeout_minutes": 480,
            "max_concurrent_sessions": 5,
            "remember_me_days": 30
        }
    }'::jsonb, 'Security and authentication settings', 'security'),

    ('authentication', '{
        "allow_registration": false,
        "require_email_verify": true,
        "allowed_domains": [],
        "social_login_enabled": false,
        "social_providers": ["google", "microsoft", "github"],
        "lockout_policy": {
            "enabled": true,
            "max_failed_attempts": 5,
            "lockout_duration_minutes": 15
        }
    }'::jsonb, 'Authentication configuration', 'auth'),

    ('branding', '{
        "logo_url": "/assets/logo.png",
        "favicon_url": "/assets/favicon.ico",
        "primary_color": "#3B82F6",
        "secondary_color": "#1E40AF",
        "login_page_title": "Sign in to OpenIDX",
        "login_page_message": "Welcome to OpenIDX Identity Platform",
        "footer_html": "&copy; 2025 OpenIDX. All rights reserved."
    }'::jsonb, 'Branding and UI customization', 'branding'),

    ('dashboard', '{
        "refresh_interval_seconds": 30,
        "show_system_metrics": true,
        "show_security_alerts": true,
        "default_time_range": "24h"
    }'::jsonb, 'Dashboard configuration', 'dashboard'),

    ('audit', '{
        "retention_days": 365,
        "export_enabled": true,
        "max_export_rows": 100000
    }'::jsonb, 'Audit log settings', 'audit')
ON CONFLICT (key) DO NOTHING;

-- ============================================================================
-- ADMIN CONSOLE SETTINGS HISTORY TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS admin_console_settings_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    settings_key VARCHAR(255) NOT NULL,
    old_value JSONB,
    new_value JSONB NOT NULL,
    changed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason TEXT
);

-- Index for querying settings history
CREATE INDEX IF NOT EXISTS idx_admin_settings_history_key ON admin_console_settings_history(settings_key);
CREATE INDEX IF NOT EXISTS idx_admin_settings_history_at ON admin_console_settings_history(changed_at DESC);

-- ============================================================================
-- FUNCTIONS
-- ============================================================================

-- Function to get admin console setting by key
CREATE OR REPLACE FUNCTION get_admin_setting(setting_key VARCHAR)
RETURNS JSONB AS $$
DECLARE
    setting_value JSONB;
BEGIN
    SELECT value INTO setting_value
    FROM admin_console_settings
    WHERE key = setting_key;

    IF setting_value IS NULL THEN
        RAISE EXCEPTION 'Setting % not found', setting_key;
    END IF;

    RETURN setting_value;
END;
$$ LANGUAGE plpgsql;

-- Function to update admin console setting with history tracking
CREATE OR REPLACE FUNCTION update_admin_setting(
    setting_key VARCHAR,
    new_value JSONB,
    user_id UUID DEFAULT NULL,
    change_reason TEXT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
    old_value JSONB;
BEGIN
    -- Get current value for history
    SELECT value INTO old_value
    FROM admin_console_settings
    WHERE key = setting_key
    FOR UPDATE;

    -- Insert history entry
    INSERT INTO admin_console_settings_history (settings_key, old_value, new_value, changed_by, reason)
    VALUES (setting_key, old_value, new_value, user_id, change_reason);

    -- Update the setting
    UPDATE admin_console_settings
    SET value = new_value,
        updated_at = CURRENT_TIMESTAMP,
        updated_by = user_id
    WHERE key = setting_key;

    RETURN new_value;
END;
$$ LANGUAGE plpgsql;

-- Function to get all admin console settings
CREATE OR REPLACE FUNCTION get_all_admin_settings()
RETURNS JSONB AS $$
DECLARE
    result JSONB := '{}'::jsonb;
    rec RECORD;
BEGIN
    FOR rec IN SELECT key, value FROM admin_console_settings LOOP
        result := result || jsonb_build_object(rec.key, rec.value);
    END LOOP;

    RETURN result;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_admin_settings_key ON admin_console_settings(key);
CREATE INDEX IF NOT EXISTS idx_admin_settings_category ON admin_console_settings(category);
CREATE INDEX IF NOT EXISTS idx_admin_settings_updated ON admin_console_settings(updated_at DESC);

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE admin_console_settings IS 'Admin console frontend configuration settings';
COMMENT ON TABLE admin_console_settings_history IS 'Audit trail of admin console settings changes';

COMMENT ON FUNCTION get_admin_setting IS 'Get a single admin console setting by key';
COMMENT ON FUNCTION update_admin_setting IS 'Update admin console setting with history tracking';
COMMENT ON FUNCTION get_all_admin_settings IS 'Get all admin console settings as a single JSON object';
