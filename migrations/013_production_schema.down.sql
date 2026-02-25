-- OpenIDX Production Schema Rollback
-- Version: 013
-- Description: Rollback production schema changes

-- ============================================================================
-- DROP FUNCTIONS
-- ============================================================================

DROP FUNCTION IF EXISTS cleanup_expired_sessions();
DROP FUNCTION IF EXISTS cleanup_expired_tokens();
DROP FUNCTION IF EXISTS update_login_stats(UUID);
DROP FUNCTION IF EXISTS record_failed_login(UUID);

-- ============================================================================
-- DROP INDEXES
-- ============================================================================

-- Audit events indexes
DROP INDEX IF EXISTS idx_audit_events_correlation;
DROP INDEX IF EXISTS idx_audit_events_resource;
DROP INDEX IF EXISTS idx_audit_events_severity;
DROP INDEX IF EXISTS idx_audit_events_type_timestamp;
DROP INDEX IF EXISTS idx_audit_events_user_timestamp;
DROP INDEX IF EXISTS idx_audit_events_timestamp_desc;

-- Sessions indexes
DROP INDEX IF EXISTS idx_sessions_device_id;
DROP INDEX IF EXISTS idx_sessions_type;
DROP INDEX IF EXISTS idx_sessions_expires_at;
DROP INDEX IF EXISTS idx_sessions_user_id_created;

-- Users indexes
DROP INDEX IF EXISTS idx_users_locked;
DROP INDEX IF EXISTS idx_users_email_verified;
DROP INDEX IF EXISTS idx_users_enabled;
DROP INDEX IF EXISTS idx_users_last_login;

-- OAuth cleanup indexes
DROP INDEX IF EXISTS idx_oauth_auth_codes_expires;
DROP INDEX IF EXISTS idx_oauth_refresh_tokens_expires;
DROP INDEX IF EXISTS idx_oauth_access_tokens_expires;

-- Settings index
DROP INDEX IF EXISTS idx_production_settings_public;

-- ============================================================================
-- DROP PRODUCTION SETTINGS TABLE
-- ============================================================================

DROP TABLE IF EXISTS production_settings;

-- ============================================================================
-- DROP COLUMNS (PostgreSQL doesn't support DROP COLUMN IF NOT EXISTS in older versions)
-- ============================================================================

-- Audit events table
ALTER TABLE audit_events DROP COLUMN IF EXISTS x_forwarded_for;
ALTER TABLE audit_events DROP COLUMN IF EXISTS severity;
ALTER TABLE audit_events DROP COLUMN IF EXISTS session_id;
ALTER TABLE audit_events DROP COLUMN IF EXISTS correlation_id;

-- Sessions table
ALTER TABLE user_sessions DROP COLUMN IF EXISTS metadata;
ALTER TABLE user_sessions DROP COLUMN IF EXISTS city;
ALTER TABLE user_sessions DROP COLUMN IF EXISTS country_code;
ALTER TABLE user_sessions DROP COLUMN IF EXISTS device_id;
ALTER TABLE user_sessions DROP COLUMN IF EXISTS device_name;
ALTER TABLE user_sessions DROP COLUMN IF EXISTS device_type;
ALTER TABLE user_sessions DROP COLUMN IF EXISTS session_type;

-- Users table
ALTER TABLE users DROP COLUMN IF EXISTS locale;
ALTER TABLE users DROP COLUMN IF EXISTS timezone;
ALTER TABLE users DROP COLUMN IF EXISTS phone_verified;
ALTER TABLE users DROP COLUMN IF EXISTS phone_number;
ALTER TABLE users DROP COLUMN IF EXISTS profile_image_url;
ALTER TABLE users DROP COLUMN IF EXISTS preferences;
ALTER TABLE users DROP COLUMN IF EXISTS backup_codes;
ALTER TABLE users DROP COLUMN IF EXISTS totp_enabled;
ALTER TABLE users DROP COLUMN IF EXISTS totp_secret;
ALTER TABLE users DROP COLUMN IF EXISTS password_changed_at;
ALTER TABLE users DROP COLUMN IF EXISTS locked_until;
ALTER TABLE users DROP COLUMN IF EXISTS failed_login_count;
ALTER TABLE users DROP COLUMN IF EXISTS login_count;
ALTER TABLE users DROP COLUMN IF EXISTS last_login_at;
