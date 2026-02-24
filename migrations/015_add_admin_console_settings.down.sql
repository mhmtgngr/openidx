-- OpenIDX Admin Console Settings Rollback
-- Version: 015
-- Description: Rollback admin console settings migration

-- Drop functions
DROP FUNCTION IF EXISTS get_all_admin_settings CASCADE;
DROP FUNCTION IF EXISTS update_admin_setting CASCADE;
DROP FUNCTION IF EXISTS get_admin_setting CASCADE;

-- Drop indexes
DROP INDEX IF EXISTS idx_admin_settings_updated;
DROP INDEX IF EXISTS idx_admin_settings_category;
DROP INDEX IF EXISTS idx_admin_settings_key;

DROP INDEX IF EXISTS idx_admin_settings_history_at;
DROP INDEX IF EXISTS idx_admin_settings_history_key;

-- Drop tables
DROP TABLE IF EXISTS admin_console_settings_history;
DROP TABLE IF EXISTS admin_console_settings;
