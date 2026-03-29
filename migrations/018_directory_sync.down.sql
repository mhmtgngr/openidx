-- Rollback 018: Directory Sync State and Logs

DROP INDEX IF EXISTS idx_sync_logs_started;
DROP INDEX IF EXISTS idx_sync_logs_directory;
DROP TABLE IF EXISTS directory_sync_logs;
DROP TABLE IF EXISTS directory_sync_state;
DROP INDEX IF EXISTS idx_groups_directory_id;
ALTER TABLE groups DROP COLUMN IF EXISTS external_id;
ALTER TABLE groups DROP COLUMN IF EXISTS ldap_dn;
ALTER TABLE groups DROP COLUMN IF EXISTS directory_id;
ALTER TABLE groups DROP COLUMN IF EXISTS source;
DROP INDEX IF EXISTS idx_users_source;
DROP INDEX IF NOT EXISTS idx_users_directory_id;
ALTER TABLE users DROP COLUMN IF EXISTS ldap_dn;
ALTER TABLE users DROP COLUMN IF EXISTS directory_id;
ALTER TABLE users DROP COLUMN IF EXISTS source;
