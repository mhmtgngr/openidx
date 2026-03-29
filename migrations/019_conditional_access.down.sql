-- Rollback 019: Conditional Access and Risk Engine

ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS location;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS auth_methods;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS risk_score;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS device_fingerprint;
DROP INDEX IF EXISTS idx_stepup_user;
DROP TABLE IF EXISTS stepup_challenges;
DROP INDEX IF EXISTS idx_login_history_user;
DROP TABLE IF EXISTS login_history;
DROP INDEX IF EXISTS idx_known_devices_user;
DROP TABLE IF EXISTS known_devices;
