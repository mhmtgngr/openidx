-- Rollback 005: Multi-Factor Authentication Tables

DROP TABLE IF EXISTS mfa_push_challenges CASCADE;
DROP TABLE IF EXISTS mfa_push_devices CASCADE;
DROP TABLE IF EXISTS mfa_webauthn CASCADE;
DROP TABLE IF EXISTS user_mfa_policies CASCADE;
DROP TABLE IF EXISTS mfa_policies CASCADE;
DROP TABLE IF EXISTS mfa_backup_codes CASCADE;
DROP TABLE IF EXISTS mfa_totp CASCADE;
