-- Rollback 023: Password History and Credential Rotation

DROP INDEX IF EXISTS idx_credential_rotations_sa;
DROP TABLE IF EXISTS credential_rotations;
DROP INDEX IF EXISTS idx_password_history_user;
DROP TABLE IF EXISTS password_history;
