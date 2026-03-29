-- Rollback 024: Session Management Enhancements

ALTER TABLE sessions DROP COLUMN IF EXISTS revoke_reason;
ALTER TABLE sessions DROP COLUMN IF EXISTS revoked_by;
ALTER TABLE sessions DROP COLUMN IF EXISTS revoked_at;
ALTER TABLE sessions DROP COLUMN IF EXISTS revoked;
ALTER TABLE sessions DROP COLUMN IF EXISTS device_type;
ALTER TABLE sessions DROP COLUMN IF EXISTS location;
ALTER TABLE sessions DROP COLUMN IF EXISTS device_name;
