DROP TABLE IF EXISTS recording_retention_policies;

DROP INDEX IF EXISTS idx_remote_support_recordings_purgeable;
DROP INDEX IF EXISTS idx_remote_support_sessions_org;

ALTER TABLE remote_support_sessions
    DROP COLUMN IF EXISTS recording_purged_at,
    DROP COLUMN IF EXISTS recording_retention_days,
    DROP COLUMN IF EXISTS org_id;
