DROP INDEX IF EXISTS idx_remote_support_recordings_finalized;

ALTER TABLE remote_support_sessions
    DROP COLUMN IF EXISTS recording_finalized_at,
    DROP COLUMN IF EXISTS recording_chunk_count,
    DROP COLUMN IF EXISTS recording_size_bytes,
    DROP COLUMN IF EXISTS recording_storage_key,
    DROP COLUMN IF EXISTS recording_enabled;
