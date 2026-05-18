-- 202605180001: Track per-session recording state on remote_support_sessions.
--
-- recording_url already existed (reserved) on the original 202605150004
-- migration. This migration adds the operational columns the upload
-- pipeline needs:
--
--   recording_enabled     — admin opt-in flag captured at session start.
--   recording_storage_key — filesystem / object-store key (relative to
--                           the configured recordings root). Distinct
--                           from recording_url so we can hand out signed
--                           URLs later without migrating the schema.
--   recording_size_bytes  — running tally; updated on every chunk.
--   recording_chunk_count — monotonically increasing chunk index; used
--                           to detect out-of-order uploads.
--   recording_finalized_at — set when the admin viewer flushes the last
--                           chunk and stops the MediaRecorder.

ALTER TABLE remote_support_sessions
    ADD COLUMN IF NOT EXISTS recording_enabled       BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS recording_storage_key   VARCHAR(255),
    ADD COLUMN IF NOT EXISTS recording_size_bytes    BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS recording_chunk_count   INT    NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS recording_finalized_at  TIMESTAMPTZ;

-- Index lets the admin "recent recordings" view list finished recordings
-- quickly without scanning the whole sessions table.
CREATE INDEX IF NOT EXISTS idx_remote_support_recordings_finalized
    ON remote_support_sessions(recording_finalized_at DESC)
 WHERE recording_finalized_at IS NOT NULL;
