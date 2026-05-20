-- 202605180002: Per-tenant retention policy + auto-purge for remote-support
-- recordings.
--
-- Effective retention for a session is resolved in this priority order:
--   1. recording_retention_days on the session row (admin per-session override)
--   2. retention_days on recording_retention_policies for the session's org
--   3. RecordingsDefaultRetentionDays config (global default)
--   4. Hard fallback of 90 days
--
-- A background goroutine sweeps sessions whose recording is older than the
-- effective retention and deletes the storage blob (filesystem or S3) plus
-- nulls the storage-key fields. The row itself stays so audit history
-- survives the purge — only the media is destroyed.

ALTER TABLE remote_support_sessions
    -- org_id was missing on this table from Phase 4. Backfill by reading
    -- the admin user's org at the next start-session call; existing rows
    -- stay NULL and the retention sweeper treats them as "no org policy"
    -- (so they fall through to the global default).
    ADD COLUMN IF NOT EXISTS org_id                    UUID,
    ADD COLUMN IF NOT EXISTS recording_retention_days  INT,
    -- Stamped by the retention sweeper after the storage delete completes.
    -- Distinct from recording_finalized_at so we can tell "recorded but
    -- purged" apart from "session ended without recording".
    ADD COLUMN IF NOT EXISTS recording_purged_at       TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_remote_support_sessions_org
    ON remote_support_sessions(org_id);

-- Sweep predicate index: recordings that have been finalized but not yet
-- purged are the only ones the sweeper needs to evaluate.
CREATE INDEX IF NOT EXISTS idx_remote_support_recordings_purgeable
    ON remote_support_sessions(recording_finalized_at)
 WHERE recording_finalized_at IS NOT NULL
   AND recording_purged_at IS NULL;

-- One retention policy row per organization. retention_days = 0 disables
-- automatic deletion (useful for compliance regimes that need indefinite
-- retention under separate legal-hold processes). Set updated_by so audit
-- shows who touched the policy last.
CREATE TABLE IF NOT EXISTS recording_retention_policies (
    org_id          UUID PRIMARY KEY,
    retention_days  INT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by      UUID
);
