-- 202605180003: Legal-hold workflow for remote-support recordings.
--
-- A legal hold prevents the retention sweeper from purging the
-- recording attached to a session, even when the org's retention
-- policy says the recording is past its keep-by date. Each hold is a
-- discrete row carrying who placed it, when, and why; releasing the
-- hold stamps released_at + released_by rather than deleting the row,
-- so the audit trail survives the eventual purge of the recording
-- itself.
--
-- Partial unique index on (session_id) WHERE released_at IS NULL
-- enforces the invariant that a session has at most one *active* hold
-- — multiple sequential hold-then-release cycles are still allowed
-- and produce distinct history rows.

CREATE TABLE IF NOT EXISTS recording_legal_holds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL,
    reason          TEXT NOT NULL,
    placed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    placed_by       UUID,
    released_at     TIMESTAMPTZ,
    released_by     UUID,
    released_reason TEXT,
    CONSTRAINT recording_legal_holds_session_fk
        FOREIGN KEY (session_id) REFERENCES remote_support_sessions(id) ON DELETE CASCADE
);

-- One active hold per session; releasing a hold stamps released_at so a
-- new hold can be placed without conflicting with the partial index.
CREATE UNIQUE INDEX IF NOT EXISTS uq_recording_legal_holds_active
    ON recording_legal_holds(session_id) WHERE released_at IS NULL;

-- The retention sweeper's "is this session held?" lookup; partial
-- index keeps it tight.
CREATE INDEX IF NOT EXISTS idx_recording_legal_holds_lookup
    ON recording_legal_holds(session_id) WHERE released_at IS NULL;
