package migrations

// Migration v68 — Guacamole recording legal-hold. Parallels recording_legal_holds
// (v42, remote_support) but FKs to guacamole_sessions so a held Guacamole recording
// is never purged by sweepExpiredGuacRecordings. A separate table (not a polymorphic
// column) keeps the per-type FK + ON DELETE CASCADE. A UNIQUE partial index enforces at
// most one active hold per session (so the place-hold 409 fires — the v42 remote_support
// index is non-unique, a latent gap this improves on). Not RLS-belted (tenancy flows via
// the guacamole_sessions FK + org-scoped handler checks), mirroring recording_legal_holds.
// openidx_app exists by v68 (created by v53), so a plain GRANT is safe (no DO $$ block).
var guacRecordingLegalHoldsUp = `-- Migration 068: Guacamole recording legal-hold.
CREATE TABLE IF NOT EXISTS guacamole_recording_legal_holds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL,
    reason          TEXT NOT NULL,
    placed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    placed_by       UUID,
    released_at     TIMESTAMPTZ,
    released_by     UUID,
    released_reason TEXT,
    CONSTRAINT guac_rec_legal_holds_session_fk
        FOREIGN KEY (session_id) REFERENCES guacamole_sessions(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_guac_rec_legal_holds_active
    ON guacamole_recording_legal_holds(session_id) WHERE released_at IS NULL;
GRANT SELECT, INSERT, UPDATE, DELETE ON guacamole_recording_legal_holds TO openidx_app;
`

var guacRecordingLegalHoldsDown = `-- Migration 068 down.
DROP TABLE IF EXISTS guacamole_recording_legal_holds;
`
