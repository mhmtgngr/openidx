package migrations

// Migration 241: seal and retention metadata for PAM entry session recordings.
//
// guacd records a PAM entry session (POST /pam/entries/:id/connect, the
// Windows app launch) to the path on pam_entry_sessions.recording_path, but
// the recording sealer, the retention purge and the download read only
// guacamole_sessions, the route path's table. An entry session's recording
// therefore stayed plaintext on disk, was never purged and could not be
// downloaded. These are the same four columns guacamole_sessions carries
// (v116 and v68), so the entry path's sweep stamps and claims exactly as the
// route path's does.
//
// A route launch writes a row in both tables for one file; the entry sweep
// leaves those to the route path, which already seals and purges them.
//
// Nullable columns under the table's existing org policy; down drops them.

var pamEntryRecordingSealUp = `-- Migration 241: pam_entry_sessions recording seal + retention metadata.
ALTER TABLE pam_entry_sessions ADD COLUMN IF NOT EXISTS recording_sealed_at TIMESTAMPTZ;
ALTER TABLE pam_entry_sessions ADD COLUMN IF NOT EXISTS recording_sha256 TEXT;
ALTER TABLE pam_entry_sessions ADD COLUMN IF NOT EXISTS recording_key_id SMALLINT;
ALTER TABLE pam_entry_sessions ADD COLUMN IF NOT EXISTS recording_purged_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_pam_entry_sessions_unsealed
    ON pam_entry_sessions (ended_at)
    WHERE recording_path IS NOT NULL AND recording_sealed_at IS NULL AND recording_purged_at IS NULL;
`

var pamEntryRecordingSealDown = `-- Rollback migration 241.
DROP INDEX IF EXISTS idx_pam_entry_sessions_unsealed;
ALTER TABLE pam_entry_sessions DROP COLUMN IF EXISTS recording_purged_at;
ALTER TABLE pam_entry_sessions DROP COLUMN IF EXISTS recording_key_id;
ALTER TABLE pam_entry_sessions DROP COLUMN IF EXISTS recording_sha256;
ALTER TABLE pam_entry_sessions DROP COLUMN IF EXISTS recording_sealed_at;
`
