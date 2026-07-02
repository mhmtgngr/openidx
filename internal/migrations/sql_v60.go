package migrations

// Migration v60 — PAM M4 session assurance: guacamole transcript columns.
//
// Adds two columns to guacamole_sessions so the session-assurance sweeper
// (Task 3) can track the guacd-native transcript file independently of the
// recording blob:
//
//   - transcript_path         TEXT     — full filesystem path to the guacd
//     transcript file (e.g. <recording-root>/<name>.typescript). Populated by
//     Task 3's sweeper once the session has ended and guacd has flushed the
//     file.
//   - transcript_generated_at TIMESTAMPTZ — wall-clock timestamp when the
//     transcript file was first detected / generated.
//
// Idempotent (ADD COLUMN IF NOT EXISTS). Mirrored into
// deployments/docker/init-db.sql so TestInitDBParity stays green.
var guacTranscriptUp = `-- Migration 060: PAM M4 session assurance — guacamole transcript columns.
ALTER TABLE guacamole_sessions ADD COLUMN IF NOT EXISTS transcript_path          TEXT;
ALTER TABLE guacamole_sessions ADD COLUMN IF NOT EXISTS transcript_generated_at  TIMESTAMPTZ;
`

var guacTranscriptDown = `-- Migration 060 down.
ALTER TABLE guacamole_sessions DROP COLUMN IF EXISTS transcript_generated_at;
ALTER TABLE guacamole_sessions DROP COLUMN IF EXISTS transcript_path;
`
