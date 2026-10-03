package migrations

// Migration v221 -- moderation for PAM entries.
//
// Section 6.10 of the third-party access framework: the moderation gate a
// route-based Guacamole connection could ask for (v117, PAM C3) is extended to
// PAM entries. A session on an entry that requires a moderator does not start
// until a moderator has joined to watch it: an administrator, or, for an
// external (vendor) user, their sponsor.
//
//  1. pam_entries.require_moderator -- the entry's flag, off by default, so
//     no existing entry changes.
//  2. guacamole_moderation_sessions.entry_id -- a moderation request names
//     the PAM entry it is for. connection_id stays the key of a route-based
//     request and is NULL for an entry's, and a row names one or the other.
//  3. guacamole_moderation_sessions.admitted_at -- when a launch spent the
//     moderation. One moderation admits one session: the launch claims it in
//     the statement that finds it, and a second launch needs a moderator to
//     join again.
//  4. pam_entry_sessions.moderation_id -- the moderation that admitted the
//     session, so its moderator watches and ends that session and no other,
//     and the lifecycle sweep ends a session whose moderation ended.

var pamEntryModerationUp = `-- Migration 221: moderation for PAM entries.
ALTER TABLE pam_entries ADD COLUMN IF NOT EXISTS require_moderator BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE guacamole_moderation_sessions ALTER COLUMN connection_id DROP NOT NULL;
ALTER TABLE guacamole_moderation_sessions
    ADD COLUMN IF NOT EXISTS entry_id UUID REFERENCES pam_entries(id) ON DELETE CASCADE;
ALTER TABLE guacamole_moderation_sessions ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;
ALTER TABLE guacamole_moderation_sessions DROP CONSTRAINT IF EXISTS chk_guac_moderation_target;
ALTER TABLE guacamole_moderation_sessions
    ADD CONSTRAINT chk_guac_moderation_target
    CHECK ((connection_id IS NULL) <> (entry_id IS NULL));
CREATE INDEX IF NOT EXISTS idx_guac_moderation_entry
    ON guacamole_moderation_sessions (entry_id, requester_id, status)
    WHERE entry_id IS NOT NULL;

ALTER TABLE pam_entry_sessions ADD COLUMN IF NOT EXISTS moderation_id UUID
    REFERENCES guacamole_moderation_sessions(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_pam_entry_sessions_moderation
    ON pam_entry_sessions (moderation_id)
    WHERE moderation_id IS NOT NULL;
`

var pamEntryModerationDown = `-- Migration 221 down.
DROP INDEX IF EXISTS idx_pam_entry_sessions_moderation;
ALTER TABLE pam_entry_sessions DROP COLUMN IF EXISTS moderation_id;
DROP INDEX IF EXISTS idx_guac_moderation_entry;
ALTER TABLE guacamole_moderation_sessions DROP CONSTRAINT IF EXISTS chk_guac_moderation_target;
DELETE FROM guacamole_moderation_sessions WHERE connection_id IS NULL;
ALTER TABLE guacamole_moderation_sessions DROP COLUMN IF EXISTS admitted_at;
ALTER TABLE guacamole_moderation_sessions DROP COLUMN IF EXISTS entry_id;
ALTER TABLE guacamole_moderation_sessions ALTER COLUMN connection_id SET NOT NULL;
ALTER TABLE pam_entries DROP COLUMN IF EXISTS require_moderator;
`
