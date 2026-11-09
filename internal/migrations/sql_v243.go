package migrations

// Migration 243: warnings for risky commands in privileged SSH sessions.
//
// org_pam_policy gains risky_command_patterns: the organization's list of
// regular expressions (RE2, matched case-insensitively against each line of
// an SSH session's text transcript). After a recorded SSH entry session ends,
// the lifecycle sweep reads its typescript and, for every line a pattern
// matches, raises one audit event and one webhook per session. It warns; it
// does not block, and the console says so.
//
// pam_entry_sessions gains commands_scanned_at (the claim: scanned once) and
// risky_command_count (NULL when there was no transcript to read), with a
// partial index for the unscanned sweep.
//
// Default empty list, so no organization is scanned on upgrade.

var pamRiskyCommandsUp = `-- Migration 243: risky-command warnings.
ALTER TABLE org_pam_policy ADD COLUMN IF NOT EXISTS risky_command_patterns TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE pam_entry_sessions ADD COLUMN IF NOT EXISTS commands_scanned_at TIMESTAMPTZ;
ALTER TABLE pam_entry_sessions ADD COLUMN IF NOT EXISTS risky_command_count INTEGER;

CREATE INDEX IF NOT EXISTS idx_pam_entry_sessions_unscanned
    ON pam_entry_sessions (ended_at)
    WHERE protocol = 'ssh' AND recording_path IS NOT NULL AND commands_scanned_at IS NULL;
`

var pamRiskyCommandsDown = `-- Rollback migration 243.
DROP INDEX IF EXISTS idx_pam_entry_sessions_unscanned;
ALTER TABLE pam_entry_sessions DROP COLUMN IF EXISTS risky_command_count;
ALTER TABLE pam_entry_sessions DROP COLUMN IF EXISTS commands_scanned_at;
ALTER TABLE org_pam_policy DROP COLUMN IF EXISTS risky_command_patterns;
`
