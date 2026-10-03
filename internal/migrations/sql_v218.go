package migrations

// Migration v218 -- a PAM entry session records when the external user's
// sponsor was told it started.
//
// Invariant I6 of the third-party access framework: when an external (vendor)
// user's privileged session starts, their sponsor is told. The access service
// tells them as it records the launch, and pam_entry_sessions.sponsor_notified_at
// says when that notification was written, so "was the sponsor told?" is a
// question the session row answers. It stays NULL for an internal user's
// session, and for an external one whose sponsor switched the notification
// type off: the row records what happened, not what was meant to.

var pamSessionSponsorNotifiedUp = `-- Migration 218: pam_entry_sessions.sponsor_notified_at.
ALTER TABLE pam_entry_sessions ADD COLUMN IF NOT EXISTS sponsor_notified_at TIMESTAMPTZ;
`

var pamSessionSponsorNotifiedDown = `-- Migration 218 down.
ALTER TABLE pam_entry_sessions DROP COLUMN IF EXISTS sponsor_notified_at;
`
