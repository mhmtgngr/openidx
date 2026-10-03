package migrations

// Migration v217 -- a PAM entry session records which gates its launch passed
// only because the caller is an administrator.
//
// A session opened on a grant ends when the grant does: when a request's
// window closes, when an administrator removes the grant, when the role or
// group that carried it goes (P5 of the third-party access framework, and
// section 5.6.6: "when the time is up the grant is swept and the live session
// ends"). The lifecycle sweep in internal/access ends those sessions, and for
// that it has to know which sessions a grant opened. An administrator connects
// past the grant check, so a session they opened without one is not ended for
// the lack of one.
//
// pam_entry_sessions.admin_bypass holds the gates the launch passed only
// because the caller is an administrator ('grant', 'approval'), the list the
// pam.entry_connected event already carries; empty when nothing was bypassed.
// Rows written before this migration are left NULL: whether a grant opened
// them was not recorded, so the sweep does not judge them, and they end as
// they always have (the kill switch, deprovisioning, a disabled user).

var pamSessionAdminBypassUp = `-- Migration 217: pam_entry_sessions.admin_bypass.
ALTER TABLE pam_entry_sessions ADD COLUMN IF NOT EXISTS admin_bypass TEXT[];
ALTER TABLE pam_entry_sessions ALTER COLUMN admin_bypass SET DEFAULT '{}';
`

var pamSessionAdminBypassDown = `-- Migration 217 down.
ALTER TABLE pam_entry_sessions DROP COLUMN IF EXISTS admin_bypass;
`
