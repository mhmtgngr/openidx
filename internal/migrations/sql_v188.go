package migrations

// Migration v188 — a vendor link points at a PAM entry, instead of carrying its
// own copy of a target.
//
// temp_access_links stored protocol, target_host, target_port and username
// itself, and handleUseTempAccess redirected the vendor to a Guacamole
// connection built from them at creation time with no parameters at all. Every
// control the PAM launch path applies was therefore absent from the one feature
// in this product built for third-party access: no PAM_REQUIRE_ZTNA check, no
// broker selection by reach mode (always the direct broker), no session
// recording, no credential injection — so the vendor had to be told a password
// out of band, which is the thing the vault exists to prevent.
//
// WHY A REFERENCE AND NOT MORE COLUMNS. The obvious alternative was to copy
// reach_mode and record_session onto the link and synthesise a pamLaunchEntry
// at redemption. That does not work, and fails in the worst available
// direction: pam_entry_sessions.entry_id is NOT NULL REFERENCES pam_entries(id)
// (v81), so a synthetic id violates the foreign key — and recordPamLaunch logs
// that failure at WARN and carries on, because a ledger write must not abort a
// launch already in flight. The session would open and the ledger would have no
// row: an outsider on an internal host with no record. Pointing at a real entry
// is the only shape in which the existing core can be reused.
//
// It is also less to maintain. The entry already carries the ACL, the approval
// flag, the recording flag, the vault credential, the reach mode and the Ziti
// intercept port; a link that references one inherits all of it and cannot
// drift from it.
//
// NULLABLE, AND WHAT THAT MEANS AT REDEMPTION. Links created before this
// migration have no entry to point at, and there is nothing to backfill them
// from: target_host is a hostname, and guessing which pam_entries row an
// operator meant would be inventing an authorization. They keep their columns
// as a record of what was issued, and handleUseTempAccess refuses them with a
// message saying the link predates the change and must be re-created. Failing
// closed on a handful of in-flight vendor links is the cheap direction; the
// expensive one is leaving the old redirect alive as a second, ungated path.
//
// ON DELETE CASCADE matches pam_entry_sessions: deleting the entry a vendor was
// pointed at removes the link that pointed there, rather than leaving a live
// token addressing a target that no longer exists.

var tempLinkPamEntryUp = `-- Migration 188: temp access links reference a PAM entry.
ALTER TABLE temp_access_links
    ADD COLUMN IF NOT EXISTS pam_entry_id UUID REFERENCES pam_entries(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_temp_access_links_pam_entry
    ON temp_access_links (pam_entry_id) WHERE pam_entry_id IS NOT NULL;`

var tempLinkPamEntryDown = `-- Rollback 188.
DROP INDEX IF EXISTS idx_temp_access_links_pam_entry;
ALTER TABLE temp_access_links DROP COLUMN IF EXISTS pam_entry_id;`
