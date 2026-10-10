package migrations

// Migration 233: push devices record when they were last seen.
//
// A push device row lived forever. A phone that was lost, wiped or replaced
// kept its row, kept push on the user's list of factors and kept being sent
// every challenge, and a user whose only factor was that phone could not sign
// in at all (an administrator was locked out exactly this way).
//
// last_seen_at is the last time the device itself proved it was alive:
// registering or re-registering, answering a challenge (approve or deny), or a
// posture report from the enrolled agent it is linked to. The login uses it to
// stop offering a long-unseen phone as the only way in, and a sweep in the
// identity service disables a device unseen for long enough.
//
// disabled_at and disabled_reason record a device disabled by that sweep
// ('stale') or by an administrator ('admin'). They are what tells such a
// device apart from one the user switched off: a device the system disabled
// is still a factor the user HAS, so the login keeps asking for a second
// factor (offering the fallbacks) instead of letting the password alone
// through. Re-registering the device clears both.
//
// Existing rows are given the best evidence there is, the last approval or
// else the registration. The code reads COALESCE(last_seen_at, last_used_at,
// created_at) throughout, so a row this backfill could not reach (a migrator
// subject to the table's RLS policy sees no rows) behaves the same.
//
// No new table, so no new policy: the table's existing org policy covers the
// new columns.
var pushDeviceLastSeenUp = `-- Migration 233: push device liveness.
ALTER TABLE mfa_push_devices ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE mfa_push_devices ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE mfa_push_devices ADD COLUMN IF NOT EXISTS disabled_reason VARCHAR(32);
UPDATE mfa_push_devices SET last_seen_at = COALESCE(last_used_at, created_at) WHERE last_seen_at IS NULL;
ALTER TABLE mfa_push_devices ALTER COLUMN last_seen_at SET DEFAULT NOW();
CREATE INDEX IF NOT EXISTS idx_mfa_push_devices_last_seen ON mfa_push_devices(last_seen_at) WHERE enabled;
`

var pushDeviceLastSeenDown = `-- Rollback migration 233.
DROP INDEX IF EXISTS idx_mfa_push_devices_last_seen;
ALTER TABLE mfa_push_devices DROP COLUMN IF EXISTS disabled_reason;
ALTER TABLE mfa_push_devices DROP COLUMN IF EXISTS disabled_at;
ALTER TABLE mfa_push_devices DROP COLUMN IF EXISTS last_seen_at;
`
