package migrations

// Migration 139: throttle hardware-token verification.
//
// VerifyHardwareToken checks a six-digit code with no failure counter and no
// lockout, which is the exposure mfa_totp's failed_attempts/locked_until pair
// (added earlier, and explained at internal/identity/service.go's
// totpMaxAttempts) exists to close. It is worse here than for TOTP: verifyHOTP
// walks a look-ahead window of ten counters and verifyTOTP accepts a +/- 1 step
// window, so roughly eleven of a million values are live at any instant, and
// nothing anywhere made guessing them expensive.
//
// The columns mirror mfa_totp exactly so the two factors throttle the same way
// and one set of constants tunes both.
//
// Not addressed here: hardware_tokens still has no org_id, and serial_number is
// UNIQUE install-wide. Both are on the orgscope needsScoping register and are
// their own migration, because adding org_id means a backfill, the RLS belt and
// every query in internal/identity/hardware_token.go.
var hardwareTokenThrottleUp = `-- Migration 139: throttle hardware-token verification.
ALTER TABLE hardware_tokens ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hardware_tokens ADD COLUMN IF NOT EXISTS last_failed_at  TIMESTAMPTZ;
ALTER TABLE hardware_tokens ADD COLUMN IF NOT EXISTS locked_until    TIMESTAMPTZ;

-- The verifier reads the lock before it reads the code, so this index is on the
-- path of every second-factor check that uses a hardware token.
CREATE INDEX IF NOT EXISTS idx_hardware_tokens_locked_until ON hardware_tokens(locked_until)
    WHERE locked_until IS NOT NULL;
`

var hardwareTokenThrottleDown = `-- Rollback migration 139.
DROP INDEX IF EXISTS idx_hardware_tokens_locked_until;
ALTER TABLE hardware_tokens DROP COLUMN IF EXISTS locked_until;
ALTER TABLE hardware_tokens DROP COLUMN IF EXISTS last_failed_at;
ALTER TABLE hardware_tokens DROP COLUMN IF EXISTS failed_attempts;
`
