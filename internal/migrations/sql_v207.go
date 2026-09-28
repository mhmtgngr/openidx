package migrations

// Migration v207 -- mfa_totp.last_step: the last time step each TOTP
// credential accepted.
//
// VerifyTOTP accepted any code valid in its +/-1 step window and recorded only
// when it last succeeded (last_used_at), which nothing read. A code that had
// just been accepted stayed acceptable for the rest of its window, about 90
// seconds: whoever saw it -- over a shoulder, in a proxy log, through a phishing
// page that relays it -- could sign in, or pass a step-up, with it a second
// time. RFC 6238 section 5.2 asks the verifier not to accept a code twice.
//
// The verifier now works out which step the presented code belongs to and
// accepts it only for a step later than this column, in the same UPDATE that
// records it (WHERE last_step < $step), so two requests carrying one code admit
// exactly one. Enrollment records the step of the code it was confirmed with.
//
// DEFAULT 0 is below every real step (Unix time over 30, about sixty million in
// 2026), so a credential enrolled before this migration verifies as before on
// its next use. A constant default is stored in the catalog; no row is rewritten, and
// none is touched under the row-level-security belt.
//
// Down drops the column. An install rolling back runs code that neither reads
// nor writes it, and accepts a code again within its window.

var totpLastStepUp = `-- Migration 207: the last TOTP time step each credential accepted.
ALTER TABLE mfa_totp ADD COLUMN IF NOT EXISTS last_step BIGINT NOT NULL DEFAULT 0;
`

var totpLastStepDown = `-- Migration 207 down: drop the accepted-step record.
ALTER TABLE mfa_totp DROP COLUMN IF EXISTS last_step;
`
